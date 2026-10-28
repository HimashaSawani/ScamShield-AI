"""Frozen, abstention-aware rules evaluation. Never activates a model in the API."""
import argparse
from collections import Counter
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from backend.app.detection import analyze, VERSION
from ml.training.validation import validate

LABELS=['Scam','Legitimate','Uncertain']
PREDICTIONS=['Scam','Legitimate','Inconclusive']
LANGUAGES=['English','Sinhala','Tamil','Singlish']

def digest_rows(rows):
    canonical=json.dumps(sorted(rows,key=lambda r:r['record_id']),ensure_ascii=False,sort_keys=True,separators=(',',':'))
    return hashlib.sha256(canonical.encode()).hexdigest()

def load(path,allow_synthetic=False):
    with Path(path).open(encoding='utf-8-sig',newline='') as file:
        rows=list(csv.DictReader(file))
    checks=validate(rows,allow_synthetic,labels=LABELS,require_binary_splits=False)
    for row in rows:
        if not row.get('source_license','').strip() or not row.get('source_record_id','').strip():
            raise ValueError('Evaluation requires source_license and source_record_id; publisher labels are not automatically adjudicated labels')
        if row['label']=='Uncertain' and not row.get('annotation_reason','').strip():
            raise ValueError('Uncertain labels require annotation_reason')
    if not any(r['split']=='test' for r in rows):
        raise ValueError('An explicitly frozen test split is required')
    return rows,checks

def freeze(rows,path):
    test=[r for r in rows if r['split']=='test']
    manifest={'format':1,'test_sha256':digest_rows(test),'test_record_ids':sorted(r['record_id'] for r in test),'rows_at_freeze_sha256':digest_rows(rows),'note':'Frozen before evaluation. Do not tune rules or model thresholds using this test set.'}
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as file:json.dump(manifest,file,indent=2)
    return manifest

def verify_frozen(rows,path):
    manifest=json.loads(Path(path).read_text(encoding='utf-8'))
    test=[r for r in rows if r['split']=='test']
    if manifest.get('format')!=1 or manifest.get('test_sha256')!=digest_rows(test):
        raise ValueError('Frozen test set changed. Review and version the dataset; never silently refreeze after inspecting results.')
    return manifest

def summarize(records):
    """Primary matrix preserves abstentions. Flag-detection metrics never call them safe."""
    matrix=[[0]*3 for _ in LABELS]
    for record in records:
        matrix[LABELS.index(record['label'])][PREDICTIONS.index(record['prediction'])]+=1
    tp,explicit_fn,abstained_scam=matrix[0]
    fp,tn,abstained_legitimate=matrix[1]
    positives=sum(matrix[0]);negatives=sum(matrix[1]);total=len(records)
    precision=tp/(tp+fp) if tp+fp and negatives else None
    recall=tp/positives if positives else None
    f1=2*precision*recall/(precision+recall) if precision is not None and recall is not None and precision+recall else (0.0 if precision is not None and recall is not None else None)
    errors=lambda label,predicate:[r['record_id'] for r in records if r['label']==label and predicate(r['prediction'])][:100]
    return {'count':total,'ground_truth_counts':dict(Counter(r['label'] for r in records)),
            'confusion_matrix':{'ground_truth_rows':LABELS,'prediction_columns':PREDICTIONS,'values':matrix},
            'flag_detection_metrics':{'precision':precision,'recall':recall,'f1':f1,'known_label_count':positives+negatives,'definition':'High/Medium => Scam flag. Recall includes missed Scam abstentions. Inconclusive is not a Legitimate decision; Uncertain ground truth is excluded from binary metrics.'},
            'false_positives':fp,'false_negatives_explicit_legitimate':explicit_fn,'scams_not_flagged_including_abstentions':explicit_fn+abstained_scam,
            'abstained_scam':abstained_scam,'abstained_legitimate':abstained_legitimate,
            'false_positive_record_ids_first_100':errors('Legitimate',lambda p:p=='Scam'),
            'missed_scam_record_ids_first_100':errors('Scam',lambda p:p!='Scam'),
            'inconclusive_rate':sum(r['prediction']=='Inconclusive' for r in records)/total if total else None,
            'decision_coverage':sum(r['prediction']!='Inconclusive' for r in records)/total if total else None,
            'conclusion':'insufficient evidence / pilot only' if total<100 or positives<20 or negatives<20 else 'descriptive reviewed-corpus metrics only; representativeness not established'}

def summarize_languages(records):
    return {language:summarize([r for r in records if r['language']==language]) for language in sorted(set(LANGUAGES)|{r['language'] for r in records})}

def rules_record(row):
    result=analyze(row['text'])
    return {k:row[k] for k in ['record_id','label','language','source','scam_category']}|{'prediction':'Scam' if result['assessment'] in ['High','Medium'] else 'Inconclusive','assessment':result['assessment']}

def compare_models(rows,test,rules):
    """Fit TF-IDF on train; choose a raw decision-score threshold on validation only."""
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.metrics import f1_score
    parts={split:[r for r in rows if r['split']==split and r['label']!='Uncertain'] for split in ['train','validation']}
    if any({r['label'] for r in part}!={'Scam','Legitimate'} for part in parts.values()):
        raise ValueError('Comparison requires both known labels in train and validation; no fallback to test fitting/tuning')
    model=Pipeline([('tfidf',TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=1,max_features=100000)),('classifier',LogisticRegression(max_iter=1500,class_weight='balanced',random_state=0))])
    model.fit([r['text'] for r in parts['train']],[int(r['label']=='Scam') for r in parts['train']])
    val_scores=model.decision_function([r['text'] for r in parts['validation']]);val_y=[int(r['label']=='Scam') for r in parts['validation']]
    candidates=np.unique(np.r_[np.quantile(val_scores,np.linspace(0,1,11)),val_scores.min()-1,val_scores.max()+1])
    threshold=float(max(candidates,key=lambda t:f1_score(val_y,val_scores>=t,zero_division=0)))
    start=time.perf_counter();scores=model.decision_function([r['text'] for r in test]);latency=(time.perf_counter()-start)*1000
    ml=[{k:r[k] for k in ['record_id','label','language','source','scam_category']}|{'prediction':'Scam' if score>=threshold else 'Legitimate'} for r,score in zip(test,scores)]
    combined=[r|{'prediction':'Scam' if a['prediction']=='Scam' and r['prediction']=='Scam' else 'Inconclusive'} for a,r in zip(rules,ml)]
    report=lambda records:{'overall':summarize(records),'languages':summarize_languages(records)}
    return {'tfidf_logistic_regression':report(ml),'agreement_gate':report(combined),'threshold':threshold,'threshold_source':'validation decision_function scores, never test labels','probabilities':'not reported; calibration not evaluated','train_count':len(parts['train']),'validation_count':len(parts['validation']),'test_batch_inference_ms':latency,'combined_rationale':'Require positive agreement; all other outcomes abstain. No negative rules evidence is invented. Diagnostic precision/coverage tradeoff, not an activated model or validated improvement.'}

def evaluate(rows,manifest,compare=False):
    test=[r for r in rows if r['split']=='test'];records=[];timings=[]
    for row in test:
        start=time.perf_counter();records.append(rules_record(row));timings.append((time.perf_counter()-start)*1000)
    synthetic=any(r['data_origin']=='synthetic' for r in test)
    report={'rules_version':VERSION,'test_manifest':manifest,'input_rows_sha256':digest_rows(rows),'composition':{'all_splits':dict(Counter(r['split'] for r in rows)),'test_sources':dict(Counter(r['source'] for r in test)),'test_languages':dict(Counter(r['language'] for r in test)),'test_labels':dict(Counter(r['label'] for r in test)),'test_origins':dict(Counter(r['data_origin'] for r in test))},
            'evaluation_kind':'SYNTHETIC FUNCTIONAL SMOKE TEST; NOT DETECTION ACCURACY' if synthetic else 'Reviewed corpus evaluation; representativeness and external validity not established',
            'rules':{'overall':summarize(records),'languages':summarize_languages(records),'categories':{category:summarize([r for r in records if r['scam_category']==category]) for category in sorted({r['scam_category'] for r in records})}},
            'latency_ms':{'samples':len(timings),'median':statistics.median(timings),'p95':sorted(timings)[math.ceil(.95*len(timings))-1],'maximum':max(timings),'scope':'Per-record local rule invocation; first PSL use may include snapshot initialization; no HTTP/OCR'},
            'environment':{'python':platform.python_version(),'os':platform.platform(),'processor':platform.processor(),'logical_cpus':os.cpu_count()},'policy':'Thresholds unchanged. No model is activated. Feedback/publisher spam labels are not automatically trusted scam labels.'}
    if synthetic:
        for summary in report['rules']['languages'].values():summary['conclusion']='synthetic functional exercise only; insufficient evidence'
    if compare:
        report['comparison']=compare_models(rows,test,records)
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset',type=Path);parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--freeze-test',action='store_true');parser.add_argument('--output',type=Path)
    parser.add_argument('--allow-synthetic-smoke',action='store_true');parser.add_argument('--compare',action='store_true')
    args=parser.parse_args()
    try:
        rows,_=load(args.dataset,args.allow_synthetic_smoke)
        if args.freeze_test:
            freeze(rows,args.manifest);print('Frozen test manifest created. Evaluate in a separate command; do not tune on final test results.');return
        manifest=verify_frozen(rows,args.manifest)
        if not args.output:parser.error('--output is required for evaluation')
        report=evaluate(rows,manifest,args.compare)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open('x',encoding='utf-8') as file:json.dump(report,file,indent=2)
        print(json.dumps({'report':str(args.output),'evaluation_kind':report['evaluation_kind'],'test_count':report['rules']['overall']['count']}))
    except (ValueError,FileExistsError) as error:
        parser.exit(2,str(error)+'\n')

if __name__=='__main__':main()
