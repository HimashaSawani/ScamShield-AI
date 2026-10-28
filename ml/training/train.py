"""Train only on an explicitly frozen dataset. No bundled fabricated corpus."""
import argparse
import csv
import hashlib
import json
import time
import statistics
from pathlib import Path
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import precision_recall_fscore_support, average_precision_score, confusion_matrix, precision_recall_curve, auc
try:
    from .validation import validate
except ImportError:
    from validation import validate

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('dataset',type=Path)
    parser.add_argument('--output',type=Path,default=Path('ml/artifacts/baseline'))
    parser.add_argument('--allow-synthetic-evaluation',action='store_true',help='Pipeline smoke test only; never real-world evidence')
    args=parser.parse_args()
    raw=args.dataset.read_bytes()
    with args.dataset.open(encoding='utf-8-sig',newline='') as file:
        records=list(csv.DictReader(file))
    try:
        validation_checks=validate(records,args.allow_synthetic_evaluation)
    except ValueError as error:
        raise SystemExit(str(error))
    parts={split:[r for r in records if r['split']==split] for split in ['train','validation','test']}
    if any({r['label'] for r in rows}!={'Scam','Legitimate'} for rows in parts.values()):
        raise SystemExit('Each split must contain both labels.')
    model=Pipeline([('tfidf',TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=2,max_features=100000)),('classifier',LogisticRegression(max_iter=1500,class_weight='balanced'))])
    model.fit([r['text'] for r in parts['train']],[int(r['label']=='Scam') for r in parts['train']])
    validation=parts['validation'];vy=[int(r['label']=='Scam') for r in validation];vp=model.predict_proba([r['text'] for r in validation])[:,1]
    def metrics(y,probs,threshold):
        pred=probs>=threshold
        p,r,f,_=precision_recall_fscore_support(y,pred,average='binary',zero_division=0)
        curve_precision,curve_recall,_=precision_recall_curve(y,probs)
        return {'precision':float(p),'recall':float(r),'f1':float(f),'pr_auc':float(auc(curve_recall,curve_precision)),'average_precision':float(average_precision_score(y,probs)),'confusion_matrix':confusion_matrix(y,pred,labels=[0,1]).tolist(),'count':len(y)}
    threshold=max([i/100 for i in range(20,81,5)],key=lambda t:metrics(vy,vp,t)['f1'])
    test=parts['test'];y=[int(r['label']=='Scam') for r in test];probs=model.predict_proba([r['text'] for r in test])[:,1]
    timings=[]
    for row in test:
        start=time.perf_counter();model.predict_proba([row['text']]);timings.append((time.perf_counter()-start)*1000)
    report={'dataset_sha256':hashlib.sha256(raw).hexdigest(),'threshold':threshold,'validation_checks':validation_checks,'test':metrics(y,probs,threshold),'language':{},'category':{},'latency_ms':{'median':statistics.median(timings),'p95':sorted(timings)[min(len(timings)-1,int(len(timings)*.95))],'samples':len(timings)},'note':'No calibration evaluated. Synthetic smoke-test metrics are not real-world accuracy. Language conclusions require representative data and adequate sample counts.'}
    for lang in sorted({r['language'] for r in test}|{'English','Sinhala','Tamil','Singlish'}):
        idx=[i for i,r in enumerate(test) if r['language']==lang]
        counts={'count':len(idx),'scam_count':sum(y[i] for i in idx),'legitimate_count':sum(not y[i] for i in idx)}
        if len({y[i] for i in idx})==2:
            report['language'][lang]={**metrics([y[i] for i in idx],probs[idx],threshold),**counts,'conclusion':'insufficient evidence' if len(idx)<100 or min(counts['scam_count'],counts['legitimate_count'])<20 or validation_checks['synthetic_evaluation'] else 'descriptive held-out metrics only'}
        else:
            report['language'][lang]={**counts,'conclusion':'insufficient evidence'}
    for category in sorted({r['scam_category'] for r in test}):
        idx=[i for i,r in enumerate(test) if r['scam_category']==category]
        counts={'count':len(idx),'true_scam_count':sum(y[i] for i in idx),'predicted_scam_count':int(sum(probs[idx]>=threshold))}
        if len({y[i] for i in idx})==2:
            report['category'][category]={**metrics([y[i] for i in idx],probs[idx],threshold),**counts}
        else:
            positive=[i for i in idx if y[i]]
            report['category'][category]={**counts,'scam_recall':float(sum(probs[i]>=threshold for i in positive)/len(positive)) if positive else None,'conclusion':'single-label subset: precision and PR-AUC not estimated'}
    args.output.mkdir(parents=True,exist_ok=True)
    joblib.dump(model,args.output/'model.joblib')
    (args.output/'evaluation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':
    main()
