"""Validation-selected models; evaluate frozen test once; export data-only JSON."""
import argparse
from collections import Counter
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import time
import numpy as np
import sklearn
from sklearn.pipeline import Pipeline,FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report,confusion_matrix,f1_score,average_precision_score
from backend.app.detection import analyze,VERSION
from backend.app.model_features import url_features,URL_FEATURES,URL_SCHEMA

SEED=20261023
def digest(data):return hashlib.sha256(data).hexdigest()
def metrics(y,pred,classes,positive,scores=None):
    y=np.array(y);pred=np.array(pred);known=pred!='Inconclusive'
    binary=y==positive;flag=pred==positive
    fp=int(sum(flag&~binary));tp=int(sum(flag&binary));fn=int(sum(~flag&binary));tn=int(sum(~flag&~binary))
    p=tp/(tp+fp) if tp+fp else 0;r=tp/(tp+fn) if tp+fn else 0
    report={'count':len(y),'class_counts':dict(Counter(y.tolist())),'per_class':classification_report(y,pred,labels=classes,output_dict=True,zero_division=0),'macro_f1':float(f1_score(y,pred,labels=classes,average='macro',zero_division=0)),'confusion_matrix':{'rows':classes,'columns':classes+['Inconclusive'],'values':[[int(sum((y==a)&(pred==b))) for b in classes+['Inconclusive']] for a in classes]},'positive':positive,'positive_precision':p,'positive_recall':r,'positive_f1':2*p*r/(p+r) if p+r else 0,'false_positive_rate':fp/(fp+tn) if fp+tn else None,'false_positives':fp,'false_negatives_including_abstention':fn,'inconclusive_rate':float(1-known.mean()),'decision_coverage':float(known.mean())}
    if scores is not None:report['average_precision_PR_AUC']=float(average_precision_score(binary,scores))
    return report

def export_model(model,kind):
    if kind=='text':
        union=model.named_steps['features'];clf=model.named_steps['classifier']
        branches=[]
        for name,v in union.transformer_list:
            branches.append({'name':name,'analyzer':v.analyzer,'ngram_range':list(v.ngram_range),'sublinear_tf':v.sublinear_tf,'vocabulary':{key:int(value) for key,value in v.vocabulary_.items()},'idf':v.idf_.tolist()})
        return {'type':'tfidf-logistic','branches':branches,'classes':clf.classes_.tolist(),'coef':clf.coef_.tolist(),'intercept':clf.intercept_.tolist()}
    if isinstance(model,Pipeline):
        scaler=model.named_steps['scale'];clf=model.named_steps['classifier']
        return {'type':'numeric-logistic','classes':clf.classes_.tolist(),'mean':scaler.mean_.tolist(),'scale':scaler.scale_.tolist(),'coef':clf.coef_.tolist(),'intercept':clf.intercept_.tolist()}
    return {'type':'numeric-forest','classes':model.classes_.tolist(),'trees':[{'left':t.tree_.children_left.tolist(),'right':t.tree_.children_right.tolist(),'feature':t.tree_.feature.tolist(),'threshold':t.tree_.threshold.tolist(),'value':t.tree_.value[:,0,:].tolist()} for t in model.estimators_]}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--prepared',type=Path,default=Path('ml/prepared/v1'));parser.add_argument('--output',type=Path,default=Path('ml/artifacts/v1'));parser.add_argument('--version',default='v1');args=parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,39}',args.version):raise SystemExit('Supply a short unique version identifier')
    if args.output.exists():raise SystemExit('Use a new version: final test reports/artifacts cannot be overwritten')
    args.output.mkdir(parents=True)
    config={'seed':SEED,'version':args.version,'threshold_candidates':[.40,.50,.60,.70,.80,.90,.95],'selection_metric':'validation macro F1','text':{'word_ngrams':[1,2],'word_max_features':40000,'char_ngrams':[3,5],'char_max_features':60000,'min_df':2,'sublinear_tf':True,'classifier':'LogisticRegression','max_iter':1000,'class_weight':'balanced'},'url':{'feature_schema':URL_SCHEMA,'baseline':'StandardScaler plus LogisticRegression, max_iter=1500, balanced','forest':{'n_estimators':64,'max_depth':14,'min_samples_leaf':5,'class_weight':'balanced','n_jobs':2}},'hybrid':'Strong credential plus urgency can add a positive screening flag; validation must improve macro F1 to select; app never lowers rule concerns'}
    (args.output/'training-config.json').write_text(json.dumps(config,indent=2))
    reports={};artifacts={}
    for kind in ['text','url']:
        path=args.prepared/(kind+'.csv');rows=list(csv.DictReader(path.open(encoding='utf-8',newline='')))
        frozen=json.loads((args.prepared/(kind+'-frozen.json')).read_text())
        assert digest(path.read_bytes())==frozen['prepared_sha256'],'Prepared corpus changed'
        parts={s:[r for r in rows if r['split']==s] for s in ['train','validation','test']}
        assert digest(json.dumps(parts['test'],sort_keys=True).encode())==frozen['test_sha256']
        group_sets={s:{r['group'] for r in rs} for s,rs in parts.items()}
        assert all(not group_sets[a]&group_sets[b] for a,b in [('train','test'),('train','validation'),('validation','test')])
        positive='smishing' if kind=='text' else 'phishing';classes=['ham','spam','smishing'] if kind=='text' else ['legitimate','phishing']
        X={s:[r['text'] for r in rs] if kind=='text' else np.array([url_features(r['text']) for r in rs]) for s,rs in parts.items()}
        y={s:[r['label'] for r in rs] for s,rs in parts.items()}
        if kind=='text':
            candidates={'word-char-logistic':Pipeline([('features',FeatureUnion([('word',TfidfVectorizer(ngram_range=(1,2),min_df=2,max_features=40000,sublinear_tf=True)),('char',TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=2,max_features=60000,sublinear_tf=True))])),('classifier',LogisticRegression(max_iter=1000,class_weight='balanced',random_state=SEED))])}
        else:
            candidates={'scaled-logistic':Pipeline([('scale',StandardScaler()),('classifier',LogisticRegression(max_iter=1500,class_weight='balanced',random_state=SEED))]),'static-random-forest':RandomForestClassifier(n_estimators=64,max_depth=14,min_samples_leaf=5,class_weight='balanced',random_state=SEED,n_jobs=2)}
        selection={};fitted={}
        for name,model in candidates.items():
            started=time.perf_counter();model.fit(X['train'],y['train']);prob=model.predict_proba(X['validation']);names=list(model.classes_);positive_idx=names.index(positive)
            best=None
            for threshold in [.40,.50,.60,.70,.80,.90,.95]:
                pred=np.array(names)[prob.argmax(axis=1)];pred=np.where(prob[:,positive_idx]>=threshold,positive,np.where(pred==positive,'ham' if kind=='text' else 'legitimate',pred))
                m=metrics(y['validation'],pred,classes,positive,prob[:,positive_idx]);key=m['macro_f1']
                if best is None or key>best[0]:best=(key,threshold,m)
            selection[name]={'threshold':best[1],'validation':best[2],'training_seconds':time.perf_counter()-started};fitted[name]=model
            print(kind,name,'validation macro F1',best[0],flush=True)
        chosen=max(selection,key=lambda n:selection[n]['validation']['macro_f1']);model=fitted[chosen];threshold=selection[chosen]['threshold']
        # Hybrid candidate is fixed before final test: strong credential+pressure
        # rules can add a flag, but never override a rule flag to safe.
        def rules_prediction(text):
            r=analyze(text,kind)
            return (positive if r['assessment'] in ['High','Medium'] else 'Inconclusive',{'credentials','urgency'}<={e['code'] for e in r['evidence']})
        rule_val=[rules_prediction(r['text']) for r in parts['validation']]
        vp=model.predict_proba(X['validation']);names=list(model.classes_);pi=names.index(positive)
        def predictions(prob):
            pred=np.array(names)[prob.argmax(axis=1)]
            return np.where(prob[:,pi]>=threshold,positive,np.where(pred==positive,'ham' if kind=='text' else 'legitimate',pred))
        val_pred=predictions(vp);hybrid_val=np.array([positive if strong else p for p,(_,strong) in zip(val_pred,rule_val)])
        hybrid_metrics=metrics(y['validation'],hybrid_val,classes,positive)
        use_hybrid=kind=='text' and hybrid_metrics['macro_f1']>selection[chosen]['validation']['macro_f1']
        gate=hybrid_metrics if use_hybrid else selection[chosen]['validation']
        supported=gate['positive_precision']>=.95 and gate['positive_recall']>=.70 and gate['false_positive_rate']<=.02 and min(Counter(y['validation']).values())>=50
        decision={'candidate':chosen,'threshold':threshold,'hybrid':use_hybrid,'activation_eligible_on_validation':supported,'gate':'positive precision >=.95, recall >=.70, FPR <=.02, >=50 validation examples/class; source-benchmark checks only, external validity unestablished','selected_before_test':True}
        (args.output/(kind+'-selection.json')).write_text(json.dumps({'decision':decision,'candidates':selection,'hybrid_validation':hybrid_metrics},indent=2))
        # Test is touched for reporting only after selection is frozen above.
        tp=model.predict_proba(X['test']);pred=predictions(tp);rule_test=[rules_prediction(r['text']) for r in parts['test']]
        hybrid=np.array([positive if strong else p for p,(_,strong) in zip(pred,rule_test)])
        errors={name:{'false_positive_ids':[r['id'] for r,p in zip(parts['test'],ps) if r['label']!=positive and p==positive][:20],'false_negative_ids':[r['id'] for r,p in zip(parts['test'],ps) if r['label']==positive and p!=positive][:20]} for name,ps in [('model',pred),('rules',[p for p,_ in rule_test])]}
        timings=[]
        for i in range(min(100,len(parts['test']))):
            start=time.perf_counter();model.predict_proba([X['test'][i]]);timings.append((time.perf_counter()-start)*1000)
        report={'decision':decision,'split_counts':{s:dict(Counter(ys)) for s,ys in y.items()},'validation_candidates':selection,'test':{'rules':metrics(y['test'],[p for p,_ in rule_test],classes,positive),'model':metrics(y['test'],pred,classes,positive,tp[:,pi]),'hybrid':metrics(y['test'],hybrid,classes,positive)},'errors':errors,'latency_ms':{'median':statistics.median(timings),'p95':float(np.quantile(timings,.95)),'scope':'100 single-record estimator calls; URL extraction separate'},'rules_mapping':'High/Medium => smishing/phishing flag, all other rules assessments abstain. This is a screening proxy, not equivalence of risk and publisher classes. Rules cannot distinguish ham/spam.','limitations':'Historical publisher labels, no independent adjudication or representative deployment accuracy; no calibrated probabilities; no multilingual conclusions. SMS is predominantly English with mixed/transliterated records not individually language-adjudicated.','unsupported_languages':['Sinhala','Tamil','Singlish'],'calibration':'not evaluated','environment':{'python':platform.python_version(),'sklearn':sklearn.__version__,'numpy':np.__version__,'platform':platform.platform(),'logical_cpus':os.cpu_count()},'data_sha256':frozen['prepared_sha256'],'seed':SEED,'rules_version':VERSION,'feature_schema':URL_SCHEMA if kind=='url' else 'word-char-tfidf-1'}
        reports[kind]=report
        artifact=export_model(model,kind)|{'kind':kind,'version':'scamshield-'+kind+'-'+args.version,'threshold':threshold,'hybrid':use_hybrid,'validation_eligible':supported,'data_sha256':frozen['prepared_sha256'],'label_mapping':{'ham':'ham','spam':'spam','Smishing':'smishing'} if kind=='text' else {'1':'legitimate','0':'phishing'},'report_file':kind+'-report.json','feature_schema':URL_SCHEMA if kind=='url' else 'word-char-tfidf-1','url_features':URL_FEATURES if kind=='url' else None,'scope':report['limitations'],'environment':report['environment']}
        target=args.output/(kind+'-model.json');target.write_text(json.dumps(artifact,separators=(',',':')));artifacts[kind]={'file':target.name,'sha256':digest(target.read_bytes()),'validation_eligible':supported}
        (args.output/(kind+'-report.json')).write_text(json.dumps(report,indent=2))
        print(kind,'test',report['test']['model']['macro_f1'],'validation gate',supported,flush=True)
    (args.output/'manifest.json').write_text(json.dumps({'format':1,'artifacts':artifacts,'no_pickle':'Data-only JSON; no executable object deserialization'},indent=2))

if __name__=='__main__':main()
