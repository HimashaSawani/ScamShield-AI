"""Opt-in, integrity-pinned data-only inference. Never unpickles objects."""
import hashlib
import json
import os
from pathlib import Path
from functools import lru_cache
from .model_features import URL_SCHEMA,URL_FEATURES,URL_SCHEMAS,url_features

def read_json(path,expected):
    raw=path.read_bytes()
    if len(raw)>64*1024*1024 or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Model integrity check failed')
    return json.loads(raw)

@lru_cache(maxsize=4)
def load_bundle(folder,manifest_hash):
    directory=Path(folder).resolve()
    if len(manifest_hash)!=64:raise ValueError('Operator-pinned manifest checksum required')
    manifest=read_json(directory/'manifest.json',manifest_hash)
    if manifest.get('format')!=1:raise ValueError('Unknown model manifest schema')
    models={}
    for kind,entry in manifest['artifacts'].items():
        if kind not in ['text','url']:raise ValueError('Unknown model kind')
        path=(directory/entry['file']).resolve()
        if path.parent!=directory or path.suffix!='.json':raise ValueError('Invalid artifact path')
        data=read_json(path,entry['sha256'])
        if not entry.get('validation_eligible') or not data.get('validation_eligible'):continue
        if data['kind']!=kind:raise ValueError('Model kind mismatch')
        if kind=='url':
            schema=data.get('feature_schema')
            expected_feats=URL_SCHEMAS.get(schema)
            if expected_feats is None or data.get('url_features')!=expected_feats:raise ValueError('Feature schema mismatch')
        if data['type']=='tfidf-logistic':
            import numpy as np
            from scipy.sparse import hstack
            from sklearn.feature_extraction.text import TfidfVectorizer
            import sklearn
            if data['environment']['sklearn']!=sklearn.__version__:raise ValueError('Model dependency version mismatch')
            vectors=[]
            for branch in data['branches']:
                v=TfidfVectorizer(analyzer=branch['analyzer'],ngram_range=tuple(branch['ngram_range']),sublinear_tf=branch['sublinear_tf'],vocabulary=branch['vocabulary'])
                v.idf_=np.array(branch['idf']);vectors.append(v)
            data['_vectors']=vectors
        models[kind]=data
    return models

def predict(data,text):
    import numpy as np
    if data['type']=='tfidf-logistic':
        from scipy.sparse import hstack
        x=hstack([v.transform([text]) for v in data['_vectors']]);logits=np.asarray(x@np.array(data['coef']).T).ravel()+np.array(data['intercept'])
        scores=np.exp(logits-logits.max());scores/=scores.sum()
    elif data['type']=='numeric-logistic':
        schema=data.get('feature_schema','url-static-1')
        x=(np.array(url_features(text,schema=schema))-data['mean'])/data['scale']
        z=float(np.array(data['coef'])[0]@x+data['intercept'][0]);p=1/(1+np.exp(-np.clip(z,-700,700)));scores=np.array([1-p,p])
    elif data['type']=='numeric-forest':
        schema=data.get('feature_schema','url-static-1')
        x=np.array(url_features(text,schema=schema),dtype=np.float32);scores=np.zeros(len(data['classes']))
        for tree in data['trees']:
            node=0
            while tree['left'][node]!=tree['right'][node]:node=tree['left'][node] if x[tree['feature'][node]]<=tree['threshold'][node] else tree['right'][node]
            values=np.array(tree['value'][node]);scores+=values/values.sum()
        scores/=len(data['trees'])
    else:raise ValueError('Unsupported data-only estimator')
    if not np.isfinite(scores).all():raise ValueError('Invalid estimator output')
    positive='smishing' if data['kind']=='text' else 'phishing';pi=data['classes'].index(positive)
    label=positive if scores[pi]>=data['threshold'] else data['classes'][int(scores.argmax())]
    if label==positive and scores[pi]<data['threshold']:label='ham' if data['kind']=='text' else 'legitimate'
    return label

def enrich(result,text,kind):
    """Rules evidence/indicator score remain untouched; ML can add Medium only."""
    folder=os.getenv('SCAMSHIELD_MODEL_DIR','');pin=os.getenv('SCAMSHIELD_MODEL_MANIFEST_SHA256','')
    result['models']=[];result['model_mode']='rules-only'
    if not folder:
        result['coverage']['unavailable'].append('Optional models disabled by operator configuration')
        return result
    try:
        models=load_bundle(folder,pin)
    except Exception:
        result['coverage'].setdefault('failed',[]).append('Configured model loading failed; rules-only fallback')
        return result
    applicable=[('url',d['url']) for d in result.get('url_details',[]) if d['hostname'] and d['registrable_domain']]
    if any(d['hostname'] and not d['registrable_domain'] for d in result.get('url_details',[])):
        result['coverage']['unavailable'].append('URL model abstained: IP/unknown suffix outside reviewed named-domain scope')
    if kind!='url':applicable.insert(0,('text',text))
    for model_kind,value in applicable:
        data=models.get(model_kind)
        if not data:
            result['coverage']['unavailable'].append(model_kind+' model absent or failed validation gate')
            continue
        # Source corpus is English-dominant, not a multilingual validation set.
        # This guard detects script mismatch, not the language of Latin text.
        if model_kind=='text' and any('\u0d80'<=c<='\u0dff' or '\u0b80'<=c<='\u0bff' for c in value):
            result['coverage']['unavailable'].append('Text model unsupported for Sinhala/Tamil scripts; Singlish also unvalidated')
            continue
        try:
            label=predict(data,value)
            entry={'kind':model_kind,'version':data['version'],'prediction':label,'scope':'Historical English-dominant SMS benchmark / static URL syntax only; not calibrated or verified sender identity','effect':'No rule evidence or score changed'}
            positive=label in ['smishing','phishing']
            if positive and result['assessment']=='Inconclusive':
                result['assessment']='Medium';entry['effect']='Added Medium model concern; rules indicator score unchanged'
                result['explanation']='A validated source-benchmark model flags possible phishing. This is separate from rule evidence and does not confirm fraud or sender identity.'
                result['next_actions']=['Verify through an independently obtained official contact.','Keep passwords and one-time codes private.','Avoid unverified links and payments.']
            if not positive and result['assessment'] in ['High','Medium']:entry['conflict']='Model did not flag phishing; rule concern retained. Neither signal verifies safety.'
            result['models'].append(entry);result['model_mode']='rules-plus-model'
            result['coverage']['completed'].append(model_kind+' model inference '+data['version'])
        except Exception:
            result['coverage'].setdefault('failed',[]).append(model_kind+' model inference failed; rules-only fallback for this input')
    if result['models']:
        result['coverage']['unavailable']=[s for s in result['coverage']['unavailable'] if s!='Trained model inference']
    return result

def model_status():
    folder=os.getenv('SCAMSHIELD_MODEL_DIR','')
    if not folder:return {'mode':'rules-only','enabled':[],'status':'Optional models disabled'}
    try:
        models=load_bundle(folder,os.getenv('SCAMSHIELD_MODEL_MANIFEST_SHA256',''))
        return {'mode':'rules-plus-model' if models else 'rules-only','enabled':[{'kind':kind,'version':data['version']} for kind,data in models.items()],'status':'Source-benchmark validation only; no calibrated or multilingual performance claim'}
    except Exception:return {'mode':'rules-only','enabled':[],'status':'Configured model unavailable; rules-only fallback'}
