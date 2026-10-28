import hashlib
import json
import numpy as np
import pytest
from sklearn.pipeline import Pipeline,FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from backend.app.detection import analyze
from backend.app.model_features import url_features,URL_SCHEMA,URL_FEATURES
from backend.app.model_inference import load_bundle,predict,enrich
from ml.train_v1 import export_model

def fixture_bundle(tmp_path):
    x=['ordinary meeting tomorrow','normal chat with friends','discount sale at store','sale offer today only','send your bank password','reply with verification code']
    y=['ham','ham','spam','spam','smishing','smishing']
    model=Pipeline([('features',FeatureUnion([('word',TfidfVectorizer()),('char',TfidfVectorizer(analyzer='char',ngram_range=(3,5)))])),('classifier',LogisticRegression())]).fit(x,y)
    import sklearn
    data=export_model(model,'text')|{'kind':'text','version':'test-only','threshold':.5,'validation_eligible':True,'feature_schema':'word-char-tfidf-1','environment':{'sklearn':sklearn.__version__}}
    path=tmp_path/'text.json';path.write_text(json.dumps(data));manifest={'format':1,'artifacts':{'text':{'file':'text.json','sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'validation_eligible':True}}}
    target=tmp_path/'manifest.json';target.write_text(json.dumps(manifest));pin=hashlib.sha256(target.read_bytes()).hexdigest()
    return x,model,pin

def test_json_text_parity_and_integrity(tmp_path):
    x,model,pin=fixture_bundle(tmp_path)
    data=load_bundle(str(tmp_path),pin)['text']
    for text,prob in zip(x,model.predict_proba(x)):
        names=list(model.classes_);expected='smishing' if prob[names.index('smishing')]>=.5 else names[int(prob.argmax())]
        if expected=='smishing' and prob[names.index('smishing')]<.5:expected='ham'
        assert predict(data,text)==expected
    load_bundle.cache_clear();(tmp_path/'text.json').write_text('{}')
    with pytest.raises(ValueError,match='integrity'):load_bundle(str(tmp_path),pin)

def test_forest_export_parity():
    urls=['https://example.com/','http://192.0.2.1/login','https://bank.invalid@evil.invalid/login','https://example.org/about']
    x=[url_features(u) for u in urls];y=['legitimate','phishing','phishing','legitimate']
    model=RandomForestClassifier(n_estimators=4,random_state=3).fit(x,y)
    data=export_model(model,'url')|{'kind':'url','threshold':.5}
    for url,probs in zip(urls,model.predict_proba(x)):
        assert predict(data,url)==('phishing' if probs[list(model.classes_).index('phishing')]>=.5 else 'legitimate')

def test_explicit_missing_corrupt_and_disabled_fallback(monkeypatch,tmp_path):
    monkeypatch.delenv('SCAMSHIELD_MODEL_DIR',raising=False)
    r=enrich(analyze('ordinary message'),'ordinary message','text')
    assert r['assessment']=='Inconclusive' and r['model_mode']=='rules-only'
    monkeypatch.setenv('SCAMSHIELD_MODEL_DIR',str(tmp_path));monkeypatch.setenv('SCAMSHIELD_MODEL_MANIFEST_SHA256','0'*64)
    r=enrich(analyze('Send your password immediately'),'Send your password immediately','text')
    assert r['assessment']=='High' and r['score']==65 and r['models']==[]
    assert 'fallback' in r['coverage']['failed'][-1]

def test_nonpositive_model_cannot_erase_rule_evidence(monkeypatch,tmp_path):
    _,_,pin=fixture_bundle(tmp_path)
    monkeypatch.setenv('SCAMSHIELD_MODEL_DIR',str(tmp_path));monkeypatch.setenv('SCAMSHIELD_MODEL_MANIFEST_SHA256',pin)
    monkeypatch.setattr('backend.app.model_inference.predict',lambda *_:'spam')
    text='Reply with your password immediately';r=enrich(analyze(text),text,'text')
    assert r['assessment']=='High' and r['score']==65
    assert r['models'][0]['prediction']=='spam' and 'conflict' in r['models'][0]
    assert len(r['evidence'])==2

def test_positive_model_has_no_fabricated_evidence(monkeypatch,tmp_path):
    _,_,pin=fixture_bundle(tmp_path);monkeypatch.setenv('SCAMSHIELD_MODEL_DIR',str(tmp_path));monkeypatch.setenv('SCAMSHIELD_MODEL_MANIFEST_SHA256',pin)
    monkeypatch.setattr('backend.app.model_inference.predict',lambda *_:'smishing')
    r=enrich(analyze('ordinary words'),'ordinary words','text')
    assert r['assessment']=='Medium' and r['score']==0 and r['evidence']==[]
    assert r['models'][0]['version']=='test-only'

def test_script_scope_and_inference_failure(monkeypatch,tmp_path):
    _,_,pin=fixture_bundle(tmp_path);monkeypatch.setenv('SCAMSHIELD_MODEL_DIR',str(tmp_path));monkeypatch.setenv('SCAMSHIELD_MODEL_MANIFEST_SHA256',pin)
    r=enrich(analyze('தமிழ்'),'தமிழ்','text');assert r['models']==[]
    def fail(*_):raise RuntimeError('fixture failure')
    monkeypatch.setattr('backend.app.model_inference.predict',fail)
    r=enrich(analyze('ordinary words'),'ordinary words','text')
    assert r['assessment']=='Inconclusive' and 'fallback' in r['coverage']['failed'][-1]
