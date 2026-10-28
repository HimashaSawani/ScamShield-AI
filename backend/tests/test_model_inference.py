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

def test_released_url_model_bundle_and_worker_inference(monkeypatch):
    from pathlib import Path
    from backend.app.model_inference import model_status
    bundle=Path(__file__).resolve().parents[2]/'ml'/'artifacts'/'v1-json'
    if not (bundle/'manifest.json').is_file():
        pytest.skip('v1-json model bundle not present')
    expected_pin='833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9'
    assert hashlib.sha256((bundle/'manifest.json').read_bytes()).hexdigest()==expected_pin
    monkeypatch.setenv('SCAMSHIELD_MODEL_DIR',str(bundle))
    monkeypatch.setenv('SCAMSHIELD_MODEL_MANIFEST_SHA256',expected_pin)
    load_bundle.cache_clear()
    models=load_bundle(str(bundle),expected_pin)
    assert list(models.keys())==['url']
    assert 'text' not in models
    assert models['url']['version']=='scamshield-url-v1'
    assert models['url']['feature_schema']==URL_SCHEMA
    assert models['url']['url_features']==URL_FEATURES
    status=model_status()
    assert status['mode']=='rules-plus-model'
    assert status['enabled']==[{'kind':'url','version':'scamshield-url-v1'}]
    # Named-domain URL missed by rules alone is elevated to Medium by URL ML without altering indicator score
    url='https://apple-verify.example.com/login'
    rule_only=analyze(url,'url')
    assert rule_only['assessment']=='Inconclusive' and rule_only['score']==20
    combined=enrich(analyze(url,'url'),url,'url')
    assert combined['assessment']=='Medium' and combined['score']==20
    assert combined['model_mode']=='rules-plus-model'
    assert combined['models'][0]['version']=='scamshield-url-v1'
    assert combined['models'][0]['prediction']=='phishing'
    assert 'url model inference scamshield-url-v1' in combined['coverage']['completed']
    # Legitimate root homepage in source domain style remains Inconclusive when model predicts legitimate
    legit='https://www.southbankmosaics.com'
    legit_res=enrich(analyze(legit,'url'),legit,'url')
    assert legit_res['assessment']=='Inconclusive' and legit_res['score']==0
    assert legit_res['models'][0]['prediction']=='legitimate'

def test_v2_url_model_bundle_and_worker_inference(monkeypatch):
    from pathlib import Path
    from backend.app.model_inference import model_status
    bundle=Path(__file__).resolve().parents[2]/'ml'/'artifacts'/'v2-json'
    if not (bundle/'manifest.json').is_file():
        pytest.skip('v2-json model bundle not present')
    expected_pin='b9c99c7e5bc4e003357748dd343ca5f9e44fc9c24f03c611f77e4d342ca33606'
    assert hashlib.sha256((bundle/'manifest.json').read_bytes()).hexdigest()==expected_pin
    monkeypatch.setenv('SCAMSHIELD_MODEL_DIR',str(bundle))
    monkeypatch.setenv('SCAMSHIELD_MODEL_MANIFEST_SHA256',expected_pin)
    load_bundle.cache_clear()
    models=load_bundle(str(bundle),expected_pin)
    assert list(models.keys())==['url']
    assert 'text' not in models
    assert models['url']['version']=='scamshield-url-v2'
    assert models['url']['feature_schema']=='url-static-2'
    assert len(models['url']['url_features'])==28
    status=model_status()
    assert status['mode']=='rules-plus-model'
    assert status['enabled']==[{'kind':'url','version':'scamshield-url-v2'}]
    # Phishing link elevated to Medium
    phish_url='https://apple-verify.example.com/login'
    combined=enrich(analyze(phish_url,'url'),phish_url,'url')
    assert combined['assessment']=='Medium'
    assert combined['model_mode']=='rules-plus-model'
    assert combined['models'][0]['version']=='scamshield-url-v2'
    assert combined['models'][0]['prediction']=='phishing'
    # Legitimate deep path URL remains Inconclusive (addressing path bias)
    deep_path='https://docs.python.org/3/library/sqlite3.html'
    deep_res=enrich(analyze(deep_path,'url'),deep_path,'url')
    assert deep_res['assessment']=='Inconclusive'
    assert deep_res['models'][0]['prediction']=='legitimate'
