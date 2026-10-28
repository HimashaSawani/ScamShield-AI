"""Verify the real local API/worker and browser; never deletes or rewrites scans."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
from contextlib import closing
import time
import urllib.request
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.app.detection import VERSION
A='Your bank account will be blocked today. Reply with your password and OTP immediately to keep your account active.'
B='Your verification code is 123456. Never share this code with anyone. Our staff will never ask for your password or OTP.'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['before','after']);args=parser.parse_args()
    base='http://127.0.0.1:8015';token=''
    def api(path,body=None):
        request=urllib.request.Request(base+'/api'+path,data=json.dumps(body).encode() if body is not None else None,headers={**({'Authorization':'Bearer '+token} if token else {}),'Content-Type':'application/json'})
        with urllib.request.urlopen(request,timeout=15) as response:return json.load(response)
    demo_email = os.getenv('SCAMSHIELD_DEMO_EMAIL', 'demo@scamshield.test')
    demo_password = os.getenv('SCAMSHIELD_DEMO_PASSWORD', '')
    token=api('/auth/login',{'email':demo_email,'password':demo_password})['token']
    before_path=ROOT/'artifacts'/'detection-before.json';before_path.parent.mkdir(exist_ok=True)
    def hashes():
        with closing(sqlite3.connect(f'{(ROOT/"scamshield.db").as_uri()}?mode=ro',uri=True)) as db:
            return {id:hashlib.sha256(result.encode()).hexdigest() for id,result in db.execute("SELECT id,result FROM scans WHERE status='completed'")}
    record={'mode':args.mode,'health':api('/health'),'assets':{},'results':{}}
    for name in ['app.js','style.css']:
        with urllib.request.urlopen(base+'/'+name) as response:data=response.read()
        record['assets'][name]={'matches_workspace':data==(ROOT/'apps/dashboard'/name).read_bytes(),'sha256':hashlib.sha256(data).hexdigest()}
    if args.mode=='before':record['historical_results']=hashes()
    for label,text in [('A',A),('B',B)]:
        scan=api('/scans',{'kind':'text','text':text})
        for _ in range(120):
            scan=api('/scans/'+scan['id'])
            if scan['status'] not in ['queued','processing']:break
            time.sleep(.25)
        assert scan['status']=='completed',scan['status']
        r=scan['result'];record['results'][label]={'id':scan['id'],'processing_status':scan['status'],'assessment':r['assessment'],'score':r['score'],'version':r['version'],'evidence_codes':[e['code'] for e in r['evidence']],'evidence':[{'title':e['description'],'quote':e['quote'],'weight':e['weight']} for e in r['evidence']]}
    if args.mode=='before':
        record['historical_results']=hashes();before_path.write_text(json.dumps(record,indent=2))
    else:
        previous=json.loads(before_path.read_text());current=hashes()
        record['historical_results_unchanged']=all(current.get(id)==value for id,value in previous['historical_results'].items())
        assert record['historical_results_unchanged']
        assert record['results']['A']['assessment']=='High'
        assert {'credentials','urgency'}<=set(record['results']['A']['evidence_codes'])
        assert record['results']['B']['assessment']=='Inconclusive'
        assert 'credentials' not in record['results']['B']['evidence_codes']
        assert all(r['version']==VERSION for r in record['results'].values())
        (ROOT/'docs/detection-live-verification.json').write_text(json.dumps(record,indent=2))
    print(json.dumps({k:v for k,v in record.items() if k!='historical_results'},indent=2))
    api('/auth/logout',{})

if __name__=='__main__':main()
