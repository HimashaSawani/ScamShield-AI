"""Add new acceptance records to localhost:8015. Never rewrites/deletes history."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import time
import httpx
from PIL import Image
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts.verify_detection_live import A,B

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--expect-fallback',action='store_true');args=parser.parse_args()
    with sqlite3.connect('file:scamshield.db?mode=ro',uri=True) as db:before={id:hashlib.sha256(result.encode()).hexdigest() for id,result in db.execute("SELECT id,result FROM scans WHERE status='completed'")}
    with httpx.Client(base_url='http://127.0.0.1:8015/api',timeout=30) as client:
        auth=client.post('/auth/login',json={'email':'demo@scamshield.test','password':'ScamShieldDemo123!'});auth.raise_for_status();client.headers['Authorization']='Bearer '+auth.json()['token']
        def poll(id):
            for _ in range(160):
                response=client.get('/scans/'+id);response.raise_for_status();scan=response.json()
                if scan['status'] not in ['queued','processing']:return scan
                time.sleep(.25)
            raise AssertionError('Queue timeout')
        def create(kind,text):
            response=client.post('/scans',json={'kind':kind,'text':text});response.raise_for_status();return poll(response.json()['id'])
        if args.expect_fallback:
            scan=create('text',A);r=scan['result'];assert scan['status']=='completed' and r['assessment']=='High' and any('fallback' in s for s in r['coverage']['failed'])
            record={'scan_id':scan['id'],'status':scan['status'],'result':r}
            target='model-fallback-live.json'
        else:
            cases={'A':('text',A),'B':('text',B),'C':('url','https://bank.invalid@account-check.invalid/login'),'promotion':('text','Our shop has a 10% discount this weekend. Visit us during opening hours.'),'named_url':('url','https://example.com/about')}
            scans={label:create(kind,text) for label,(kind,text) in cases.items()}
            assert scans['A']['result']['assessment']=='High' and {e['code'] for e in scans['A']['result']['evidence']}>={'credentials','urgency'}
            assert scans['B']['result']['assessment']=='Inconclusive' and not scans['B']['result']['evidence']
            assert scans['C']['result']['url_details'][0]['hostname']=='account-check.invalid'
            assert scans['promotion']['result']['assessment']=='Inconclusive'
            assert scans['named_url']['result']['models'][0]['version']=='scamshield-url-v1'
            # Real queue + adapter path, synthetic image; absence of Tesseract is
            # allowed only as explicit manual fallback, never invented OCR quality.
            image=io.BytesIO();Image.new('RGB',(160,100),'white').save(image,format='PNG')
            response=client.post('/scans/screenshot',files={'file':('acceptance.png',image.getvalue(),'image/png')})
            response.raise_for_status();shot=poll(response.json()['id']);assert shot['status'] in ['awaiting_confirmation','partially_completed']
            preview=shot['status'];response=client.post('/scans/'+shot['id']+'/confirm',json={'kind':'text','text':A});response.raise_for_status();shot=poll(shot['id']);assert shot['text']==A and shot['result']['assessment']=='High'
            scans['corrected_screenshot']=shot
            for scan in scans.values():assert client.get('/scans/'+scan['id']).json()['result']==scan['result']
            record={'scans':{label:{'id':scan['id'],'status':scan['status'],'result':scan['result']} for label,scan in scans.items()},'screenshot_preview_status':preview,'screenshot_scope':'Synthetic upload, real adapter/manual correction queue; not OCR accuracy','model_endpoint':client.get('/model').json()}
            target='models-live-verification.json'
        with sqlite3.connect('file:scamshield.db?mode=ro',uri=True) as db:after={id:hashlib.sha256(result.encode()).hexdigest() for id,result in db.execute("SELECT id,result FROM scans WHERE status='completed'")}
        record['historical_results_unchanged']=all(after.get(id)==value for id,value in before.items());assert record['historical_results_unchanged']
        (ROOT/'docs'/target).write_text(json.dumps(record,indent=2),encoding='utf-8');print(json.dumps({'report':target,'historical_results_unchanged':True,**({'ids':{label:scan['id'] for label,scan in scans.items()}} if not args.expect_fallback else {'id':scan['id']})},indent=2));client.post('/auth/logout')

if __name__=='__main__':main()
