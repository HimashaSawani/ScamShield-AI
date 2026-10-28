import base64
import hashlib
import hmac
import io
import os
import struct
import tempfile
from pathlib import Path

TEST_ROOT = Path(tempfile.mkdtemp(prefix='scamshield-tests-'))
test_database = os.getenv('SCAMSHIELD_TEST_DATABASE_URL')
if test_database:
    from sqlalchemy.engine import make_url
    if not (make_url(test_database).database or '').endswith('_test'):
        raise RuntimeError('Destructive integration tests require a dedicated database ending in _test')
os.environ['DATABASE_URL'] = test_database or 'sqlite:///'+str(TEST_ROOT/'test.db')
os.environ['STORAGE_PATH'] = str(TEST_ROOT/'storage')
os.environ['DEV_EMAIL_TOKENS'] = '1'

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import select
from backend.app.db import Base, engine, Session, User, Scan, now
from backend.app.main import app
from backend.app.worker import process_one
from backend.app.detection import analyze

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

def account(email='user@example.com', role='user'):
    password = 'correct-password-123'
    r = client.post('/api/auth/register', json={'email':email,'password':password})
    assert r.status_code == 201, r.text
    assert client.post('/api/auth/verify',json={'token':r.json()['development_token']}).status_code == 200
    otp = ''
    if role != 'user':
        secret = base64.b32encode(b'12345678901234567890').decode()
        with Session() as db:
            user = db.scalar(select(User).where(User.email == email))
            user.role, user.mfa_secret = role, secret
            db.commit()
        block = hmac.new(base64.b32decode(secret),struct.pack('>Q',int(now()//30)),hashlib.sha1).digest()
        offset=block[-1]&15
        otp=f'{(struct.unpack(">I",block[offset:offset+4])[0]&0x7fffffff)%1000000:06d}'
    r = client.post('/api/auth/login',json={'email':email,'password':password,'otp':otp})
    assert r.status_code == 200, r.text
    return {'Authorization':'Bearer '+r.json()['token']}

def scan(headers,text='Urgent! Send your OTP immediately. Claim your prize https://bank-login.example.com',key=None):
    r = client.post('/api/scans',headers={**headers,**({'Idempotency-Key':key} if key else {})},json={'kind':'text','text':text})
    assert r.status_code == 202, r.text
    return r.json()['id']

def test_end_to_end_ownership_idempotency_review_and_audit():
    a,b,analyst,admin=account(),account('b@example.com'),account('analyst@example.com','analyst'),account('admin@example.com','admin')
    sid=scan(a,key='one')
    assert scan(a,key='one')==sid
    assert client.get('/api/scans/'+sid,headers=b).status_code==404
    assert client.delete('/api/scans/'+sid,headers=b).status_code==404
    assert client.get('/api/reports',headers=a).status_code==403
    assert process_one()
    assert not process_one()
    result=client.get('/api/scans/'+sid,headers=a).json()
    assert result['status']=='completed'
    assert result['result']['assessment']=='High'
    for e in result['result']['evidence']:
        assert result['text'][e['start']:e['end']]==e['quote']
    rid=client.post('/api/scans/'+sid+'/report',headers=a,json={'reason':'Please verify this request'}).json()['id']
    assert client.get('/api/reports',headers=analyst).json()[0]['id']==rid
    assert client.post('/api/reports/'+rid+'/decision',headers=a,json={'verdict':'Legitimate','reason':'No permission'}).status_code==403
    assert client.post('/api/reports/'+rid+'/decision',headers=analyst,json={'verdict':'Confirmed scam','reason':'Credential request verified'}).status_code==200
    result=client.get('/api/scans/'+sid,headers=a).json()
    assert result['reviews'][0]['verdict']=='Confirmed scam'
    assert result['result']['assessment']=='High'
    assert any(r['action']=='report.review' for r in client.get('/api/admin/audit',headers=admin).json())
    assert client.get('/api/admin/users',headers=analyst).status_code==403

def test_campaigns_and_deletion():
    a,staff=account(),account('analyst@example.com','analyst')
    ids=[]
    for text in ['Urgent send OTP https://bad.example.com','You won a prize https://bad.example.com']:
        sid=scan(a,text);process_one()
        ids.append(client.post('/api/scans/'+sid+'/report',headers=a,json={'reason':'Check this message'}).json()['id'])
    graph=client.get('/api/campaigns',headers=staff).json()
    assert graph['edges'][0]['reasons'][0]['value']=='bad.example.com'
    cid=client.post('/api/campaigns',headers=staff,json={'name':'Test campaign','reason':'Shared domain reviewed','report_ids':ids}).json()['id']
    assert client.delete('/api/campaigns/'+cid,headers=staff).status_code==200
    assert client.delete('/api/me',headers=a).status_code==200
    assert client.get('/api/scans',headers=a).status_code==401
    assert client.get('/api/reports',headers=staff).json()==[]

def test_url_and_empty_handling():
    a=account()
    for text in ['file:///etc/passwd','javascript:alert(1)','http://','https://bad host.com']:
        assert client.post('/api/scans',headers=a,json={'kind':'url','text':text}).status_code==422
    assert analyze('https://example.com','url')['assessment']=='Inconclusive'
    assert analyze('hello')['assessment']=='Inconclusive'
    assert analyze('Your bank statement is available in the official app.')['assessment']=='Inconclusive'
    assert 'ip_host' in [e['code'] for e in analyze('http://127.0.0.1','url')['evidence']]
    assert client.post('/api/scans',headers=a,json={'text':'  '}).status_code==422

def test_upload_validation_and_manual_ocr_fallback(monkeypatch):
    import pytesseract
    a=account()
    assert client.post('/api/scans/screenshot',headers=a,files={'file':('a.png',b'not an image','image/png')}).status_code==422
    assert client.post('/api/scans/screenshot',headers=a,files={'file':('a.png',b'a'*(5*1024*1024+1),'image/png')}).status_code==413
    data=io.BytesIO();Image.new('RGB',(50,50),'white').save(data,'PNG')
    assert client.post('/api/scans/screenshot',headers=a,files={'file':('a.jpg',data.getvalue(),'image/jpeg')}).status_code==422
    r=client.post('/api/scans/screenshot',headers=a,files={'file':('a.png',data.getvalue(),'image/png')})
    assert r.status_code==202,r.text
    sid=r.json()['id']
    monkeypatch.setattr(pytesseract,'image_to_string',lambda *args,**kwargs:(_ for _ in ()).throw(RuntimeError('unavailable')))
    process_one()
    result=client.get('/api/scans/'+sid,headers=a).json()
    assert result['status']=='partially_completed'
    assert result['result']['assessment']=='Inconclusive'
    assert client.post('/api/scans/'+sid+'/confirm',headers=a,json={'text':'Urgent! Send your OTP immediately'}).status_code==200
    process_one()
    assert client.get('/api/scans/'+sid,headers=a).json()['result']['assessment']=='High'
    assert client.delete('/api/scans/'+sid,headers=a).status_code==200
    assert list((TEST_ROOT/'storage').glob('*.png'))==[]

def test_password_reset_revokes_sessions_and_token_single_use():
    a=account()
    token=client.post('/api/auth/forgot',json={'email':'user@example.com'}).json()['development_token']
    assert client.post('/api/auth/reset',json={'token':token,'password':'new-password-123'}).status_code==200
    assert client.get('/api/me',headers=a).status_code==401
    assert client.post('/api/auth/reset',json={'token':token,'password':'other-password-123'}).status_code==400

def test_recovery_and_rate_limit():
    a=account();sid=scan(a)
    with Session() as db:
        job=db.get(Scan,sid);job.status='processing';job.updated=now()-200;db.commit()
    assert process_one()
    assert client.get('/api/scans/'+sid,headers=a).json()['status']=='completed'
    for _ in range(20):
        client.post('/api/auth/login',json={'email':'missing@example.com','password':'bad-password'})
    assert client.post('/api/auth/login',json={'email':'missing@example.com','password':'bad-password'}).status_code==429

@pytest.mark.parametrize('text',['ikmanin otp eka ewanna salli ewanna','வங்கி ரகசிய எண் உடனே அனுப்பு','වහාම මුරපදය එවන්න'])
def test_language_smoke_patterns(text):
    result=analyze(text)
    assert result['assessment'] in ['Medium','High']
    assert result['evidence']

def test_staff_mfa_and_logout():
    staff=account('analyst@example.com','analyst')
    assert client.post('/api/auth/login',json={'email':'analyst@example.com','password':'correct-password-123'}).status_code==403
    assert client.post('/api/auth/logout',headers=staff).status_code==200
    assert client.get('/api/me',headers=staff).status_code==401

def test_retries_are_bounded_and_never_safe(monkeypatch):
    import backend.app.worker as worker
    a=account();sid=scan(a)
    monkeypatch.setattr(worker,'analyze',lambda *args:(_ for _ in ()).throw(RuntimeError('dependency failed')))
    for _ in range(3):
        assert process_one()
    result=client.get('/api/scans/'+sid,headers=a).json()
    assert result['status']=='failed'
    assert result['result']['assessment']=='Inconclusive'
    assert not process_one()

def test_successful_ocr_requires_confirmation(monkeypatch):
    import pytesseract
    a=account();data=io.BytesIO();Image.new('RGB',(50,50),'white').save(data,'PNG')
    sid=client.post('/api/scans/screenshot',headers=a,files={'file':('a.png',data.getvalue(),'image/png')}).json()['id']
    monkeypatch.setattr(pytesseract,'image_to_string',lambda *args,**kwargs:'Urgent! Send your OTP immediately')
    process_one()
    result=client.get('/api/scans/'+sid,headers=a).json()
    assert result['status']=='awaiting_confirmation'
    assert result['result']['assessment']=='Inconclusive'
    assert 'Urgent' in result['text']

def test_idempotency_conflict_and_expired_session():
    from backend.app.db import LoginSession
    a=account();scan(a,key='same')
    assert client.post('/api/scans',headers={**a,'Idempotency-Key':'same'},json={'text':'Different message'}).status_code==409
    with Session() as db:
        session=db.scalar(select(LoginSession));session.expires=now()-1;db.commit()
    assert client.get('/api/me',headers=a).status_code==401
