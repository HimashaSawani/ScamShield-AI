import io
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from fastapi import HTTPException
from sqlalchemy import select, func
from backend.tests.test_system import client, account, scan, clean
from backend.app.db import Session, Scan, User, ActionToken, LoginSession, RecoveryCode, now
from backend.app.security import limit, digest, recovery_codes
from backend.app.worker import process_one, heartbeat, retain

def test_resend_generic_cooldown_and_replaced_token():
    original=client.post('/api/auth/register',json={'email':'pending@example.com','password':'correct-password-123'}).json()['development_token']
    known=client.post('/api/auth/resend',json={'email':'pending@example.com'}).json()
    unknown=client.post('/api/auth/resend',json={'email':'absent@example.com'}).json()
    assert known['message']==unknown['message']
    assert client.post('/api/auth/resend',json={'email':'pending@example.com'}).json()==unknown
    assert client.post('/api/auth/verify',json={'token':original}).status_code==400
    assert client.post('/api/auth/verify',json={'token':known['development_token']}).status_code==200
    assert client.post('/api/auth/verify',json={'token':known['development_token']}).status_code==400

def test_recovery_codes_single_use_regeneration_and_revocation():
    staff=account('staff@example.com','analyst')
    with Session() as db:
        user=db.scalar(select(User).where(User.email=='staff@example.com'))
        codes=recovery_codes(db,user);db.commit()
        assert not db.get(RecoveryCode,codes[0])
        assert db.get(RecoveryCode,digest(codes[0]))
    creds={'email':'staff@example.com','password':'correct-password-123','recovery_code':codes[0]}
    response=client.post('/api/auth/login',json=creds)
    assert response.status_code==200
    assert client.get('/api/me',headers=staff).status_code==401
    assert client.post('/api/auth/login',json=creds).status_code==403
    headers={'Authorization':'Bearer '+response.json()['token']}
    assert client.post('/api/auth/mfa/recovery-codes',headers=headers,json={'password':'wrong-password','recovery_code':codes[1]}).status_code==403
    regenerated=client.post('/api/auth/mfa/recovery-codes',headers=headers,json={'password':'correct-password-123','recovery_code':codes[1]})
    assert regenerated.status_code==200
    assert len(regenerated.json()['recovery_codes'])==8
    assert client.get('/api/me',headers=headers).status_code==401
    assert client.post('/api/auth/login',json={**creds,'recovery_code':codes[2]}).status_code==403
    assert client.post('/api/auth/login',json={**creds,'recovery_code':regenerated.json()['recovery_codes'][0]}).status_code==200

def test_atomic_quota_under_concurrency():
    def attempt(_):
        with Session() as db:
            try:
                limit(db,'concurrent',5,60)
                return True
            except HTTPException as error:
                assert error.status_code==429
                return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt,range(24)))==5

def test_two_workers_claim_once_and_fence_stale_result(monkeypatch):
    import backend.app.worker as worker
    a=account();sid=scan(a)
    entered=threading.Event();release=threading.Event();calls=[]
    original=worker.analyze
    def slow(text,kind):
        calls.append(text);entered.set();assert release.wait(10)
        return original(text,kind)
    monkeypatch.setattr(worker,'analyze',slow)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first=pool.submit(process_one)
        assert entered.wait(5)
        second=pool.submit(process_one)
        assert second.result(timeout=5) is False
        release.set();assert first.result(timeout=5)
    assert len(calls)==1
    # A stale owner's result must not overwrite another lease.
    sid=scan(a,'Another sufficiently long message')
    def superseded(text,kind):
        with Session() as db:
            job=db.get(Scan,sid);job.lease='new-owner';db.commit()
        return original(text,kind)
    monkeypatch.setattr(worker,'analyze',superseded)
    process_one()
    with Session() as db:
        job=db.get(Scan,sid)
        assert job.status=='processing' and job.lease=='new-owner'

def test_crash_recovery_exhaustion_and_readiness():
    a=account();sid=scan(a)
    assert client.get('/api/ready').status_code==503
    heartbeat();assert client.get('/api/ready').status_code==200
    with Session() as db:
        job=db.get(Scan,sid);job.status='processing';job.attempts=3;job.updated=now()-200;db.commit()
    assert not process_one()
    data=client.get('/api/scans/'+sid,headers=a).json()
    assert data['status']=='failed' and data['result']['assessment']=='Inconclusive'

def test_concurrent_scan_idempotency():
    a=account()
    def submit(_):
        return client.post('/api/scans',headers={**a,'Idempotency-Key':'parallel'},json={'text':'A concurrent example message'})
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses=list(pool.map(submit,range(8)))
    assert all(r.status_code==202 for r in responses)
    assert len({r.json()['id'] for r in responses})==1

def test_metrics_auth_log_redaction_and_retention(caplog):
    a=account();sid=scan(a,'Sensitive private message secret-sample-789')
    process_one()
    assert client.get('/api/admin/metrics',headers=a).status_code==403
    admin=account('admin@example.com','admin')
    metrics=client.get('/api/admin/metrics',headers=admin).json()
    assert metrics['counters']['processing_duration_ms']['count']>=1
    logs=caplog.text
    for sensitive in ['secret-sample-789','correct-password-123',a['Authorization'],'admin@example.com']:
        assert sensitive not in logs
    with Session() as db:
        job=db.get(Scan,sid);job.created=now()-91*86400;db.commit()
    retain()
    assert client.get('/api/scans/'+sid,headers=a).status_code==404

def test_unhandled_errors_do_not_log_private_exception_data(monkeypatch,caplog):
    import backend.app.main as main
    a=account();sid=scan(a)
    def fail(*args):
        raise RuntimeError('sensitive-input-do-not-log-123')
    monkeypatch.setattr(main,'serialize',fail)
    result=client.get('/api/scans/'+sid,headers=a)
    assert result.status_code==500
    assert result.headers['x-request-id']==result.json()['request_id']
    assert 'sensitive-input-do-not-log-123' not in caplog.text
    assert 'sensitive-input-do-not-log-123' not in result.text
