import base64
import io
import json
import os
import re
import secrets
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Header, Request, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel, Field
from sqlalchemy import select, delete, func
from sqlalchemy.exc import IntegrityError
from .db import Session, User, LoginSession, ActionToken, Scan, Feedback, Report, Decision, Campaign, Audit, RecoveryCode, now
from .security import uid, digest, password_hash, password_ok, totp_ok, audit, limit, mail_token, recovery_codes, consume_recovery
from .detection import VERSION, url_observations
from .worker import STORAGE

app = FastAPI(title='ScamShield AI', version='1.0.0')
from .observability import request_log, ready, snapshot
app.middleware('http')(request_log)

def database():
    with Session() as db:
        yield db

def current(authorization: str = Header(default=''), db=Depends(database)):
    token = authorization.removeprefix('Bearer ')
    session = db.get(LoginSession, digest(token))
    if not session or session.expires <= now():
        raise HTTPException(401, 'Please sign in again')
    user = db.get(User, session.user_id)
    if not user:
        raise HTTPException(401)
    return user

def staff(user=Depends(current)):
    if user.role not in ['analyst', 'admin']:
        raise HTTPException(403, 'Analyst access required')
    return user

def admin(user=Depends(current)):
    if user.role != 'admin':
        raise HTTPException(403, 'Admin access required')
    return user

def owned(db, scan_id, user):
    scan = db.get(Scan, scan_id)
    if not scan or scan.owner_id != user.id:
        raise HTTPException(404, 'Scan not found')
    return scan

def serialize(scan, db):
    report = db.scalar(select(Report).where(Report.scan_id == scan.id))
    decisions = db.scalars(select(Decision).where(Decision.report_id == report.id).order_by(Decision.created.desc())).all() if report else []
    return dict(id=scan.id, kind=scan.kind, text=scan.text, status=scan.status, created=scan.created, result=json.loads(scan.result), report_id=report.id if report else None,
                reviews=[dict(verdict=d.verdict, reason=d.reason, created=d.created) for d in decisions])

class Credentials(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=10, max_length=128)
    otp: str = Field(default='', max_length=6)
    recovery_code: str = Field(default='', max_length=40)

def email_address(value):
    value = value.strip().lower()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
        raise HTTPException(422, 'Enter a valid email address')
    return value

@app.get('/api/health')
def health(db=Depends(database)):
    db.execute(select(1))
    return {'status': 'ok', 'version': VERSION}

@app.get('/api/ready')
def readiness(db=Depends(database)):
    if not ready(db):
        raise HTTPException(503, 'No recent worker heartbeat')
    return {'status':'ready'}

@app.get('/api/admin/metrics')
def metrics(user=Depends(admin), db=Depends(database)):
    return snapshot(db)

@app.post('/api/auth/register', status_code=201)
def register(body: Credentials, request: Request, db=Depends(database)):
    limit(db, 'register:'+request.client.host, 10, 3600)
    email = email_address(body.email)
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, 'Account already exists')
    user = User(id=uid(), email=email, password=password_hash(body.password))
    db.add(user)
    db.commit()
    return mail_token(db, user, 'verify')

@app.post('/api/auth/login')
def login(body: Credentials, request: Request, db=Depends(database)):
    limit(db, 'login:'+request.client.host, 20, 900)
    user = db.scalar(select(User).where(User.email == body.email.strip().lower()))
    if not user or not password_ok(body.password, user.password):
        raise HTTPException(401, 'Invalid credentials')
    if not user.verified:
        raise HTTPException(403, 'Verify your email first')
    if user.mfa_secret:
        if body.recovery_code:
            if not consume_recovery(db, user, body.recovery_code):
                raise HTTPException(403, 'Invalid recovery code')
        elif not totp_ok(user.mfa_secret, body.otp):
            raise HTTPException(403, 'A valid authenticator or recovery code is required')
    elif user.role in ['admin', 'analyst']:
        raise HTTPException(403, 'Staff MFA enrollment is required')
    token = secrets.token_urlsafe(32)
    db.add(LoginSession(token=digest(token), user_id=user.id, expires=now()+86400))
    audit(db, user.id, 'login', user.id)
    db.commit()
    return {'token': token, 'expires_in': 86400, 'user': {'id': user.id, 'email': user.email, 'role': user.role}}

class TokenBody(BaseModel):
    token: str = Field(max_length=200)
    password: str = Field(default='', max_length=128)

def consume(db, body, purpose):
    action = db.get(ActionToken, digest(body.token))
    if not action or action.purpose != purpose or action.expires < now():
        raise HTTPException(400, 'Invalid or expired token')
    user = db.get(User, action.user_id)
    deleted = db.execute(delete(ActionToken).where(ActionToken.token==action.token, ActionToken.expires >= now()))
    if not deleted.rowcount:
        raise HTTPException(400, 'Invalid or expired token')
    return user

@app.post('/api/auth/verify')
def verify(body: TokenBody, db=Depends(database)):
    user = consume(db, body, 'verify')
    user.verified = 1
    db.commit()
    return {'message': 'Email verified. You can sign in.'}

class EmailBody(BaseModel):
    email: str = Field(max_length=254)

@app.post('/api/auth/resend')
def resend(body: EmailBody, request: Request, db=Depends(database)):
    response = {'message':'If the account is eligible, an email has been sent.'}
    # Identical cooldown/limit handling for known, verified and unknown addresses.
    key = digest(body.email.strip().lower())
    try:
        limit(db, 'resend-ip:'+request.client.host, 10, 3600)
        limit(db, 'resend-email:'+key, 1, 60)
    except HTTPException:
        return response
    user = db.scalar(select(User).where(User.email==body.email.strip().lower(), User.verified==0))
    if user:
        return mail_token(db, user, 'verify')
    return response

@app.post('/api/auth/forgot')
def forgot(body: EmailBody, request: Request, db=Depends(database)):
    limit(db, 'forgot:'+request.client.host, 5, 3600)
    user = db.scalar(select(User).where(User.email == body.email.strip().lower()))
    return mail_token(db, user, 'reset') if user else {'message': 'If the account is eligible, an email has been sent.'}

@app.post('/api/auth/reset')
def reset(body: TokenBody, db=Depends(database)):
    if len(body.password) < 10:
        raise HTTPException(422, 'Password must be at least 10 characters')
    user = consume(db, body, 'reset')
    user.password = password_hash(body.password)
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    db.commit()
    return {'message': 'Password reset; all sessions revoked'}

@app.get('/api/me')
def me(user=Depends(current)):
    return {'id': user.id, 'email': user.email, 'role': user.role, 'mfa_enabled': bool(user.mfa_secret)}

@app.post('/api/auth/logout')
def logout(authorization: str = Header(default=''), user=Depends(current), db=Depends(database)):
    db.execute(delete(LoginSession).where(LoginSession.token == digest(authorization.removeprefix('Bearer '))))
    db.commit()
    return {'message': 'Signed out'}

class MFASetup(BaseModel):
    secret: str = Field(pattern=r'^[A-Z2-7]{32}$')
    otp: str = Field(pattern=r'^\d{6}$')

@app.post('/api/auth/mfa')
def mfa(body: MFASetup, user=Depends(current), db=Depends(database)):
    if user.mfa_secret:
        raise HTTPException(409, 'MFA already enrolled')
    if not totp_ok(body.secret, body.otp):
        raise HTTPException(400, 'Invalid authenticator code')
    user.mfa_secret = body.secret
    codes = recovery_codes(db, user)
    audit(db, user.id, 'mfa.enroll', user.id)
    db.commit()
    return {'message': 'Authenticator enrolled. Save your recovery codes securely.', 'recovery_codes':codes}

class RecoveryBody(BaseModel):
    password: str = Field(min_length=10, max_length=128)
    otp: str = Field(default='', max_length=6)
    recovery_code: str = Field(default='', max_length=40)

@app.post('/api/auth/mfa/recovery-codes')
def regenerate_codes(body: RecoveryBody, user=Depends(current), db=Depends(database)):
    limit(db, 'mfa-reauth:'+user.id, 5, 900)
    if not user.mfa_secret or not password_ok(body.password, user.password):
        raise HTTPException(403, 'Reauthentication failed')
    # Serialize regeneration for one account on PostgreSQL.
    db.scalar(select(User).where(User.id==user.id).with_for_update())
    valid = consume_recovery(db, user, body.recovery_code) if body.recovery_code else totp_ok(user.mfa_secret, body.otp)
    if not valid:
        raise HTTPException(403, 'Reauthentication failed')
    codes = recovery_codes(db, user)
    db.execute(delete(LoginSession).where(LoginSession.user_id==user.id))
    audit(db, user.id, 'mfa.recovery_codes.regenerate', user.id)
    db.commit()
    return {'recovery_codes':codes, 'message':'Save these codes. All sessions were revoked; sign in again.'}

class ScanBody(BaseModel):
    kind: Literal['text', 'url'] = 'text'
    text: str = Field(min_length=1, max_length=20000)

def create_scan(db, user, kind, text, key=None, attachment=''):
    if key:
        if len(key) > 100:
            raise HTTPException(422, 'Idempotency key too long')
        previous = db.scalar(select(Scan).where(Scan.owner_id == user.id, Scan.request_key == key))
        if previous:
            if previous.kind != kind or previous.text != text:
                raise HTTPException(409, 'Idempotency key already used for different input')
            return previous
    limit(db, 'scan:'+user.id, 100, 86400)
    scan = Scan(id=uid(), owner_id=user.id, kind=kind, text=text, request_key=key, attachment=attachment)
    db.add(scan)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if key:
            previous = db.scalar(select(Scan).where(Scan.owner_id==user.id, Scan.request_key==key))
            if previous and previous.kind==kind and previous.text==text:
                return previous
        raise HTTPException(409, 'Duplicate request; retrieve scan history')
    return scan

@app.post('/api/scans', status_code=202)
def new_scan(body: ScanBody, user=Depends(current), db=Depends(database), idempotency_key: str | None = Header(default=None)):
    if not body.text.strip():
        raise HTTPException(422, 'Enter some text')
    if body.kind == 'url' and not url_observations(body.text)[0]:
        raise HTTPException(422, 'Enter a complete HTTP or HTTPS URL')
    return serialize(create_scan(db, user, body.kind, body.text, idempotency_key), db)

@app.post('/api/scans/screenshot', status_code=202)
async def screenshot(file: UploadFile = File(...), user=Depends(current), db=Depends(database)):
    limit(db, 'upload:'+user.id, 30, 86400)
    data = await file.read(5*1024*1024+1)
    if len(data) > 5*1024*1024:
        raise HTTPException(413, 'Image exceeds 5 MB')
    suffix = Path(file.filename or '').suffix.lower()
    if suffix not in ['.png', '.jpg', '.jpeg'] or file.content_type not in ['image/png', 'image/jpeg']:
        raise HTTPException(415, 'Upload a PNG or JPEG screenshot')
    try:
        with Image.open(io.BytesIO(data)) as image:
            expected = 'PNG' if suffix == '.png' else 'JPEG'
            if image.format != expected or image.width*image.height > 16000000 or min(image.size) < 20:
                raise ValueError()
            image.verify()
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            STORAGE.mkdir(parents=True, exist_ok=True, mode=0o700)
            name = uid()+'.png'
            ImageOps.exif_transpose(image).convert('RGB').save(STORAGE/name, 'PNG')
            os.chmod(STORAGE/name, 0o600)
    except (UnidentifiedImageError, ValueError, OSError, Image.DecompressionBombError):
        raise HTTPException(422, 'Invalid image or unsupported dimensions')
    try:
        scan = create_scan(db, user, 'screenshot', '', attachment=name)
    except Exception:
        (STORAGE/name).unlink(missing_ok=True)
        raise
    return serialize(scan, db)

@app.post('/api/scans/{scan_id}/confirm')
def confirm(scan_id: str, body: ScanBody, user=Depends(current), db=Depends(database)):
    scan = owned(db, scan_id, user)
    if scan.kind != 'screenshot' or scan.status not in ['awaiting_confirmation', 'partially_completed']:
        raise HTTPException(409, 'Scan is not waiting for OCR correction')
    if not body.text.strip():
        raise HTTPException(422, 'Text is required')
    scan.text, scan.status, scan.attempts = body.text, 'queued', 0
    db.commit()
    return serialize(scan, db)

@app.get('/api/scans')
def history(user=Depends(current), db=Depends(database), offset: int = 0):
    return [serialize(s, db) for s in db.scalars(select(Scan).where(Scan.owner_id == user.id).order_by(Scan.created.desc()).offset(max(0, offset)).limit(100)).all()]

@app.get('/api/scans/{scan_id}')
def get_scan(scan_id: str, user=Depends(current), db=Depends(database)):
    return serialize(owned(db, scan_id, user), db)

def remove_scan(db, scan):
    reports = db.scalars(select(Report).where(Report.scan_id == scan.id)).all()
    for report in reports:
        for campaign in db.scalars(select(Campaign)).all():
            ids = json.loads(campaign.report_ids)
            if report.id in ids:
                campaign.report_ids = json.dumps([i for i in ids if i != report.id])
        db.execute(delete(Decision).where(Decision.report_id == report.id))
        db.delete(report)
    db.execute(delete(Feedback).where(Feedback.scan_id == scan.id))
    if scan.attachment:
        (STORAGE/scan.attachment).unlink(missing_ok=True)
    db.delete(scan)

@app.delete('/api/scans/{scan_id}')
def delete_scan(scan_id: str, user=Depends(current), db=Depends(database)):
    scan = owned(db, scan_id, user)
    remove_scan(db, scan)
    audit(db, user.id, 'scan.delete', scan_id)
    db.commit()
    return {'message': 'Scan deleted'}

@app.delete('/api/me')
def delete_account(user=Depends(current), db=Depends(database)):
    for scan in db.scalars(select(Scan).where(Scan.owner_id == user.id)).all():
        remove_scan(db, scan)
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    db.execute(delete(ActionToken).where(ActionToken.user_id == user.id))
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    audit(db, 'deleted-account', 'account.delete', user.id)
    db.delete(user)
    db.commit()
    return {'message': 'Account and scans deleted'}

class Comment(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)

@app.post('/api/scans/{scan_id}/feedback', status_code=201)
def feedback(scan_id: str, body: Comment, user=Depends(current), db=Depends(database)):
    owned(db, scan_id, user)
    limit(db, 'feedback:'+user.id, 50, 86400)
    db.add(Feedback(id=uid(), scan_id=scan_id, owner_id=user.id, comment=body.reason))
    db.commit()
    return {'message': 'Feedback saved; it is not automatically used as a training label'}

@app.post('/api/scans/{scan_id}/report', status_code=201)
def report(scan_id: str, body: Comment, user=Depends(current), db=Depends(database)):
    scan = owned(db, scan_id, user)
    if scan.status != 'completed':
        raise HTTPException(409, 'Wait for analysis to complete')
    existing = db.scalar(select(Report).where(Report.scan_id == scan_id))
    if existing:
        return {'id': existing.id}
    report = Report(id=uid(), scan_id=scan_id, reason=body.reason)
    db.add(report)
    audit(db, user.id, 'report.create', report.id)
    db.commit()
    return {'id': report.id}

@app.get('/api/reports')
def reports(user=Depends(staff), db=Depends(database)):
    rows = db.scalars(select(Report).order_by(Report.created.desc()).limit(500)).all()
    return [dict(id=r.id, reason=r.reason, status=r.status, created=r.created, scan=serialize(db.get(Scan, r.scan_id), db)) for r in rows]

class Review(Comment):
    verdict: Literal['Confirmed scam', 'Legitimate', 'Uncertain']

@app.post('/api/reports/{report_id}/decision')
def review(report_id: str, body: Review, user=Depends(staff), db=Depends(database)):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(404)
    db.add(Decision(id=uid(), report_id=report_id, analyst_id=user.id, verdict=body.verdict, reason=body.reason))
    report.status = 'reviewed'
    audit(db, user.id, 'report.review', report_id)
    db.commit()
    return {'message': 'Review recorded separately from model assessment'}

@app.get('/api/campaigns')
def campaigns(user=Depends(staff), db=Depends(database)):
    reports = db.scalars(select(Report).limit(500)).all()
    nodes, edges = [], []
    for r in reports:
        scan = db.get(Scan, r.scan_id)
        entities = json.loads(scan.result).get('entities', [])
        nodes.append(dict(id=r.id, label=scan.text[:55], entities=entities, created=r.created))
    for i, a in enumerate(nodes):
        for b in nodes[i+1:]:
            common = [e for e in a['entities'] if e in b['entities']]
            if common:
                edges.append(dict(source=a['id'], target=b['id'], reasons=common, attribution='Candidate relationship; shared entities do not establish a shared attacker'))
    saved = [dict(id=c.id, name=c.name, report_ids=json.loads(c.report_ids), reason=c.reason) for c in db.scalars(select(Campaign)).all()]
    return {'nodes': nodes, 'edges': edges, 'campaigns': saved}

class CampaignBody(Comment):
    name: str = Field(min_length=3, max_length=120)
    report_ids: list[str] = Field(min_length=2, max_length=100)

@app.post('/api/campaigns')
def save_campaign(body: CampaignBody, user=Depends(staff), db=Depends(database)):
    ids = list(set(body.report_ids))
    if len(ids) < 2 or any(not db.get(Report, i) for i in ids):
        raise HTTPException(422, 'Select at least two existing reports')
    campaign = Campaign(id=uid(), name=body.name, report_ids=json.dumps(ids), reason=body.reason)
    db.add(campaign)
    audit(db, user.id, 'campaign.create', campaign.id)
    db.commit()
    return {'id': campaign.id}

@app.delete('/api/campaigns/{campaign_id}')
def split_campaign(campaign_id: str, user=Depends(staff), db=Depends(database)):
    campaign = db.get(Campaign, campaign_id)
    if not campaign:
        raise HTTPException(404)
    db.delete(campaign)
    audit(db, user.id, 'campaign.dissolve', campaign_id)
    db.commit()
    return {'message': 'Grouping dissolved; reports preserved'}

@app.get('/api/admin/users')
def users(user=Depends(admin), db=Depends(database)):
    return [dict(id=u.id, email=u.email, role=u.role, mfa_enabled=bool(u.mfa_secret)) for u in db.scalars(select(User)).all()]

class RoleBody(BaseModel):
    role: Literal['user', 'analyst', 'admin']

@app.put('/api/admin/users/{user_id}/role')
def role(user_id: str, body: RoleBody, actor=Depends(admin), db=Depends(database)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404)
    if user.id == actor.id:
        raise HTTPException(409, 'Cannot change your own role')
    if body.role != 'user' and not user.mfa_secret:
        raise HTTPException(409, 'User must enroll MFA before staff promotion')
    user.role = body.role
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    audit(db, actor.id, 'role.'+body.role, user.id)
    db.commit()
    return {'message': 'Role updated; sessions revoked'}

@app.get('/api/admin/audit')
def audits(user=Depends(admin), db=Depends(database)):
    return [dict(id=a.id, actor=a.actor, action=a.action, target=a.target, created=a.created) for a in db.scalars(select(Audit).order_by(Audit.created.desc()).limit(500)).all()]

@app.get('/api/model')
def model(user=Depends(current)):
    from .model_inference import model_status
    return {'version': VERSION, 'type': 'Versioned rules with optional benchmark models', 'metrics': None, 'languages': ['English', 'Sinhala', 'Tamil', 'Singlish'], 'evaluation_status': 'Not validated on representative deployment data. Local-language rules remain experimental; English-dominant SMS and static URL benchmark reports are separate.', 'models':model_status(), 'live_url_checks': False}

DASHBOARD = Path(__file__).resolve().parents[2]/'apps'/'dashboard'
if DASHBOARD.exists():
    app.mount('/', StaticFiles(directory=DASHBOARD, html=True), name='dashboard')
