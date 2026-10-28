import base64
import hashlib
import hmac
import os
import secrets
import smtplib
import struct
from email.message import EmailMessage
from fastapi import HTTPException
from sqlalchemy import delete, case
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from .db import ActionToken, Audit, RateBucket, RecoveryCode, LoginSession, now

def uid():
    return secrets.token_hex(16)

def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()

def password_hash(password):
    salt = secrets.token_hex(16)
    value = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()
    return salt + ':' + value

def password_ok(password, encoded):
    salt, expected = encoded.split(':')
    actual = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()
    return hmac.compare_digest(actual, expected)

def totp_ok(secret, code):
    if not secret or len(code) != 6:
        return False
    key = base64.b32decode(secret)
    for drift in [-1, 0, 1]:
        block = hmac.new(key, struct.pack('>Q', int(now() // 30) + drift), hashlib.sha1).digest()
        offset = block[-1] & 15
        value = (struct.unpack('>I', block[offset:offset+4])[0] & 0x7fffffff) % 1000000
        if hmac.compare_digest(f'{value:06d}', code):
            return True
    return False

def audit(db, actor, action, target):
    db.add(Audit(id=uid(), actor=actor, action=action, target=target))

def limit(db, key, maximum, seconds):
    insert = postgres_insert if db.bind.dialect.name == 'postgresql' else sqlite_insert
    timestamp = now()
    statement = insert(RateBucket).values(key=key, count=1, expires=timestamp+seconds)
    result = db.execute(statement.on_conflict_do_update(index_elements=['key'], set_={
        'count': case((RateBucket.expires <= timestamp, 1), else_=RateBucket.count+1),
        'expires': case((RateBucket.expires <= timestamp, timestamp+seconds), else_=RateBucket.expires)
    }, where=(RateBucket.expires <= timestamp) | (RateBucket.count < maximum)).returning(RateBucket.count)).scalar_one_or_none()
    db.commit()
    if result is None:
        raise HTTPException(429, 'Rate limit exceeded. Try again later.')

def recovery_codes(db, user):
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = [secrets.token_hex(10) for _ in range(8)]
    db.add_all([RecoveryCode(token=digest(code), user_id=user.id) for code in codes])
    return codes

def consume_recovery(db, user, code):
    result = db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id, RecoveryCode.token == digest(code.strip())))
    if not result.rowcount:
        return False
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    audit(db, user.id, 'mfa.recovery', user.id)
    return True

def mail_token(db, user, purpose):
    token = secrets.token_urlsafe(32)
    db.execute(delete(ActionToken).where(ActionToken.user_id == user.id, ActionToken.purpose == purpose))
    db.add(ActionToken(token=digest(token), user_id=user.id, purpose=purpose, expires=now()+1800))
    db.commit()
    host = os.getenv('SMTP_HOST')
    if host:
        message = EmailMessage()
        message['From'] = os.getenv('SMTP_FROM', 'scamshield@localhost')
        message['To'] = user.email
        message['Subject'] = f'ScamShield {purpose}'
        message.set_content(f'Your {purpose} token (expires in 30 minutes):\n{token}')
        try:
            with smtplib.SMTP(host, int(os.getenv('SMTP_PORT', '1025')), timeout=10) as smtp:
                if os.getenv('SMTP_TLS') == '1':
                    smtp.starttls()
                if os.getenv('SMTP_USER'):
                    smtp.login(os.environ['SMTP_USER'], os.environ['SMTP_PASSWORD'])
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException):
            from .observability import event, count
            event('email_delivery_failed')
            count('email_delivery_failures')
    # Tokens are exposed only when explicitly enabled for local development.
    return {'message': 'If the account is eligible, an email has been sent.', **({'development_token': token} if os.getenv('DEV_EMAIL_TOKENS') == '1' else {})}
