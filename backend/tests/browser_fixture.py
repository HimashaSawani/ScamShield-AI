"""Controlled OCR/server fixture. Never used by deployment entrypoints."""
import os
if os.getenv('SCAMSHIELD_BROWSER_FIXTURE')!='1' or not os.environ.get('DATABASE_URL','').endswith('browser-test.db'):
    raise RuntimeError('Browser fixtures require an explicit isolated test database')
import threading
import time
import pytesseract
from backend.app.main import app
from backend.app.db import Session, User
from backend.app.security import password_hash
from backend.app.worker import process_one, heartbeat

def ocr(image, **kwargs):
    if image.getpixel((0,0)) < 100:
        raise RuntimeError('Controlled OCR failure')
    return 'Urgent! Send your OTP immediately. Claim your prize https://fixture.example.test'
pytesseract.image_to_string=ocr
with Session() as db:
    if not db.get(User,'browser-admin'):
        db.add(User(id='browser-admin',email='admin@fixture.test',password=password_hash('BrowserPassword123!'),verified=1,role='admin',mfa_secret='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'))
        db.commit()

def work():
    while True:
        heartbeat()
        process_one()
        time.sleep(.1)
threading.Thread(target=work,daemon=True).start()
