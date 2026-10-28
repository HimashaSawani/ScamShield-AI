"""Durable database queue: conditional claims, bounded retries and stale lease recovery."""
import io
import json
import os
import time
import threading
import secrets
from pathlib import Path
from PIL import Image, ImageOps
from sqlalchemy import select, update
from .db import Session, Scan, WorkerHeartbeat, now
from .detection import analyze
from .model_inference import enrich
from .observability import event, count

STORAGE = Path(os.getenv('STORAGE_PATH', './storage'))

WORKER_ID = secrets.token_hex(16)

def heartbeat():
    with Session() as db:
        db.merge(WorkerHeartbeat(id=WORKER_ID, updated=now()))
        db.commit()

def renew(scan_id, lease, stop):
    while not stop.wait(20):
        try:
            with Session() as db:
                changed = db.execute(update(Scan).where(Scan.id==scan_id, Scan.lease==lease, Scan.status=='processing').values(updated=now()))
                db.commit()
                if not changed.rowcount:
                    return
            heartbeat()
        except Exception:
            event('lease_renewal_failed', scan_id=scan_id, job_id=lease)

def process_one():
    with Session() as db:
        exhausted = db.execute(update(Scan).where(Scan.status == 'processing', Scan.updated < now()-180, Scan.attempts >= 3).values(status='failed', lease='', result=json.dumps({'assessment':'Inconclusive','error':'Worker recovery attempts exhausted.'}))).rowcount
        db.execute(update(Scan).where(Scan.status == 'processing', Scan.updated < now()-180, Scan.attempts < 3).values(status='queued', lease=''))
        db.commit()
        for _ in range(exhausted):
            count('retry_exhaustion')
        job = db.scalar(select(Scan).where(Scan.status == 'queued').order_by(Scan.created).limit(1))
        if not job:
            return False
        lease = secrets.token_hex(16)
        claimed = db.execute(update(Scan).where(Scan.id == job.id, Scan.status == 'queued', Scan.attempts < 3).values(status='processing', lease=lease, updated=now(), attempts=Scan.attempts+1))
        db.commit()
        if not claimed.rowcount:
            return True
        db.refresh(job)
        attempt = job.attempts
        # Detach the working copy: only a fenced update may persist the result.
        db.expunge(job)
        stop = threading.Event()
        pulse = threading.Thread(target=renew, args=(job.id, lease, stop), daemon=True)
        pulse.start()
        start = time.perf_counter()
        event('job_started', scan_id=job.id, job_id=lease, attempt=attempt)
        try:
            if job.kind == 'screenshot' and not job.text:
                import pytesseract
                tess_cmd = os.getenv('TESSERACT_CMD')
                if not tess_cmd:
                    local_bin = Path(__file__).resolve().parents[2] / 'tools' / 'tesseract' / 'bin' / 'tesseract.exe'
                    if local_bin.is_file():
                        tess_cmd = str(local_bin)
                if tess_cmd and Path(tess_cmd).is_file():
                    pytesseract.pytesseract.tesseract_cmd = tess_cmd
                    local_tessdata = Path(tess_cmd).parents[1] / 'tessdata'
                    if local_tessdata.is_dir() and 'TESSDATA_PREFIX' not in os.environ:
                        os.environ['TESSDATA_PREFIX'] = str(local_tessdata)
                try:
                    with Image.open(STORAGE / job.attachment) as image:
                        image = ImageOps.grayscale(ImageOps.exif_transpose(image))
                        job.text = pytesseract.image_to_string(image, lang=os.getenv('OCR_LANGUAGES', 'eng+sin+tam'), timeout=45).strip()
                except Exception:
                    count('ocr_failures')
                    job.result = json.dumps({'assessment': 'Inconclusive', 'error': 'OCR unavailable. Enter the message text to continue.', 'coverage': {'completed': [], 'unavailable': ['OCR', 'Text analysis']}})
                    job.status = 'partially_completed'
                else:
                    job.status = 'awaiting_confirmation'
                    job.result = json.dumps({'assessment': 'Inconclusive', 'ocr_text': job.text, 'message': 'Review and correct extracted text before analysis.'})
            else:
                result = enrich(analyze(job.text, job.kind), job.text, job.kind)
                job.normalized = result.pop('normalized')
                result['analyzed_at'] = now()
                job.result = json.dumps(result, ensure_ascii=False)
                job.status = 'completed'
        except Exception:
            job.status = 'queued' if attempt < 3 else 'failed'
            job.result = json.dumps({'assessment': 'Inconclusive', 'error': 'Analysis failed. Please retry or contact support.'})
        finally:
            stop.set()
            pulse.join(timeout=3)
        changed = db.execute(update(Scan).where(Scan.id==job.id, Scan.status=='processing', Scan.lease==lease).values(text=job.text, normalized=job.normalized, result=job.result, status=job.status, updated=now(), lease=''))
        db.commit()
        elapsed = (time.perf_counter()-start)*1000
        if changed.rowcount:
            count('processing_duration_ms', elapsed)
            if job.status=='failed':
                count('retry_exhaustion')
            if job.status in ['failed','queued']:
                count('processing_failures')
        event('job_finished', scan_id=job.id, job_id=lease, status=job.status if changed.rowcount else 'lease_lost', duration_ms=round(elapsed,2), attempt=attempt)
    return True

def retain():
    from .main import remove_scan
    with Session() as db:
        for scan in db.scalars(select(Scan).where(Scan.status != 'processing', Scan.created < now()-int(os.getenv('RETENTION_DAYS', '90'))*86400)).all():
            remove_scan(db, scan)
        db.commit()

if __name__ == '__main__':
    last_cleanup = 0
    while True:
        heartbeat()
        if time.time()-last_cleanup > 3600:
            retain()
            last_cleanup = time.time()
        if not process_one():
            time.sleep(1)
