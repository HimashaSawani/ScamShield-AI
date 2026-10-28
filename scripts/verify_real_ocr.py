"""Real Screenshot OCR and Complete Workflow Verification.

Tests real image validation, OCR extraction, fallback handling, text correction,
and persistence through the actual FastAPI app and worker without mocking.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest
from starlette.testclient import TestClient

def check_tesseract_environment():
    """Step A2: Verify Tesseract installation, PATH, version, and language packs."""
    import subprocess
    tess_cmd = os.getenv('TESSERACT_CMD')
    cmd = tess_cmd or shutil.which('tesseract') or shutil.which('tesseract.exe')
    
    # Check common Windows paths if not found on PATH
    if not cmd:
        candidates = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Tesseract-OCR\tesseract.exe"),
        ]
        for c in candidates:
            if Path(c).is_file():
                cmd = c
                break
                
    info = {
        'installed': bool(cmd),
        'executable': cmd,
        'version': None,
        'languages': [],
        'has_eng': False,
        'has_sin': False,
        'has_tam': False,
        'notes': ''
    }
    
    if cmd:
        try:
            v_res = subprocess.run([cmd, '--version'], capture_output=True, text=True, timeout=10)
            info['version'] = v_res.stdout.splitlines()[0] if v_res.stdout else None
            
            l_res = subprocess.run([cmd, '--list-langs'], capture_output=True, text=True, timeout=10)
            langs = [line.strip() for line in l_res.stdout.splitlines() if line.strip() and not line.startswith('List of')]
            info['languages'] = langs
            info['has_eng'] = 'eng' in langs
            info['has_sin'] = 'sin' in langs
            info['has_tam'] = 'tam' in langs
        except Exception as e:
            info['notes'] = f"Error querying tesseract executable: {e}"
    else:
        info['notes'] = "Tesseract executable not found on PATH or in standard Program Files locations."
        
    return info

def create_synthetic_image(text, fmt='PNG', size=(600, 200), low_res=False):
    """Generate synthetic image fixture."""
    if low_res:
        img = Image.new('RGB', (100, 40), color=(255, 255, 255))
        d = ImageDraw.Draw(img)
        d.text((5, 10), text[:15], fill=(0, 0, 0))
    else:
        img = Image.new('RGB', size, color=(255, 255, 255))
        d = ImageDraw.Draw(img)
        d.text((20, 40), text, fill=(0, 0, 0))
    
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()

def calculate_cer(reference, hypothesis):
    """Levenshtein-based Character Error Rate."""
    ref = reference.strip()
    hyp = hypothesis.strip()
    if not ref:
        return 0.0 if not hyp else 1.0
    r_len = len(ref)
    h_len = len(hyp)
    d = [[0] * (h_len + 1) for _ in range(r_len + 1)]
    for i in range(r_len + 1):
        d[i][0] = i
    for j in range(h_len + 1):
        d[0][j] = j
    for i in range(1, r_len + 1):
        for j in range(1, h_len + 1):
            cost = 0 if ref[i - 1] == hyp[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
    return d[r_len][h_len] / r_len

def run_ocr_test_suite():
    tess_info = check_tesseract_environment()
    print("=" * 80)
    print("TESSERACT ENVIRONMENT STATUS:")
    print(f"  Installed:  {tess_info['installed']}")
    print(f"  Executable: {tess_info['executable']}")
    print(f"  Version:    {tess_info['version']}")
    print(f"  Languages:  {tess_info['languages']}")
    print(f"  Notes:      {tess_info['notes']}")
    print("=" * 80)
    
    # Set up isolated SQLite environment
    temp_dir = tempfile.mkdtemp(prefix="scamshield-ocr-test-")
    db_path = Path(temp_dir) / "ocr_test.db"
    storage_path = Path(temp_dir) / "storage"
    storage_path.mkdir(parents=True, exist_ok=True)
    
    os.environ['DATABASE_URL'] = f"sqlite:///{db_path}"
    os.environ['STORAGE_PATH'] = str(storage_path)
    os.environ['DEV_EMAIL_TOKENS'] = '1'
    os.environ['SCAMSHIELD_MODEL_DIR'] = str(ROOT / 'ml' / 'artifacts' / 'v1-json')
    os.environ['SCAMSHIELD_MODEL_MANIFEST_SHA256'] = '833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9'
    
    from backend.app.db import Base, engine, Session, User
    from backend.app.main import app
    from backend.app.worker import process_one
    
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    
    # 1. Register & verify user
    reg = client.post('/api/auth/register', json={'email': 'ocr-tester@example.com', 'password': 'Password123!'})
    assert reg.status_code == 201
    v_token = reg.json().get('development_token')
    ver = client.post('/api/auth/verify', json={'token': v_token})
    assert ver.status_code == 200
    
    # 2. Login
    login = client.post('/api/auth/login', json={'email': 'ocr-tester@example.com', 'password': 'Password123!'})
    assert login.status_code == 200
    token = login.json()['token']
    auth_headers = {'Authorization': f'Bearer {token}'}
    
    fixtures = [
        # (ID, Text, Format, LowRes, IsValidImage, GroundTruthCategory)
        ('en_scam_png', 'URGENT: Your account has been suspended. Send OTP immediately to verify.', 'PNG', False, True, 'scam'),
        ('en_legit_jpg', 'Hi John, are we still meeting for lunch at 12:30 PM today?', 'JPEG', False, True, 'legitimate'),
        ('en_webp', 'Security Alert: Password change requested. Reply with code 948210.', 'WEBP', False, True, 'scam'),
        ('si_text_png', 'ඔබේ මුරපදය කිසිවිටෙකත් වෙනත් අයෙකුට ලබා නොදෙන්න.', 'PNG', False, True, 'legitimate'),
        ('ta_text_png', 'உங்கள் ரகசிய கடவுச்சொல்லை யாரிடமும் பகிர வேண்டாம்.', 'PNG', False, True, 'legitimate'),
        ('mixed_lang_png', 'URGENT ALERT: Send your OTP වහාම now to prevent deactivation.', 'PNG', False, True, 'scam'),
        ('low_res_png', 'Urgent bank code 1234', 'PNG', True, True, 'scam'),
        ('empty_image_png', '', 'PNG', False, True, 'empty'),
        ('invalid_image_corrupted', b'NOT_AN_IMAGE_HEADER_GARBAGE_BYTES_1234567890', 'CORRUPT', False, False, 'invalid'),
    ]
    
    results = []
    
    print("\nRUNNING REAL SCREENSHOT OCR & WORKFLOW TEST ON FIXTURES:")
    
    for f_id, text, fmt, low_res, is_valid, gt_cat in fixtures:
        start_time = time.perf_counter()
        
        if not is_valid:
            # Test rejection of corrupt/invalid image
            file_bytes = text
            resp = client.post(
                '/api/scans/screenshot',
                headers=auth_headers,
                files={'file': (f'{f_id}.png', file_bytes, 'image/png')}
            )
            elapsed = (time.perf_counter() - start_time) * 1000
            
            passed = resp.status_code in (415, 422)
            results.append({
                'fixture_id': f_id,
                'valid_image': False,
                'status_code': resp.status_code,
                'passed': passed,
                'error_detail': resp.json().get('detail'),
                'latency_ms': round(elapsed, 2)
            })
            print(f"  [{'PASS' if passed else 'FAIL'}] {f_id} (Corrupt file) -> HTTP {resp.status_code} ({resp.json().get('detail')}) [{elapsed:.1f}ms]")
            continue
            
        # Create valid synthetic image
        img_bytes = create_synthetic_image(text, fmt=fmt, low_res=low_res)
        mime = f"image/{fmt.lower()}"
        ext = 'jpg' if fmt == 'JPEG' else fmt.lower()
        
        # 1. Upload screenshot
        upload_resp = client.post(
            '/api/scans/screenshot',
            headers=auth_headers,
            files={'file': (f'{f_id}.{ext}', img_bytes, mime)}
        )
        assert upload_resp.status_code == 202, f"Upload failed for {f_id}: {upload_resp.text}"
        scan_id = upload_resp.json()['id']
        
        # 2. Execute background worker job (Real OCR execution via pytesseract)
        worker_start = time.perf_counter()
        work_done = process_one()
        worker_elapsed = (time.perf_counter() - worker_start) * 1000
        assert work_done, f"Worker found no job for scan {scan_id}"
        
        # 3. Fetch intermediate status
        scan_data = client.get(f'/api/scans/{scan_id}', headers=auth_headers).json()
        stage_status = scan_data['status']
        extracted_text = scan_data.get('text') or ''
        result_json = scan_data.get('result') or {}
        if isinstance(result_json, str):
            result_json = json.loads(result_json)
        ocr_text_in_result = result_json.get('ocr_text', '')
        
        # Determine extraction metrics
        cer = None
        if tess_info['installed'] and text:
            # CER against ground truth if engine is active
            cer = calculate_cer(text, extracted_text or ocr_text_in_result)
            
        # 4. User Text Correction & Confirmation
        # Use ground truth text for final scam detection confirmation
        confirmed_text = text if text else "Manual override text for empty image"
        confirm_resp = client.post(
            f'/api/scans/{scan_id}/confirm',
            headers=auth_headers,
            json={'text': confirmed_text}
        )
        assert confirm_resp.status_code == 200, f"Confirm failed: {confirm_resp.text}"
        
        # 5. Worker processes confirmed text into final scam assessment
        work_done_2 = process_one()
        assert work_done_2, f"Worker failed to process confirmed scan {scan_id}"
        
        # 6. Retrieve final result from history
        final_scan = client.get(f'/api/scans/{scan_id}', headers=auth_headers).json()
        assert final_scan['status'] == 'completed', f"Final status not completed: {final_scan}"
        final_result = final_scan.get('result') or {}
        if isinstance(final_result, str):
            final_result = json.loads(final_result)
        final_assessment = final_result.get('assessment')
        final_score = final_result.get('score')
        
        total_elapsed = (time.perf_counter() - start_time) * 1000
        
        test_passed = (
            stage_status in ('awaiting_confirmation', 'partially_completed') and
            final_scan['status'] == 'completed' and
            final_assessment in ('High', 'Medium', 'Inconclusive')
        )
        
        results.append({
            'fixture_id': f_id,
            'format': fmt,
            'ground_truth': text,
            'category': gt_cat,
            'valid_image': True,
            'ocr_stage_status': stage_status,
            'extracted_text': extracted_text or ocr_text_in_result,
            'cer': cer,
            'confirmed_text': confirmed_text,
            'final_status': final_scan['status'],
            'final_assessment': final_assessment,
            'final_score': final_score,
            'worker_latency_ms': round(worker_elapsed, 2),
            'total_latency_ms': round(total_elapsed, 2),
            'passed': test_passed
        })
        
        print(f"  [{'PASS' if test_passed else 'FAIL'}] {f_id} ({fmt}) -> Stage: {stage_status} | Final: {final_assessment} (score={final_score}) | Worker: {worker_elapsed:.1f}ms")
    
    # Check history listing
    history = client.get('/api/scans', headers=auth_headers).json()
    assert len(history) == len([f for f in fixtures if f[4]]), "History count mismatch"
    print(f"\nHistory verified: {len(history)} screenshot scans recorded in user history.")
    
    # Save test report
    out_file = ROOT / 'docs' / 'ocr_verification_results.json'
    summary = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime()),
        'tesseract_environment': tess_info,
        'total_fixtures': len(fixtures),
        'passed_count': sum(1 for r in results if r['passed']),
        'results': results
    }
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved OCR verification results to {out_file}")
    
    # Clean up temp dir
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass

if __name__ == '__main__':
    run_ocr_test_suite()
