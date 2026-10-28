"""Run Chrome flows against a disposable API/database and controlled OCR worker."""
import hashlib
import base64
import hmac
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from PIL import Image
from playwright.sync_api import sync_playwright, expect

ROOT=Path(__file__).resolve().parents[1]
def otp(secret=None):
    key=base64.b32decode(secret) if secret else b'12345678901234567890'
    block=hmac.new(key,struct.pack('>Q',int(time.time()//30)),hashlib.sha1).digest()
    offset=block[-1]&15
    return f'{(struct.unpack(">I",block[offset:offset+4])[0]&0x7fffffff)%1000000:06d}'

def main():
    results=[]
    with tempfile.TemporaryDirectory(prefix='scamshield-browser-') as tmp:
        folder=Path(tmp)
        env={**os.environ,'DATABASE_URL':'sqlite:///'+str(folder/'browser-test.db'),'STORAGE_PATH':str(folder/'uploads'),'DEV_EMAIL_TOKENS':'1','SCAMSHIELD_BROWSER_FIXTURE':'1'}
        env.pop('SMTP_HOST',None)
        subprocess.run([sys.executable,'-m','alembic','-c','backend/alembic.ini','upgrade','head'],cwd=ROOT,env=env,check=True)
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        base=f'http://127.0.0.1:{port}'
        log=(folder/'server.log').open('w')
        server_python=sys.executable
        if os.name=='nt':
            # Launch the base interpreter directly to avoid the Windows venv
            # redirector spawning an unowned child that survives terminate().
            server_python=sys._base_executable
            env['PYTHONPATH']=str(Path(sys.prefix)/'Lib/site-packages')+os.pathsep+str(ROOT)
        server=subprocess.Popen([server_python,'-m','uvicorn','backend.tests.browser_fixture:app','--host','127.0.0.1','--port',str(port),'--no-access-log'],cwd=ROOT,env=env,stdout=log,stderr=log)
        try:
            for _ in range(100):
                try:
                    urllib.request.urlopen(base+'/api/ready',timeout=1);break
                except Exception:
                    time.sleep(.2)
            else:
                raise RuntimeError('Fixture server failed to start')
            with sync_playwright() as playwright:
                browser=playwright.chromium.launch(executable_path=os.getenv('CHROME_PATH',r'C:\Program Files\Google\Chrome\Application\chrome.exe'),headless=True)
                page=browser.new_page(viewport={'width':1440,'height':1000})
                page.route('https://fonts.googleapis.com/**',lambda route:route.abort())
                page.route('https://fonts.gstatic.com/**',lambda route:route.abort())
                errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
                def login(email='browser@fixture.test',staff=False,password='BrowserPassword123!'):
                    page.locator('#email').fill(email);page.locator('#password').fill(password)
                    if staff:page.locator('#otp').fill(otp())
                    page.locator('#auth-submit').click();expect(page.locator('#shell')).to_be_visible()
                def close():
                    if page.locator('#modal').is_visible():page.locator('#close-modal').click()
                def new_text(text):
                    close();page.goto(base+'/#scan');page.locator('[data-tab="text"]').click();page.locator('#scan-text').fill(text);page.locator('#scan-submit').click()
                    expect(page.locator('#modal-body .result-summary')).to_be_visible(timeout=20000)
                page.goto(base)
                page.locator('#toggle-auth').click();page.locator('#email').fill('browser@fixture.test');page.locator('#password').fill('BrowserPassword123!');page.locator('#auth-submit').click()
                expect(page.locator('#action-token')).not_to_have_value('');close()
                page.locator('#resend-open').click();page.locator('#resend-email').fill('browser@fixture.test');page.locator('#resend-form button').click()
                expect(page.locator('#action-token')).not_to_have_value('');page.locator('#token-form button').click();expect(page.locator('#modal')).not_to_be_visible()
                page.locator('#toggle-auth').click();login();results.append('registration/resend/verification/login')
                text='Urgent! Send your OTP immediately to claim your prize https://fixture.example.test'
                new_text(text);expect(page.locator('#modal-body mark').first).to_be_visible();expect(page.locator('#modal-body')).to_contain_text('High risk assessment')
                page.locator('#report').click();page.locator('#comment').fill('Please investigate this credential request');page.locator('#comment-form button').click();expect(page.locator('#report')).to_be_disabled();close()
                new_text(text+' Another reported request.');page.locator('#report').click();page.locator('#comment').fill('Related domain deserves review');page.locator('#comment-form button').click();expect(page.locator('#report')).to_be_disabled();close();results.append('text/evidence/explicit report sharing')
                page.goto(base+'/#scan');page.locator('[data-tab="url"]').click();page.locator('#scan-text').fill('https://unreachable.example.test');page.locator('#scan-submit').click();expect(page.locator('#modal-body .result-summary')).to_be_visible(timeout=20000);expect(page.locator('#modal-body')).to_contain_text('Live URL reputation');close();results.append('static URL/missing live check disclosure')
                for color,expected_status in [('white','Review and correct'),('black','OCR unavailable')]:
                    image=folder/(color+'.png');Image.new('RGB',(120,100),color).save(image)
                    page.goto(base+'/#scan');page.locator('[data-tab="screenshot"]').click();page.locator('#file').set_input_files(str(image));page.locator('#scan-submit').click()
                    expect(page.locator('#confirm-form')).to_be_visible(timeout=20000);expect(page.locator('#modal-body')).to_contain_text(expected_status)
                    if color=='white':expect(page.locator('#corrected')).to_contain_text('OTP')
                    page.locator('#corrected').fill('Urgent! Send your OTP immediately');page.locator('#confirm-form button').click();expect(page.locator('#modal-body .result-summary')).to_be_visible(timeout=20000);close()
                results.append('controlled OCR preview/correction/failure/manual fallback')
                page.goto(base+'/#history');expect(page.locator('[data-scan]')).to_have_count(5)
                page.locator('[data-scan]').first.click();page.locator('#delete-scan').click();page.locator('#delete-confirm').click();expect(page.locator('[data-scan]')).to_have_count(4);results.append('history/scan deletion')
                for width,height in [(390,844),(768,1024),(1440,1000)]:
                    page.set_viewport_size({'width':width,'height':height});page.goto(base+'/#overview');expect(page.locator('.hero')).to_be_visible()
                    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'),f'Horizontal overflow at {width}'
                    if width==390:
                        expect(page.locator('#mobile-account')).to_be_visible()
                        expect(page.locator('#mobile-logout')).to_be_visible()
                    page.locator('#toast').evaluate("element=>element.style.display='none'")
                    (ROOT/'artifacts').mkdir(exist_ok=True)
                    page.screenshot(path=str(ROOT/'artifacts'/f'browser-{width}.png'),full_page=True)
                results.append('layout overflow: 390/768/1440 pixels')
                page.route('**/api/scans',lambda route:route.abort());page.goto(base+'/#history');expect(page.locator('.inline-error')).to_be_visible();page.unroute('**/api/scans');results.append('network failure state')
                page.evaluate("sessionStorage.setItem('token','expired-fixture-token')")
                # Authentication is initially visible while boot is pending. Wait for
                # the 401-triggered second navigation before filling the login form.
                with page.expect_navigation(wait_until='load'):
                    page.reload()
                    page.wait_for_function("sessionStorage.getItem('token') === null")
                expect(page.locator('#auth')).to_be_visible();login();results.append('expired session returns to login')
                page.locator('#logout').click();expect(page.locator('#auth')).to_be_visible();login('admin@fixture.test',True)
                page.goto(base+'/#queue');page.locator('[data-report]').first.click();page.locator('#verdict').select_option('Confirmed scam');page.locator('#review-reason').fill('Controlled fixture credential request');page.locator('#review-form button').click();expect(page.locator('#modal')).not_to_be_visible()
                page.goto(base+'/#campaigns');expect(page.locator('.graph')).to_be_visible();page.locator('#campaign-name').fill('Reviewed fixture campaign');options=page.locator('#campaign-members option').evaluate_all('(items)=>items.map(o=>o.value)');page.locator('#campaign-members').select_option(options);page.locator('#campaign-reason').fill('Shared controlled domain reviewed');page.locator('#campaign-form button').click();expect(page.locator('[data-dissolve]')).to_have_count(1);results.append('analyst decision/campaign grouping')
                page.locator('#logout').click();expect(page.locator('#auth')).to_be_visible();login();page.goto(base+'/#history');page.locator('[data-scan]').filter(has_text='Another reported request.').click();expect(page.locator('#modal-body')).to_contain_text('Confirmed scam');close();results.append('user sees separate analyst outcome')
                page.locator('#logout').click();expect(page.locator('#auth')).to_be_visible();page.locator('#forgot').click();page.locator('#reset-email').fill('browser@fixture.test');page.locator('#forgot-form button').click();expect(page.locator('#action-token')).not_to_have_value('');page.locator('#new-password').fill('ResetBrowserPassword123!');page.locator('#token-form button').click();expect(page.locator('#modal')).not_to_be_visible();login(password='ResetBrowserPassword123!');results.append('password reset/new password login')
                page.goto(base+'/#settings');page.locator('#enroll-mfa').click();secret=page.locator('#modal-body pre').inner_text();page.locator('#mfa-code').fill(otp(secret));page.locator('#mfa-form button').click();expect(page.locator('#codes-saved')).to_be_visible();codes=page.locator('#modal-body pre').inner_text().splitlines();assert len(codes)==8;page.locator('#codes-saved').click()
                page.locator('#logout').click();expect(page.locator('#auth')).to_be_visible();page.locator('.recovery-login summary').click();page.locator('#recovery-code').fill(codes[0]);login(password='ResetBrowserPassword123!')
                page.goto(base+'/#settings');page.locator('[data-recovery-regenerate]').click();page.locator('#reauth-password').fill('ResetBrowserPassword123!');page.locator('#reauth-recovery').fill(codes[1]);page.locator('#recovery-form button').click();expect(page.locator('#codes-saved')).to_be_visible();new_codes=page.locator('#modal-body pre').inner_text().splitlines();page.locator('#codes-saved').click();expect(page.locator('#auth')).to_be_visible();page.locator('.recovery-login summary').click();page.locator('#recovery-code').fill(new_codes[0]);login(password='ResetBrowserPassword123!');results.append('MFA enrollment/recovery login/reauthenticated regeneration/session revocation')
                page.goto(base+'/#settings');page.locator('#delete-account').click();page.locator('#delete-word').fill('DELETE');page.locator('#delete-account-form button').click();expect(page.locator('#auth')).to_be_visible();results.append('account deletion/session removal')
                assert not errors,errors
                result={'browser':browser.version,'passed':results,'javascript_errors':errors,'ocr':'controlled fixture, not engine accuracy','device':'desktop Chrome only, no Android device'}
                print(json.dumps(result,indent=2));(ROOT/'docs/browser-verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
                browser.close()
        finally:
            server.terminate()
            server.wait(timeout=15);log.close()

if __name__=='__main__':main()
