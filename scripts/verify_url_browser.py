"""Fresh queued URL checks in the actual local dashboard; never visits input URLs."""
import json
import os
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ROOT=Path(__file__).resolve().parents[1]

def main():
    results=[];errors=[];external=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=os.getenv('CHROME_PATH',r'C:\Program Files\Google\Chrome\Application\chrome.exe'),headless=True)
        page=browser.new_page(viewport={'width':1440,'height':1100})
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.on('request',lambda request:external.append(request.url) if not request.url.startswith('http://127.0.0.1:8015/') else None)
        page.goto('http://127.0.0.1:8015/');page.locator('#try-demo').click();expect(page.locator('#shell')).to_be_visible()
        cases=[('https://bank.invalid@account-check.invalid/login','account-check.invalid',None),
               ('https://login.bank.example.co.uk/'+('long-path-'*80)+'?x=<script>alert(1)</script>','login.bank.example.co.uk','example.co.uk'),
               ('https://alice.github.io/login','alice.github.io','alice.github.io')]
        for index,(url,host,domain) in enumerate(cases):
            page.goto('http://127.0.0.1:8015/#scan');page.locator('[data-tab="url"]').click();page.locator('#scan-text').fill(url)
            with page.expect_response(lambda r:r.url.endswith('/api/scans') and r.request.method=='POST') as created:page.locator('#scan-submit').click()
            scan_id=created.value.json()['id']
            expect(page.locator('.url-card')).to_be_visible(timeout=30000)
            expect(page.locator('.actual-hostname')).to_have_text(host)
            if domain:
                expect(page.locator('.registrable-domain')).to_have_text(domain)
                expect(page.locator('.model-results')).to_contain_text('scamshield-url-v1')
            else:
                expect(page.locator('.registrable-domain')).to_contain_text('No recognized public suffix')
                expect(page.locator('.user-information')).to_have_text('bank.invalid')
                expect(page.locator('#modal-body')).to_contain_text('does not establish fraud')
            # URL tokenization stops at markup delimiters; original text remains
            # escaped in the message/evidence display.
            expect(page.locator('.url-value')).to_have_text(url.split('<')[0])
            expect(page.locator('#modal-body blockquote').first).to_contain_text(url)
            assert page.locator('.url-card a, .url-card script').count()==0
            expect(page.locator('.url-checks')).to_contain_text('Failed: None recorded')
            expect(page.locator('#modal-body')).to_contain_text('HTTPS is not proof of safety')
            for width in [390,768,1440]:
                page.set_viewport_size({'width':width,'height':1000})
                assert page.locator('#modal-body').evaluate('(e)=>e.scrollWidth<=e.clientWidth'),f'Modal overflow {width}'
                assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
                if index==1:page.screenshot(path=str(ROOT/'artifacts'/f'url-{width}.png'),full_page=True)
            results.append({'scan_id':scan_id,'hostname':host,'registrable_domain':domain,'processing':page.locator('.processing-status').inner_text(),'assessment':page.locator('.result-state .badge').inner_text(),'version':page.locator('.analysis-version').inner_text(),'plain_text':True,'widths':[390,768,1440]})
            page.locator('#close-modal').click()
        assert not errors,errors
        unexpected=[url for url in external if not url.startswith(('https://fonts.googleapis.com/','https://fonts.gstatic.com/'))]
        assert not unexpected,unexpected
        record={'fresh_url_scans':results,'javascript_errors':errors,'external_browser_requests':external,'suspected_url_requests':unexpected,'native_device_verified':False}
        (ROOT/'docs/url-browser-verification.json').write_text(json.dumps(record,indent=2),encoding='utf-8')
        print(json.dumps(record,indent=2));browser.close()

if __name__=='__main__':main()
