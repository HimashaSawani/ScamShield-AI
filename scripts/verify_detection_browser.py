"""Acceptance checks on the actual application at port 8015, not a fixture server."""
import hashlib
import json
import os
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright, expect
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.verify_detection_live import A,B
from backend.app.detection import VERSION

def main():
    results={};assets=[];errors=[]
    (ROOT/'artifacts').mkdir(exist_ok=True)
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=os.getenv('CHROME_PATH',r'C:\Program Files\Google\Chrome\Application\chrome.exe'),headless=True)
        page=browser.new_page(viewport={'width':1440,'height':1100})
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.on('response',lambda response:assets.append(response.url) if any(name in response.url for name in ['app.js','results.js','style.css']) else None)
        page.goto('http://127.0.0.1:8015/');page.locator('#try-demo').click();expect(page.locator('#shell')).to_be_visible()
        for label,text,assessment in [('A',A,'High'),('B',B,'Inconclusive')]:
            page.goto('http://127.0.0.1:8015/#scan');page.locator('[data-tab="text"]').click();page.locator('#scan-text').fill(text)
            with page.expect_response(lambda r:r.url.endswith('/api/scans') and r.request.method=='POST') as creation:
                page.locator('#scan-submit').click()
            id=creation.value.json()['id']
            expect(page.locator('.result-summary')).to_be_visible(timeout=30000)
            expect(page.locator('.result-state .badge')).to_have_text(assessment)
            expect(page.locator('.processing-status')).to_have_text('Completed')
            expect(page.locator('.analysis-version')).to_contain_text(VERSION)
            expect(page.locator('.result-summary small')).to_contain_text(f'Indicator score: {65 if label=="A" else 0}/100')
            expect(page.locator('#modal-body')).not_to_contain_text('Lowcompleted')
            if label=='A':
                expect(page.locator('.evidence-title')).to_have_count(2)
                expect(page.locator('.evidence-title').first).to_contain_text('Request to disclose')
                expect(page.locator('.evidence-weight').first).to_contain_text('+45')
                expect(page.locator('#modal-body')).to_contain_text('Do not share passwords or one-time codes.')
                assert page.locator('.evidence-item').filter(has_text='credentials ·').count()==0
                assert page.locator('.evidence-item').filter(has_text='urgency ·').count()==0
            else:
                expect(page.locator('.evidence-item')).to_have_count(0)
                expect(page.locator('#modal-body')).to_contain_text('Limited analysis cannot verify legitimacy or safety.')
            expect(page.locator('#modal-body')).to_contain_text('Live URL reputation and destination checks')
            page.screenshot(path=str(ROOT/'artifacts'/f'detection-{label}-desktop.png'),full_page=True)
            if label=='A':
                page.set_viewport_size({'width':390,'height':844})
                assert page.locator('.result-state-item').nth(0).bounding_box()['x'] != page.locator('.result-state-item').nth(1).bounding_box()['x']
                page.screenshot(path=str(ROOT/'artifacts'/'detection-A-mobile.png'),full_page=True)
                page.set_viewport_size({'width':1440,'height':1100})
            results[label]={'scan_id':id,'assessment':assessment,'version':VERSION,'processing':'Completed','evidence_titles':page.locator('.evidence-title').all_text_contents()}
            page.locator('#close-modal').click()
        before=json.loads((ROOT/'artifacts'/'detection-before.json').read_text())
        page.goto('http://127.0.0.1:8015/#history')
        old_id=before['results']['A']['id']
        page.locator(f'[data-scan="{old_id}"]').click()
        expect(page.locator('.analysis-version')).to_contain_text('rules-1.0.0')
        expect(page.locator('.result-state .badge')).to_have_text('Low')
        assert all(any(name+'?v='+VERSION in asset for asset in assets) for name in ['app.js','results.js','style.css'])
        assert not errors,errors
        result={'base_url':'http://127.0.0.1:8015','browser':browser.version,'fresh_ui_scans':results,'historical_scan_rendered_with_original_version':old_id,'versioned_assets_loaded':True,'javascript_errors':errors,'screenshots':'artifacts/detection-*.png','native_device_test':False}
        (ROOT/'docs/detection-browser-verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps(result,indent=2));browser.close()

if __name__=='__main__':main()
