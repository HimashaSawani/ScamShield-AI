"""Phase 1: Verification of active scamshield-url-v2 model and v1 rollback compatibility."""
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.model_inference import load_bundle, predict, enrich, model_status
from backend.app.model_features import url_features_v1, url_features_v2, URL_SCHEMA_V1, URL_SCHEMA_V2
from backend.app.detection import analyze

def run_phase1_verification():
    print("=" * 80)
    print("PHASE 1: VERIFY ACTIVE MODEL (scamshield-url-v2)")
    print("=" * 80)

    # 1. Manifest SHA256 integrity check
    v2_dir = ROOT / 'ml' / 'artifacts' / 'v2-json'
    manifest_bytes = (v2_dir / 'manifest.json').read_bytes()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    expected_v2_manifest = "b9c99c7e5bc4e003357748dd343ca5f9e44fc9c24f03c611f77e4d342ca33606"
    assert manifest_sha256 == expected_v2_manifest, f"Manifest mismatch: {manifest_sha256}"
    print(f"[PASS] 1. Manifest SHA256 integrity verified: {manifest_sha256}")

    # 2. Model file integrity check
    model_bytes = (v2_dir / 'url-model.json').read_bytes()
    model_sha256 = hashlib.sha256(model_bytes).hexdigest()
    expected_v2_model = "653a04f5d90792b87ceda9ac5ab993822ba483eae7d8f6aab96198a084bd7eaa"
    assert model_sha256 == expected_v2_model, f"URL model mismatch: {model_sha256}"
    print(f"[PASS] 2. URL model SHA256 integrity verified: {model_sha256}")

    # 3. Feature schema compatibility
    model_data = json.loads(model_bytes.decode('utf-8'))
    assert model_data['feature_schema'] == URL_SCHEMA_V2, f"Schema mismatch: {model_data['feature_schema']}"
    assert len(model_data['url_features']) == 28, f"Feature count: {len(model_data['url_features'])}"
    print(f"[PASS] 3. Schema compatible: {model_data['feature_schema']} (28 features)")

    # 4. Load bundle with pin and verify status
    os.environ['SCAMSHIELD_MODEL_DIR'] = str(v2_dir)
    os.environ['SCAMSHIELD_MODEL_MANIFEST_SHA256'] = manifest_sha256
    load_bundle.cache_clear()
    models = load_bundle(str(v2_dir), manifest_sha256)
    assert 'url' in models, "URL model not loaded in bundle"
    assert 'text' not in models, "Text model should remain disabled by quality gate"
    assert models['url']['version'] == 'scamshield-url-v2'
    status = model_status()
    assert status['mode'] == 'rules-plus-model'
    assert status['enabled'] == [{'kind': 'url', 'version': 'scamshield-url-v2'}]
    print(f"[PASS] 4. Bundle loaded: version={models['url']['version']}, mode={status['mode']}")

    # 5. Test legitimate root-domain and deep-path URLs
    legit_test_cases = [
        ("https://www.google.com", "root domain"),
        ("https://docs.python.org/3/library/sqlite3.html", "deep technical path"),
        ("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy", "deep doc path"),
        ("https://en.wikipedia.org/wiki/Phishing", "encyclopedia article path"),
        ("https://www.gov.uk/government/organisations", "government subpage path"),
    ]
    print("\n5. Testing Legitimate URLs (Path Bias Check):")
    for url, desc in legit_test_cases:
        rule_eval = analyze(url, 'url')
        enriched = enrich(rule_eval, url, 'url')
        pred = enriched['models'][0]['prediction']
        assessment = enriched['assessment']
        print(f"   - [{pred.upper()}] {url} ({desc}) -> Assessment: {assessment}")
        assert pred == 'legitimate', f"False positive on legitimate URL: {url} -> {pred}"
        assert assessment == 'Inconclusive', f"Assessment elevated unexpectedly: {assessment}"
    print("[PASS] Legitimate URLs all correctly evaluated as legitimate / Inconclusive.")

    # 6. Test synthetic phishing URLs
    phish_test_cases = [
        ("https://apple-verify.example.com/login", "credential harvest login"),
        ("https://secure-login.bank-update.com/auth/session", "brand spoofing with sensitive tokens"),
        ("https://account-verify-portal.top/signin.php", "phishing extension on deceptive host"),
    ]
    print("\n6. Testing Phishing URLs:")
    for url, desc in phish_test_cases:
        rule_eval = analyze(url, 'url')
        enriched = enrich(rule_eval, url, 'url')
        pred = enriched['models'][0]['prediction']
        assessment = enriched['assessment']
        explanation = enriched.get('explanation', '')
        print(f"   - [{pred.upper()}] {url} ({desc}) -> Assessment: {assessment}")
        assert pred == 'phishing', f"Missed phishing URL: {url} -> {pred}"
        assert assessment in ['Medium', 'High'], f"Expected elevation, got {assessment}"
        assert 'phishing' in explanation.lower() or 'concern' in explanation.lower(), "Missing explanation"
    print("[PASS] Phishing URLs detected and elevated to Medium with proper explanations.")

    # 7. Confirm v1 rollback remains functional
    v1_dir = ROOT / 'ml' / 'artifacts' / 'v1-json'
    v1_pin = hashlib.sha256((v1_dir / 'manifest.json').read_bytes()).hexdigest()
    expected_v1_pin = "833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9"
    assert v1_pin == expected_v1_pin
    os.environ['SCAMSHIELD_MODEL_DIR'] = str(v1_dir)
    os.environ['SCAMSHIELD_MODEL_MANIFEST_SHA256'] = v1_pin
    load_bundle.cache_clear()
    v1_models = load_bundle(str(v1_dir), v1_pin)
    assert v1_models['url']['version'] == 'scamshield-url-v1'
    assert v1_models['url']['feature_schema'] == URL_SCHEMA_V1
    assert len(v1_models['url']['url_features']) == 20
    v1_status = model_status()
    assert v1_status['enabled'] == [{'kind': 'url', 'version': 'scamshield-url-v1'}]
    print(f"[PASS] 7. Rollback to v1 verified: version={v1_models['url']['version']}, schema={v1_models['url']['feature_schema']}")

    print("\nALL PHASE 1 VERIFICATION CHECKS PASSED!")

if __name__ == '__main__':
    run_phase1_verification()
