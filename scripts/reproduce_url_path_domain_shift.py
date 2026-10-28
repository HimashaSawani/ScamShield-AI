"""Reproduce and analyze URL false positives on benign URLs with varied path depths.

Independent evaluation dataset across:
- Root-domain URLs
- Long documentation paths
- Deep documentation paths
- Search query parameters
- Product pages
- Blog posts
- Educational pages
- Government-style informational pages
- Long filenames
- URL-encoded characters
- Paired root vs deep-path domains
"""
import os
import sys
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ['SCAMSHIELD_MODEL_DIR'] = str(ROOT / 'ml' / 'artifacts' / 'v1-json')
os.environ['SCAMSHIELD_MODEL_MANIFEST_SHA256'] = '833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9'

from backend.app.detection import analyze
from backend.app.model_inference import enrich, predict, load_bundle
from backend.app.model_features import url_features, URL_FEATURES

BENIGN_EVALUATION_URLS = [
    # Paired Root vs Deep Path (Same Domain)
    {"url": "https://docs.python.org", "category": "root_domain", "expected": "legitimate"},
    {"url": "https://docs.python.org/3/library/os.path.html", "category": "documentation_path", "expected": "legitimate"},
    {"url": "https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlsplit", "category": "deep_documentation_path", "expected": "legitimate"},
    
    {"url": "https://en.wikipedia.org", "category": "root_domain", "expected": "legitimate"},
    {"url": "https://en.wikipedia.org/wiki/Phishing", "category": "educational_page", "expected": "legitimate"},
    {"url": "https://en.wikipedia.org/wiki/Computer_security_incident_response_team", "category": "deep_educational_path", "expected": "legitimate"},

    {"url": "https://developer.mozilla.org", "category": "root_domain", "expected": "legitimate"},
    {"url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy", "category": "deep_documentation_path", "expected": "legitimate"},
    {"url": "https://developer.mozilla.org/en-US/docs/Learn/Common_questions/Web_mechanisms/What_is_a_web_server", "category": "deep_documentation_path", "expected": "legitimate"},

    {"url": "https://github.com", "category": "root_domain", "expected": "legitimate"},
    {"url": "https://github.com/torvalds/linux", "category": "product_or_project_page", "expected": "legitimate"},
    {"url": "https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/security-bugs.rst", "category": "deep_documentation_path", "expected": "legitimate"},

    {"url": "https://www.nist.gov", "category": "root_domain", "expected": "legitimate"},
    {"url": "https://www.nist.gov/cyberframework", "category": "gov_informational", "expected": "legitimate"},
    {"url": "https://www.nist.gov/cyberframework/online-learning/five-functions", "category": "gov_informational_deep", "expected": "legitimate"},

    # Search query parameters
    {"url": "https://www.google.com/search?q=cybersecurity+standards&hl=en", "category": "search_query", "expected": "legitimate"},
    {"url": "https://duckduckgo.com/?q=safe+browsing+practices&ia=web", "category": "search_query", "expected": "legitimate"},

    # Product and e-commerce style pages
    {"url": "https://aws.amazon.com/security/identity-and-compliance/", "category": "product_page", "expected": "legitimate"},
    {"url": "https://cloud.google.com/security/products/zero-trust", "category": "product_page", "expected": "legitimate"},

    # Blog posts
    {"url": "https://blog.cloudflare.com/how-we-built-our-threat-intelligence-platform/", "category": "blog_post", "expected": "legitimate"},
    {"url": "https://engineering.fb.com/2026/01/15/security/zero-day-mitigation-framework/", "category": "blog_post", "expected": "legitimate"},

    # Long filenames
    {"url": "https://csrc.nist.gov/publications/detail/sp/800-63/3/final", "category": "long_filename", "expected": "legitimate"},
    {"url": "https://www.w3.org/TR/2021/REC-webdriver2-20211124/", "category": "long_filename", "expected": "legitimate"},

    # URL-encoded characters
    {"url": "https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#4xx_client_errors", "category": "encoded_and_anchor", "expected": "legitimate"},
    {"url": "https://archive.org/search.php?query=cybersecurity%20AND%20mediatype%3Atexts", "category": "encoded_query", "expected": "legitimate"},
]

def run_investigation():
    models = load_bundle(os.environ['SCAMSHIELD_MODEL_DIR'], os.environ['SCAMSHIELD_MODEL_MANIFEST_SHA256'])
    url_model = models.get('url')
    
    results = []
    print("=" * 80)
    print("REPRODUCING URL FALSE-POSITIVE BEHAVIOR ON BENIGN DEEP-PATH URLS")
    print("=" * 80)
    
    root_count = 0
    root_fps = 0
    deep_count = 0
    deep_fps = 0

    for item in BENIGN_EVALUATION_URLS:
        url = item['url']
        cat = item['category']
        
        # 1. Rules-only
        rules_res = analyze(url, 'url')
        
        # 2. Combined (rules + model)
        enriched_res = enrich(analyze(url, 'url'), url, 'url')
        
        # 3. Direct model features & prediction
        feats = url_features(url)
        raw_pred = predict(url_model, url)
        
        is_root = cat == "root_domain"
        if is_root:
            root_count += 1
            if enriched_res['assessment'] != 'Inconclusive':
                root_fps += 1
        else:
            deep_count += 1
            if enriched_res['assessment'] != 'Inconclusive':
                deep_fps += 1

        is_fp = enriched_res['assessment'] != 'Inconclusive'
        
        results.append({
            'url': url,
            'category': cat,
            'rules_score': rules_res['score'],
            'rules_assessment': rules_res['assessment'],
            'rules_evidence': [e['code'] for e in rules_res['evidence']],
            'ml_prediction': raw_pred,
            'combined_assessment': enriched_res['assessment'],
            'model_mode': enriched_res.get('model_mode'),
            'path_length': feats[2],
            'slashes': feats[7],
            'length': feats[0],
            'entropy': round(feats[17], 3),
            'false_positive': is_fp
        })
        
        flag = " [FP]" if is_fp else " [OK]"
        print(f"{flag} {url}")
        print(f"      Category: {cat} | Path len: {feats[2]} | Slashes: {feats[7]}")
        print(f"      Rules: {rules_res['assessment']} (score={rules_res['score']}) | ML: {raw_pred} | Combined: {enriched_res['assessment']}")

    print("\n" + "=" * 80)
    print("SUMMARY RESULTS:")
    print(f"  Root-domain benign URLs:  {root_count - root_fps}/{root_count} classified Inconclusive (FP rate: {root_fps/root_count*100:.1f}%)")
    print(f"  Deep-path benign URLs:     {deep_count - deep_fps}/{deep_count} classified Inconclusive (FP rate: {deep_fps/deep_count*100:.1f}%)")
    print("=" * 80)
    
    out_path = ROOT / 'docs' / 'url_path_domain_shift_reproduction.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({
            'total_tested': len(BENIGN_EVALUATION_URLS),
            'root_domain_count': root_count,
            'root_domain_false_positives': root_fps,
            'deep_path_count': deep_count,
            'deep_path_false_positives': deep_fps,
            'results': results
        }, f, indent=2)
    print(f"Saved reproduction record to {out_path}")

if __name__ == '__main__':
    run_investigation()

