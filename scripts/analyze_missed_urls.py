import json
import os
import collections
from pathlib import Path

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ['SCAMSHIELD_MODEL_DIR'] = str(ROOT / 'ml/artifacts/v1-json')
os.environ['SCAMSHIELD_MODEL_MANIFEST_SHA256'] = '833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9'

from backend.app.detection import analyze
from backend.app.model_inference import load_bundle, predict, enrich

bundle_dir = str(ROOT / 'ml/artifacts/v1-json')
manifest_hash = '833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9'
models = load_bundle(bundle_dir, manifest_hash)

dataset_path = ROOT / 'docs/synthetic_evaluation_dataset.json'
data = json.loads(dataset_path.read_text(encoding='utf-8'))

suspicious = data['suspicious_urls']
benign = data['benign_urls']

print(f"Total Suspicious: {len(suspicious)}, Total Benign: {len(benign)}")

# Evaluate all suspicious URLs
results = []
for item in suspicious:
    url = item['url']
    cat = item['subcategory']
    rule_res = analyze(url, 'url')
    ml_pred = predict(models['url'], url)
    comb_res = enrich(analyze(url, 'url'), url, 'url')
    
    rule_flag = rule_res['assessment'] in ['High', 'Medium']
    ml_flag = ml_pred == 'phishing'
    comb_flag = comb_res['assessment'] in ['High', 'Medium']
    
    results.append({
        'url': url,
        'cat': cat,
        'rule': rule_res['assessment'],
        'rule_flag': rule_flag,
        'ml_pred': ml_pred,
        'ml_flag': ml_flag,
        'comb': comb_res['assessment'],
        'comb_flag': comb_flag
    })

print("\n--- SUSPICIOUS URLs (Total 115) ---")
print("Rule-only Flagged:", sum(r['rule_flag'] for r in results))
print("ML-only Flagged:", sum(r['ml_flag'] for r in results))
print("Combined Flagged:", sum(r['comb_flag'] for r in results))

# Evaluate benign URLs for false positives
benign_results = []
for item in benign:
    url = item['url']
    cat = item['subcategory']
    rule_res = analyze(url, 'url')
    ml_pred = predict(models['url'], url)
    comb_res = enrich(analyze(url, 'url'), url, 'url')
    
    rule_flag = rule_res['assessment'] in ['High', 'Medium']
    ml_flag = ml_pred == 'phishing'
    comb_flag = comb_res['assessment'] in ['High', 'Medium']
    
    benign_results.append({
        'url': url,
        'cat': cat,
        'rule': rule_res['assessment'],
        'rule_flag': rule_flag,
        'ml_pred': ml_pred,
        'ml_flag': ml_flag,
        'comb': comb_res['assessment'],
        'comb_flag': comb_flag
    })

print("\n--- BENIGN URLs (Total 100) ---")
print("Rule-only FP:", sum(r['rule_flag'] for r in benign_results))
print("ML-only FP:", sum(r['ml_flag'] for r in benign_results))
print("Combined FP:", sum(r['comb_flag'] for r in benign_results))

print("\n--- SUB-CATEGORY BREAKDOWN ON SUSPICIOUS ---")
by_cat = collections.defaultdict(list)
for r in results:
    by_cat[r['cat']].append(r)

for cat, rows in sorted(by_cat.items()):
    r_flags = sum(x['rule_flag'] for x in rows)
    m_flags = sum(x['ml_flag'] for x in rows)
    c_flags = sum(x['comb_flag'] for x in rows)
    print(f"{cat:25s}: total={len(rows):2d} | rule={r_flags:2d} | ml={m_flags:2d} | comb={c_flags:2d}")

# Inspect the 44 previously missed
missed_by_rules = [r for r in results if not r['rule_flag']]
print(f"\nPreviously missed by rules: {len(missed_by_rules)}")
print("How many of these are detected by ML:", sum(r['ml_flag'] for r in missed_by_rules))
print("How many of these are detected by Combined:", sum(r['comb_flag'] for r in missed_by_rules))

print("\nSample missed details:")
for r in missed_by_rules[:20]:
    print(f"[{r['cat']}] ML={r['ml_pred']} Comb={r['comb']} URL={r['url']}")
