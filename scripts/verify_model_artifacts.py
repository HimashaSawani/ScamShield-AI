"""Verify the released JSON estimator reproduces the frozen URL report."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.app.model_inference import load_bundle,predict
from ml.train_v1 import metrics

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--bundle',type=Path,default=ROOT/'ml/artifacts/v1-json');parser.add_argument('--prepared',type=Path,default=ROOT/'ml/prepared/v1');args=parser.parse_args()
    pin=hashlib.sha256((args.bundle/'manifest.json').read_bytes()).hexdigest();models=load_bundle(str(args.bundle),pin)
    rows=[r for r in csv.DictReader((args.prepared/'url.csv').open(encoding='utf-8')) if r['split']=='test']
    predictions=[];timings=[]
    for i,r in enumerate(rows):
        started=time.perf_counter();predictions.append(predict(models['url'],r['text']))
        if i<100:timings.append((time.perf_counter()-started)*1000)
    actual=metrics([r['label'] for r in rows],predictions,['legitimate','phishing'],'phishing')
    expected=json.loads((args.bundle/'url-report.json').read_text())['test']['model']
    assert actual['confusion_matrix']==expected['confusion_matrix'],'JSON production estimator differs from frozen estimator report'
    record={'manifest_sha256':pin,'enabled_versions':{k:v['version'] for k,v in models.items()},'frozen_url_test_count':len(rows),'production_json_confusion_matrix_matches_training_estimator':True,'latency_ms_including_production_url_features':{'median':statistics.median(timings),'p95':sorted(timings)[94],'samples':len(timings)},'no_urls_fetched':True}
    (ROOT/'docs/model-artifact-verification.json').write_text(json.dumps(record,indent=2));print(json.dumps(record,indent=2))

if __name__=='__main__':main()
