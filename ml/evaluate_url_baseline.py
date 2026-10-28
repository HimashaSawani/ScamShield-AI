"""Report the frozen simple URL baseline without revising model selection."""
import csv
import hashlib
import json
from pathlib import Path
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
import numpy as np
from backend.app.model_features import url_features
from ml.train_v1 import metrics,SEED

def main():
    folder=Path('ml/artifacts/v1-json');prepared=Path('ml/prepared/v1')
    target=Path('docs/evaluation/url-simple-baseline-test.json')
    if target.exists():raise SystemExit('Frozen baseline report already exists')
    raw=(prepared/'url.csv').read_bytes();frozen=json.loads((prepared/'url-frozen.json').read_text());assert hashlib.sha256(raw).hexdigest()==frozen['prepared_sha256']
    rows=list(csv.DictReader(raw.decode().splitlines()));train=[r for r in rows if r['split']=='train'];test=[r for r in rows if r['split']=='test']
    selection=json.loads((folder/'url-selection.json').read_text());threshold=selection['candidates']['scaled-logistic']['threshold']
    model=Pipeline([('scale',StandardScaler()),('classifier',LogisticRegression(max_iter=1500,class_weight='balanced',random_state=SEED))])
    model.fit([url_features(r['text']) for r in train],[r['label'] for r in train])
    names=list(model.classes_);scores=model.predict_proba([url_features(r['text']) for r in test])[:,names.index('phishing')];pred=np.where(scores>=threshold,'phishing','legitimate')
    report={'threshold_from_frozen_validation_selection':threshold,'test':metrics([r['label'] for r in test],pred,['legitimate','phishing'],'phishing',scores),'selection_unchanged':selection['decision'],'note':'First held-out report for the simple baseline; no reselection or threshold tuning using test results. Data-only forest remains the validation-selected candidate.'}
    target.write_text(json.dumps(report,indent=2));print(json.dumps({'baseline_test_macro_f1':report['test']['macro_f1']}))

if __name__=='__main__':main()
