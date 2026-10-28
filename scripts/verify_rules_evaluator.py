"""Synthetic-only rules/ML evaluation workflow smoke test; not accuracy evidence."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.tests.test_rules_evaluator import fixtures

with tempfile.TemporaryDirectory(prefix='scamshield-rules-eval-') as tmp:
    folder=Path(tmp);dataset=folder/'synthetic.csv';records=fixtures()
    with dataset.open('w',encoding='utf-8',newline='') as file:
        writer=csv.DictWriter(file,fieldnames=sorted(set().union(*(r.keys() for r in records))));writer.writeheader();writer.writerows(records)
    command=[sys.executable,'ml/evaluation/evaluate_rules.py',str(dataset),'--manifest',str(folder/'frozen.json'),'--allow-synthetic-smoke']
    subprocess.run(command+['--freeze-test'],cwd=ROOT,check=True)
    subprocess.run(command+['--output',str(folder/'report.json'),'--compare'],cwd=ROOT,check=True)
    report=json.loads((folder/'report.json').read_text())
    assert report['rules']['overall']['count']==3
    assert report['rules']['languages']['Tamil']['count']==0
    assert report['comparison']['train_count']==2 and report['comparison']['validation_count']==2
    assert 'SYNTHETIC' in report['evaluation_kind']
    assert report['rules']['overall']['confusion_matrix']['prediction_columns'][-1]=='Inconclusive'
    print('PASS: frozen-test rules evaluator, abstention accounting, language counts, latency and optional ML/agreement comparison. Synthetic fixtures only; no accuracy claim or model activation.')
