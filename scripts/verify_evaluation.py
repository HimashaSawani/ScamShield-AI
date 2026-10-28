"""Exercise training/evaluation with explicitly synthetic fixtures only."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.tests.test_dataset import rows

with tempfile.TemporaryDirectory(prefix='scamshield-evaluation-') as folder:
    path=Path(folder);dataset=path/'synthetic.csv';records=rows()
    with dataset.open('w',newline='',encoding='utf-8') as file:
        writer=csv.DictWriter(file,fieldnames=list(records[0]));writer.writeheader();writer.writerows(records)
    result=subprocess.run([sys.executable,'ml/training/train.py',str(dataset),'--output',str(path/'model'),'--allow-synthetic-evaluation'],cwd=ROOT,capture_output=True,text=True)
    if result.returncode:
        raise RuntimeError(result.stderr)
    report=json.loads((path/'model'/'evaluation.json').read_text())
    assert report['validation_checks']['synthetic_evaluation']
    assert report['language']['Tamil']['conclusion']=='insufficient evidence'
    assert report['latency_ms']['samples']==2
    assert (path/'model'/'model.joblib').is_file()
    print('PASS: synthetic-only pipeline smoke test; saved artifact, held-out metrics, language counts and latency. No real-world accuracy claim.')
