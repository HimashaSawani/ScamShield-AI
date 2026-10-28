"""Train, evaluate, and compare URL model candidate v2.

Addresses domain shift by incorporating leakage-safe, domain-grouped
benign deep-path URLs into training and validation with the enhanced
url-static-2 feature schema, while evaluating on untouched test splits.
"""
import argparse
from collections import Counter
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import statistics
import time

import numpy as np
import sklearn
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import classification_report, f1_score, average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))

from backend.app.detection import analyze, VERSION as RULES_VERSION
from backend.app.model_features import url_features, URL_SCHEMA_V2, URL_FEATURES_V2
from scripts.reproduce_url_path_domain_shift import BENIGN_EVALUATION_URLS

SEED = 20261023

def digest(data):
    return hashlib.sha256(data).hexdigest()

def metrics(y, pred, classes, positive, scores=None):
    y = np.array(y)
    pred = np.array(pred)
    known = pred != 'Inconclusive'
    binary = y == positive
    flag = pred == positive
    fp = int(sum(flag & ~binary))
    tp = int(sum(flag & binary))
    fn = int(sum(~flag & binary))
    tn = int(sum(~flag & ~binary))
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    
    report = {
        'count': len(y),
        'class_counts': dict(Counter(y.tolist())),
        'per_class': classification_report(y, pred, labels=classes, output_dict=True, zero_division=0),
        'macro_f1': float(f1_score(y, pred, labels=classes, average='macro', zero_division=0)),
        'confusion_matrix': {
            'rows': classes,
            'columns': classes + ['Inconclusive'],
            'values': [[int(sum((y == a) & (pred == b))) for b in classes + ['Inconclusive']] for a in classes]
        },
        'positive': positive,
        'positive_precision': p,
        'positive_recall': r,
        'positive_f1': f1,
        'false_positive_rate': fpr,
        'false_positives': fp,
        'false_negatives_including_abstention': fn,
        'inconclusive_rate': float(1.0 - known.mean()),
        'decision_coverage': float(known.mean())
    }
    if scores is not None and len(set(binary)) > 1:
        report['average_precision_PR_AUC'] = float(average_precision_score(binary, scores))
        try:
            report['roc_auc'] = float(roc_auc_score(binary, scores))
        except Exception:
            pass
    return report

def export_model(model):
    if isinstance(model, Pipeline):
        scaler = model.named_steps['scaler']
        clf = model.named_steps['clf']
        return {
            'type': 'numeric-logistic',
            'classes': clf.classes_.tolist(),
            'mean': scaler.mean_.tolist(),
            'scale': scaler.scale_.tolist(),
            'coef': clf.coef_.tolist(),
            'intercept': clf.intercept_.tolist()
        }
    return {
        'type': 'numeric-forest',
        'classes': model.classes_.tolist(),
        'trees': [
            {
                'left': t.tree_.children_left.tolist(),
                'right': t.tree_.children_right.tolist(),
                'feature': t.tree_.feature.tolist(),
                'threshold': t.tree_.threshold.tolist(),
                'value': t.tree_.value[:, 0, :].tolist()
            }
            for t in model.estimators_
        ]
    }

def main():
    print("=" * 80)
    print("TRAINING AND EVALUATING SCAMSHIELD URL MODEL CANDIDATE V2")
    print(f"Feature Schema: {URL_SCHEMA_V2} ({len(URL_FEATURES_V2)} features)")
    print("=" * 80)
    
    # 1. Load PhiUSIIL data
    csv_path = ROOT / 'ml' / 'prepared' / 'v1' / 'url.csv'
    rows = list(csv.DictReader(csv_path.open(encoding='utf-8', newline='')))
    parts = {s: [r for r in rows if r['split'] == s] for s in ['train', 'validation', 'test']}
    
    # 2. Load Benign Deep-Path Data
    deep_path_file = ROOT / 'ml' / 'data' / 'benign_deep_paths.json'
    deep_paths = json.loads(deep_path_file.read_text(encoding='utf-8'))
    
    rng = random.Random(SEED)
    phi_train_legit = [r for r in parts['train'] if r['label'] == 'legitimate']
    phi_train_phish = [r for r in parts['train'] if r['label'] == 'phishing']
    rng.shuffle(phi_train_legit)
    rng.shuffle(phi_train_phish)
    
    # Training composition: 6,000 PhiUSIIL legit + 953 deep legit (~6,953 legit); 6,000 phishing
    selected_train = phi_train_legit[:6000] + phi_train_phish[:6000] + deep_paths['train']
    rng.shuffle(selected_train)
    
    phi_val_legit = [r for r in parts['validation'] if r['label'] == 'legitimate']
    phi_val_phish = [r for r in parts['validation'] if r['label'] == 'phishing']
    rng.shuffle(phi_val_legit)
    rng.shuffle(phi_val_phish)
    # Validation composition: 2,000 PhiUSIIL legit + 560 deep legit (~2,560 legit); 2,000 phishing
    selected_val = phi_val_legit[:2000] + phi_val_phish[:2000] + deep_paths['validation']
    rng.shuffle(selected_val)
    
    print(f"Training dataset composition:")
    print(f"  Legitimate: {sum(1 for r in selected_train if r['label']=='legitimate')} (including {len(deep_paths['train'])} deep paths)")
    print(f"  Phishing:   {sum(1 for r in selected_train if r['label']=='phishing')}")
    print(f"Validation dataset composition:")
    print(f"  Legitimate: {sum(1 for r in selected_val if r['label']=='legitimate')} (including {len(deep_paths['validation'])} deep paths)")
    print(f"  Phishing:   {sum(1 for r in selected_val if r['label']=='phishing')}")

    def extract_features_list(items, desc=""):
        X = []
        t0 = time.perf_counter()
        for idx, r in enumerate(items):
            X.append(url_features(r['text'], schema=URL_SCHEMA_V2))
            if (idx + 1) % 2500 == 0 or idx + 1 == len(items):
                print(f"  [{desc}] Extracted {idx + 1}/{len(items)} ({time.perf_counter()-t0:.1f}s)")
        return np.array(X, dtype=np.float32)

    print("\nExtracting url-static-2 features sequentially...")
    X_train = extract_features_list(selected_train, "Train")
    y_train = np.array([r['label'] for r in selected_train])
    
    X_val = extract_features_list(selected_val, "Validation")
    y_val = np.array([r['label'] for r in selected_val])

    classes = ['legitimate', 'phishing']
    positive = 'phishing'
    pos_idx = classes.index(positive)
    
    candidates = {
        'extra-trees-64': ExtraTreesClassifier(
            n_estimators=64, max_depth=14, min_samples_leaf=3, class_weight='balanced', random_state=SEED, n_jobs=2
        ),
        'random-forest-64': RandomForestClassifier(
            n_estimators=64, max_depth=14, min_samples_leaf=3, class_weight='balanced', random_state=SEED, n_jobs=2
        ),
        'scaled-logistic': Pipeline([
            ('scaler', StandardScaler()),
            ('clf', LogisticRegression(max_iter=1000, class_weight='balanced', random_state=SEED))
        ])
    }
    
    selection = {}
    fitted = {}
    
    print("\nFitting and tuning candidates on validation split:")
    for name, model in candidates.items():
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        fit_time = time.perf_counter() - t0
        prob = model.predict_proba(X_val)
        names = list(model.classes_)
        pi = names.index(positive)
        
        # Grid search over thresholds to identify those meeting release gates:
        # Precision >= 95.0%, FPR <= 2.0%, Recall >= 70.0%
        best_candidate = None
        for threshold in [0.70, 0.75, 0.80, 0.82, 0.85, 0.88, 0.90, 0.92, 0.95]:
            pred = np.where(prob[:, pi] >= threshold, positive, 'legitimate')
            m = metrics(y_val, pred, classes, positive, prob[:, pi])
            passes = (m['positive_precision'] >= 0.95 and m['false_positive_rate'] <= 0.02 and m['positive_recall'] >= 0.70)
            score = (1 if passes else 0, m['macro_f1'])
            if best_candidate is None or score > best_candidate[0]:
                best_candidate = (score, threshold, m, passes)
            print(f"    [{name:16s}] thr={threshold:.2f} | Prec={m['positive_precision']*100:6.2f}% | Rec={m['positive_recall']*100:6.2f}% | FPR={m['false_positive_rate']*100:5.2f}% | Gate={'PASS' if passes else 'FAIL'}")
            
        selection[name] = {
            'threshold': best_candidate[1],
            'validation': best_candidate[2],
            'passes_gate': best_candidate[3],
            'training_seconds': fit_time
        }
        fitted[name] = model

    # Select the best model that passes the release gate:
    eligible = [n for n in selection if selection[n]['passes_gate']]
    if eligible:
        chosen = max(eligible, key=lambda n: selection[n]['validation']['macro_f1'])
    else:
        chosen = max(selection, key=lambda n: selection[n]['validation']['macro_f1'])
        
    best_model = fitted[chosen]
    threshold = selection[chosen]['threshold']
    val_gate = selection[chosen]['validation']
    passes_gate = selection[chosen]['passes_gate']
    
    print("\n" + "=" * 80)
    print(f"CHOSEN ESTIMATOR: {chosen}")
    print(f"Threshold: {threshold:.2f}")
    print(f"Validation Precision: {val_gate['positive_precision']*100:.2f}% (Req >= 95.0%)")
    print(f"Validation Recall:    {val_gate['positive_recall']*100:.2f}% (Req >= 70.0%)")
    print(f"Validation FPR:       {val_gate['false_positive_rate']*100:.2f}% (Req <= 2.0%)")
    print(f"Validation Gate:      {'PASS' if passes_gate else 'FAIL'}")
    print("=" * 80)
    
    pi = list(best_model.classes_).index(positive)
    
    # Evaluate on Untouched Benchmark Splits:
    # 1. Benign Deep-Path Test Set (450 held-out URLs)
    X_test_deep = np.array([url_features(r['text'], schema=URL_SCHEMA_V2) for r in deep_paths['test']], dtype=np.float32)
    prob_deep = best_model.predict_proba(X_test_deep)
    pred_deep = np.where(prob_deep[:, pi] >= threshold, positive, 'legitimate')
    deep_fps = int(sum(pred_deep == positive))
    deep_fp_rate = deep_fps / len(deep_paths['test'])
    print(f"\n1. Evaluation on {len(deep_paths['test'])} Held-Out Benign Deep Paths (Test Domains):")
    print(f"   False Positives: {deep_fps} / {len(deep_paths['test'])} ({deep_fp_rate*100:.2f}%)")
    
    # 2. Reproduction 25-case Benign Stress Set
    stress_urls = [item['url'] for item in BENIGN_EVALUATION_URLS]
    X_stress = np.array([url_features(u, schema=URL_SCHEMA_V2) for u in stress_urls], dtype=np.float32)
    prob_stress = best_model.predict_proba(X_stress)
    pred_stress = np.where(prob_stress[:, pi] >= threshold, positive, 'legitimate')
    stress_fps = int(sum(pred_stress == positive))
    print(f"\n2. Evaluation on 25-Case Reproduction Benign Stress Set:")
    print(f"   False Positives: {stress_fps} / {len(stress_urls)} ({stress_fps/len(stress_urls)*100:.2f}%)")
    for u, p, pr in zip(stress_urls, pred_stress, prob_stress[:, pi]):
        flag = "[FP]" if p == positive else "[OK]"
        print(f"     {flag} {u} -> score: {pr:.3f}")

    # 3. Phishing Recall on 115 Synthetic Suspicious URLs
    with open(ROOT / 'docs' / 'synthetic_evaluation_dataset.json', 'r', encoding='utf-8') as f:
        synth = json.load(f)
    suspicious_urls = [c['url'] for c in synth['suspicious_urls']]
    X_susp = np.array([url_features(u, schema=URL_SCHEMA_V2) for u in suspicious_urls], dtype=np.float32)
    prob_susp = best_model.predict_proba(X_susp)
    pred_susp = np.where(prob_susp[:, pi] >= threshold, positive, 'legitimate')
    susp_recalled = int(sum(pred_susp == positive))
    print(f"\n3. Phishing Recall on 115 Synthetic Suspicious URLs:")
    print(f"   Detected: {susp_recalled} / {len(suspicious_urls)} ({susp_recalled/len(suspicious_urls)*100:.2f}%)")

    # 4. Untouched 33,660 PhiUSIIL Test Split
    print(f"\n4. Evaluation on Untouched PhiUSIIL Test Split ({len(parts['test'])} URLs)...")
    X_test_phi = np.array([url_features(r['text'], schema=URL_SCHEMA_V2) for r in parts['test']], dtype=np.float32)
    prob_phi = best_model.predict_proba(X_test_phi)
    pred_phi = np.where(prob_phi[:, pi] >= threshold, positive, 'legitimate')
    phi_metrics = metrics([r['label'] for r in parts['test']], pred_phi, classes, positive, prob_phi[:, pi])
    print(f"   Test Precision: {phi_metrics['positive_precision']*100:.2f}%")
    print(f"   Test Recall:    {phi_metrics['positive_recall']*100:.2f}%")
    print(f"   Test FPR:       {phi_metrics['false_positive_rate']*100:.4f}% ({phi_metrics['false_positives']} FPs)")

    # 5. Latency Benchmark
    timings = []
    sample_urls = [r['text'] for r in parts['test'][:100]]
    for u in sample_urls:
        t0 = time.perf_counter()
        _ = url_features(u, schema=URL_SCHEMA_V2)
        _ = best_model.predict_proba(np.array([_], dtype=np.float32))
        timings.append((time.perf_counter() - t0) * 1000)
    median_lat = statistics.median(timings)
    p95_lat = sorted(timings)[94]
    print(f"\n5. Inference Latency (Feature Extraction + Model Prediction):")
    print(f"   Median: {median_lat:.2f} ms | p95: {p95_lat:.2f} ms")

    # Export candidate bundle to ml/artifacts/v2-json
    out_dir = ROOT / 'ml' / 'artifacts' / 'v2-json'
    out_dir.mkdir(parents=True, exist_ok=True)
    
    model_artifact = export_model(best_model) | {
        'kind': 'url',
        'version': 'scamshield-url-v2',
        'threshold': threshold,
        'hybrid': False,
        'validation_eligible': passes_gate,
        'label_mapping': {'1': 'legitimate', '0': 'phishing'},
        'report_file': 'url-report.json',
        'feature_schema': URL_SCHEMA_V2,
        'url_features': URL_FEATURES_V2,
        'scope': 'Source-benchmark trained with leakage-safe benign deep paths; not calibrated probability or sender identity',
        'environment': {
            'python': platform.python_version(),
            'sklearn': sklearn.__version__,
            'numpy': np.__version__
        }
    }
    
    model_json = json.dumps(model_artifact, separators=(',', ':'))
    model_path = out_dir / 'url-model.json'
    model_path.write_text(model_json, encoding='utf-8')
    model_hash = digest(model_path.read_bytes())
    
    # Copy text model (disabled) as required by manifest
    text_model_v1 = ROOT / 'ml' / 'artifacts' / 'v1-json' / 'text-model.json'
    text_model_dest = out_dir / 'text-model.json'
    text_model_dest.write_bytes(text_model_v1.read_bytes())
    text_hash = digest(text_model_dest.read_bytes())
    
    manifest = {
        'format': 1,
        'artifacts': {
            'url': {
                'file': 'url-model.json',
                'sha256': model_hash,
                'validation_eligible': passes_gate
            },
            'text': {
                'file': 'text-model.json',
                'sha256': text_hash,
                'validation_eligible': False
            }
        },
        'no_pickle': 'Data-only JSON; no executable object deserialization'
    }
    
    manifest_path = out_dir / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    manifest_hash = digest(manifest_path.read_bytes())
    
    report = {
        'candidate_version': 'scamshield-url-v2',
        'chosen_estimator': chosen,
        'threshold': threshold,
        'validation_gate': val_gate,
        'passes_gate': passes_gate,
        'phiusiil_test_metrics': {
            'total_tested': len(parts['test']),
            'precision': phi_metrics['positive_precision'],
            'recall': phi_metrics['positive_recall'],
            'fpr': phi_metrics['false_positive_rate'],
            'false_positives': phi_metrics['false_positives'],
            'false_negatives': phi_metrics['false_negatives_including_abstention']
        },
        'deep_path_test_results': {
            'total_tested': len(deep_paths['test']),
            'false_positives': deep_fps,
            'false_positive_rate': deep_fp_rate
        },
        'stress_set_results': {
            'total_tested': len(stress_urls),
            'false_positives': stress_fps,
            'false_positive_rate': stress_fps / len(stress_urls)
        },
        'synthetic_phishing_recall': {
            'total_tested': len(suspicious_urls),
            'detected': susp_recalled,
            'recall': susp_recalled / len(suspicious_urls)
        },
        'latency_ms': {'median': median_lat, 'p95': p95_lat},
        'manifest_sha256': manifest_hash,
        'model_sha256': model_hash
    }
    
    # Write url-report.json matching schema for verify_model_artifacts
    v2_report = {
        'candidate_version': 'scamshield-url-v2',
        'chosen_estimator': chosen,
        'threshold': threshold,
        'feature_schema': URL_SCHEMA_V2,
        'url_features': URL_FEATURES_V2,
        'validation': val_gate,
        'test': {
            'model': phi_metrics,
            'deep_paths': {
                'total': len(deep_paths['test']),
                'false_positives': deep_fps,
                'fpr': deep_fp_rate
            },
            'stress_set': {
                'total': len(stress_urls),
                'false_positives': stress_fps,
                'fpr': stress_fps / len(stress_urls)
            },
            'synthetic_phishing': {
                'total': len(suspicious_urls),
                'detected': susp_recalled,
                'recall': susp_recalled / len(suspicious_urls)
            }
        },
        'latency_ms': {'median': median_lat, 'p95': p95_lat}
    }
    (out_dir / 'url-report.json').write_text(json.dumps(v2_report, indent=2), encoding='utf-8')
    
    report_path = out_dir / 'url-candidate-evaluation.json'
    report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    docs_report_path = ROOT / 'docs' / 'url_candidate_v2_comparison.json'
    docs_report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    
    print("\n" + "=" * 80)
    print("V2 ARTIFACT BUNDLE EXPORT COMPLETE:")
    print(f"  Quality Gate:     {'PASS' if passes_gate else 'FAIL'}")
    print(f"  Manifest SHA256:  {manifest_hash}")
    print(f"  URL Model SHA256: {model_hash}")
    print(f"  Output Directory: {out_dir}")
    print("=" * 80)

if __name__ == '__main__':
    main()
