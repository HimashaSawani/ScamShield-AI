# Dataset card, annotation guide, model card

## Dataset

No real dataset is bundled. `ml/data/schema.csv` is a header-only template. Store consented/licensed examples with record ID, original redacted text, language, label, category, provenance/source date, campaign group, annotation status and frozen split. Track license and consent evidence outside public source control. Keep unredacted source data access-controlled and do not commit private messages.

Labels: Scam, Legitimate, Uncertain. Categories: bank impersonation, delivery, fake jobs, investment, prize/reward, credential/OTP theft. Use Uncertain when sender context is missing; do not infer a scam only from language or spelling. Two annotators should label a subset independently; adjudicate disagreement and record rationale. Only adjudicated examples can enter baseline binary training. Keep Uncertain cases for separate abstention evaluation.

Remove exact and near duplicates before frozen train/validation/test assignment. Keep each campaign/template group within one split and consider time-based holdouts. Fit text preprocessing only on train. Threshold selection uses validation only. Never tune on final test results. Synthetic augmentation is allowed in training with explicit provenance; it cannot substantiate a real-world test accuracy claim.

## Current detector card

Version `rules-1.1.0`: clause-scoped credential-request/context rules plus other text indicators and static URL structure. Scores are capped sums of distinct indicator weights, not probabilities. High ≥60, Medium ≥25, otherwise Inconclusive; no new Low labels are assigned without a verified-safe evidence channel. Credential disclosure weighs 45; urgency remains 20, making their combination High/65. Protective and educational context is local rather than a global bypass. Rules still have lexical/context limitations and can produce false positives/negatives. No calibrated confidence, verified sender identity or live URL reputation is available. See detection-policy.md; historical rules-1.0.0 results are preserved.

English, Sinhala, Tamil and Singlish patterns exist but are experimental. Smoke tests demonstrate that selected expressions match, not that these languages are reliably supported. Tesseract requires installed language data; visual quality, mixed scripts and URL recognition require benchmarking on real screenshots. Always review extracted text.

## Training and evaluation

```powershell
python -m pip install -r ml/requirements.txt
python ml/training/train.py path/to/frozen-dataset.csv --output ml/artifacts/baseline-v1
```

The pipeline trains character TF-IDF + Logistic Regression, checks required labels/provenance/dates, duplicates and campaign/template/near-duplicate leakage, selects thresholds on validation, and saves artifacts. Evaluation reports precision/recall/F1, trapezoidal PR-AUC, average precision, confusion matrices, language counts/insufficient-evidence conclusions, category counts/metrics where estimable and inference latency. Automated near-duplicate detection is heuristic; manual source/template audit remains necessary. Synthetic held-out evaluation requires an explicit flag and is labeled as a smoke test. The artifact is not automatically activated in the API. Do not load untrusted joblib files. Abstention coverage, calibration and language-specific failure review still need representative data before integration. See data-collection-checklist.md.

Current evaluation: **not available**; no representative test set has been supplied. Model comparison, URL classifier, combined model and multilingual transformer benchmarks remain outstanding.
# Current supplied-data release candidate

See [model/data workflow v1](model-workflow-v1.md), [archive inventory](evaluation/dataset-inventory.json), [text report](evaluation/text-report.json), [URL report](evaluation/url-report.json) and [v1 checklist](v1-checklist.md). These supersede earlier no-dataset/no-trained-artifact statements below. Raw archives are unchanged; spam/ham/smishing remain separate. Text activation failed validation. The static URL forest passed the local source-benchmark gate and is enabled with an integrity-pinned data-only JSON manifest. Production/multilingual validity and calibration remain unestablished. No real OCR quality corpus exists locally.

