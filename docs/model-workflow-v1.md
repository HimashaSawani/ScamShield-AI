# Local dataset-to-inference release v1

The supplied archives are used as historical publisher benchmarks, not independently reviewed, contemporary deployment data. [Full inventory](evaluation/dataset-inventory.json) records every CSV column, count, missing value, original label, conflict, grouping decision and SHA256. The raw archives remain unchanged and their bundled Python scripts were not executed. No dataset URL was visited.

Sources and attribution: Sandhya Mishra and Devpriya Soni, 2022, [Mendeley SMS dataset v1](https://data.mendeley.com/datasets/f45bkkt8pr/1), DOI 10.17632/f45bkkt8pr.1; Arvind Prasad and Shalini Chandra, 2024, [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), DOI 10.1016/j.cose.2023.103545. Both publisher pages list CC BY 4.0 (checked 2026-10-23). Cleaned outputs are adaptations: normalized-text deduplication, conflict exclusion and grouped splits, with labels otherwise retained. Original authors do not endorse this app. Publisher labels are not independent analyst adjudications.

## Data and splits

The nested SMS archive contains Dataset_5971.csv: LABEL/TEXT/URL/EMAIL/PHONE, with 5,971 raw records (4,844 ham, 489 spam [466 'spam' / 23 'Spam'], and 638 smishing [616 'Smishing' / 22 'smishing']). Only TEXT is a classifier input. Labels remain three distinct classes. The cleaned corpus has 5,797 rows (4,834 ham, 435 spam, 528 smishing) after duplicate and conflict exclusion: 106 same-label duplicate occurrences (10 ham, 20 spam, 76 smishing) and 34 conflicting normalized-text groups (comprising 68 records: 34 spam and 34 smishing) were excluded. Conflicting groups are entirely excluded rather than voted on (5,971 raw - 106 same-label duplicates - 68 conflicting records = 5,797 clean rows: ham 4,844 - 10 = 4,834; spam 489 - 20 - 34 = 435; smishing 638 - 76 - 34 = 528). Entity/number-masked character template cosine >=0.85 links 952 near-template pairs; transitive components remain within one split. Split counts: train 4,041 (3,396 ham, 280 spam, 365 smishing), validation 882 (714 ham, 66 spam, 102 smishing), test 874 (724 ham, 89 spam, 61 smishing). The grouping vectorizer is used only for deduplication, never as a classifier feature/statistic. Classifier word/character vocabulary, IDF and imbalance weighting are fit on training only. Template grouping is a heuristic and does not prove independent campaigns.

PhiUSIIL contains 235,795 rows and URL plus 55 other columns. Original mapping is **1 legitimate / 0 phishing**, explicitly converted to internal string labels. Recomputed URL features alone are used. FILENAME, supplied domain/length fields, webpage content/title/HTML features, similarity indices and aggregate/target-derived probabilities are excluded. Shared registrable domains (including private PSL boundaries), or IP/unknown-suffix hostnames, stay within one split. After cleaning, 235,365 URLs remain. See inventory for exact duplicates/conflicts and parse exclusions. This grouping prevents same-domain overlap, not all possible cross-domain campaign overlap.

Seed 20261023, group-based approximately 70/15/15 train/validation/test. Actual counts vary with group sizes; all counts are in reports. Splits/manifests were reproduced byte-for-byte in a second preparation run. The 59 HTTP URLs extracted from SMS had zero exact intersections with the URL dataset; datasets were evaluated separately, not combined. Shared/cross-domain campaign review remains necessary before a joint benchmark. Synthetic regressions are separate.

## Measured results and selection

| Candidate | Held-out macro F1 | Positive precision | Positive recall | Decision |
| --- | ---: | ---: | ---: | --- |
| Word + character TF-IDF / Logistic Regression, three SMS classes | 0.873594 | 0.791045 smishing | 0.868852 smishing | Disabled: validation activation gate failed |
| Static URL random forest, validation-selected | 0.996387 | 0.999259 phishing | 0.992131 phishing | Enabled locally for supported named-domain URLs |

SMS test has 724 ham, 89 spam and only 61 smishing: a small historical-source result. Text validation macro F1 0.907429; the threshold 0.40 and plain-model approach were selected on validation, before test reporting. The strong-credential-rules hybrid did not improve validation macro F1, so it was not selected. URL forest validation macro F1 0.995512 exceeds simple scaled-logistic 0.992751; threshold 0.50. The frozen simple baseline test is [reported separately](evaluation/url-simple-baseline-test.json). No selection changes follow test reporting.

Activation gate was positive precision >=0.95, recall >=0.70, nonpositive FPR <=0.02 and >=50 validation examples/class. This is a local source-benchmark gate, not production approval. Reports contain per-class precision/recall/F1, confusion matrices, macro F1, positive FPR, PR average precision, counts and false-positive/missed-positive IDs: [SMS](evaluation/text-report.json), [URL](evaluation/url-report.json). Error IDs resolve to the protected prepared CSV for controlled message inspection; reports avoid republishing message contents.

Rules High/Medium map to a positive screening flag (smishing or phishing); other results abstain. This is a declared proxy, not semantic equivalence between risk and publisher classes. Rules cannot assign ham/spam. SMS rules inconclusive rate is 0.985126; URL rules inconclusive rate 0.981432. The matrices retain abstentions, and positive recall counts abstained positives as missed. Therefore model macro F1 and rules macro F1 are not comparable without considering their different decision coverage/targets.

All cleaned legitimate URLs use HTTPS, versus 48,881 of 100,515 phishing URLs. This is a major source collection correlation; source-benchmark performance may not transfer. HTTPS itself never proves safety. Model negative predictions never produce a verified-safe assessment. Results are uncalibrated; UI does not display classifier scores as probabilities. SMS is predominantly English but includes unadjudicated mixed/transliterated examples. No Sinhala, Tamil or Singlish performance is established. No reviewed real screenshot/transcription corpus was found: CER/WER and OCR-induced accuracy remain blocked. Synthetic upload/correction and controlled OCR tests are pipeline verification only.

The live synthetic named-domain sample `https://example.com/about` was flagged by the model despite no rule indicators, producing Medium concern with indicator score 0. This is an operational false-positive warning, not evidence that the example domain is malicious. It demonstrates why the high source-benchmark metric is insufficient for production approval. No thresholds were changed to memorize or suppress this example. Broader independently reviewed ordinary-URL negatives are required before production use.

## Reproduce and freeze

```powershell
.\.venv-release\Scripts\python.exe -m pip install -r backend/requirements.txt -r ml/requirements.txt -r backend/requirements-verification.txt
# Choose NEW output paths; existing prepared/test/report files are protected.
.\.venv-release\Scripts\python.exe -m ml.prepare --output ml/prepared/YOUR_VERSION
.\.venv-release\Scripts\python.exe -m ml.train_v1 --prepared ml/prepared/YOUR_VERSION --output ml/artifacts/YOUR_VERSION --version YOUR_VERSION
.\.venv-release\Scripts\python.exe scripts/verify_model_artifacts.py --prepared ml/prepared/YOUR_VERSION --bundle ml/artifacts/YOUR_VERSION
```

The local release is `ml/artifacts/v1-json`, prepared inputs `ml/prepared/v1` (identical CSVs to `v1-audited`). Selection JSON is written before final test inference. Manifests record prepared/test SHA256, IDs and seed. JSON artifact metadata records original label mapping, schema, dependency versions, data hash, scope and associated report. No model is activated by training. An initial JSON export failed on a NumPy integer in vocabulary indices; the serialization conversion was fixed and the identical seed/configuration/splits rerun without tuning. The incomplete `ml/artifacts/v1` folder is not an active release.

## Activate or fall back

Only explicitly configured, locally trained **data-only JSON** is accepted. The operator must pin the manifest SHA256; each artifact is independently checksum-verified, confined to the configured directory and checked against schema/validation eligibility. No pickle/joblib load or model upload endpoint exists. Exact sklearn version is required for TF-IDF reconstruction. Changing a trusted manifest requires a deliberate new pin. Checksums establish integrity relative to this trusted pin, not trust in an arbitrary supplied file.

```powershell
$env:SCAMSHIELD_MODEL_DIR = 'D:\ScamShield AI\ml\artifacts\v1-json'
$env:SCAMSHIELD_MODEL_MANIFEST_SHA256 = '833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9'
.\.venv-release\Scripts\python.exe -m backend.app.worker
# Set the same two variables for the API, then start it separately:
.\.venv-release\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8015 --no-access-log
```

To run rules-only, remove SCAMSHIELD_MODEL_DIR and SCAMSHIELD_MODEL_MANIFEST_SHA256 from both process environments and restart API/worker. Never run old and new workers together during a release switch. Models are cached per process, so deploy a new versioned directory/pin and restart. For staging, copy the approved bundle into `infra/models`, set directory `/models`, pin its manifest, and use the read-only shared mount. Keep raw/prepared data out of images. Roll back both environment pin and code/image as a matched release, preserving historical results.

Rules evidence and score remain separate from model predictions. Existing High/Medium concerns cannot be lowered by ham/spam/legitimate predictions. A model phishing flag may raise Inconclusive to Medium, without invented spans or changing the rules indicator score. Scores are never averaged. Model-only concern is explicitly explained. Spam alone is not phishing. IP/unknown-suffix URLs abstain from the model scope; Sinhala/Tamil scripts skip optional text inference; Latin-script language identification remains unverified. Missing, ineligible, corrupt or failed models disclose unavailable/failed coverage and retain rules. No-match plus model-negative remains Inconclusive. Every completed new scan records model mode, predictions and used versions alongside rules version; old results are untouched.

The production JSON estimator reproduced the frozen URL confusion matrix across all 33,660 held-out URLs; [artifact verification](model-artifact-verification.json) includes production-feature latency. These are release parity checks, not independent new evaluation data.
