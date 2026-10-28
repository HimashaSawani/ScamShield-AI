# Representative evaluation data required

Production model evaluation is blocked by missing representative labeled data. Synthetic fixtures exercise code only.

- Obtain written permission/license for each source. Record collection purpose, jurisdiction, consent/retention rules and source date; do not commit private messages.
- Recruit examples across English, Sinhala, Tamil and Singlish, including mixed scripts and locally relevant banking, delivery, job, investment, prize and credential requests. Include legitimate warnings, OTP notices, negation and borderline cases.
- Redact identifying details consistently. Keep access-controlled originals only when consent permits; track redaction transformations and exclude raw phone/account identifiers from exported evaluation artifacts.
- Fill every schema field, including template_group and data_origin. Use `representative` only when provenance supports that designation; the validator cannot verify a source's truthfulness or license.
- Use two independent annotators for a meaningful subset. Record disagreements and adjudication rationale. Keep Uncertain examples in a separate adjudication/abstention pool; do not silently convert them to binary labels.
- Deduplicate, review near-duplicate flags, and group related campaigns/templates before freezing splits. Consider source/time holdouts. Automated similarity rules are conservative heuristics, not a complete leakage guarantee.
- Freeze train/validation/test manifests and hashes. Fit preprocessing on train, choose thresholds on validation once, and evaluate test without retuning. Synthetic data belongs in explicitly marked training augmentation; synthetic held-out results require `--allow-synthetic-evaluation` and are smoke tests only.
- Plan representative sample sizes per language and category before collection. The pipeline marks fewer than 100 held-out examples or fewer than 20 per label as insufficient evidence; passing that screen alone does not establish statistical adequacy or deployability. Report confidence intervals and failure analysis during release review.
- Benchmark OCR separately using consented screenshots: blur, rotation, mixed scripts, dark mode, cropping, multiple messages and URL recognition. Measure recognition errors and downstream detection changes after user correction.
- Review test precision/recall/F1, PR-AUC, average precision, confusion matrices, language counts, category coverage, abstention coverage, latency and calibration. This baseline does not evaluate calibration, so its UI must continue to avoid model probabilities.
