# Annotation and rules evaluation

There is no adjudicated representative benchmark in this repository. Synthetic regression fixtures test software, not detection accuracy. [Publisher research](dataset-source-review.md) identifies candidates without inventing labels.

Use [collection-template.csv](../ml/data/collection-template.csv), which contains headers only. Store private messages with access controls, consent, purpose/retention and redaction review. Consistently redact names, accounts, phone numbers, codes and URL paths without removing the mechanism being reviewed. Keep the protected source mapping separately. Public data also requires privacy/license review. Never collect usable passwords or OTPs.

- **Scam:** evidence supports deception, credential theft, fraudulent payment or another fraudulent objective. Record the mechanism. Unwanted promotion alone is insufficient.
- **Legitimate:** context and trustworthy provenance support an authorized ordinary message. No detector match is not legitimacy evidence. Promotional spam must not automatically become financial fraud.
- **Uncertain:** missing context, disputed intent, unverifiable source or reviewer disagreement; explain in annotation_reason. Preserve these records in evaluation, excluding them from binary precision/recall denominators.

Two reviewers should label independently without predictions, then adjudicate. Record reviewer IDs, source/date/record ID, language, category, permission/license, reason, campaign/template groups and consent reference. Set annotation_status=adjudicated only after review; Uncertain can be adjudicated uncertainty. Feedback and analyst decisions remain separate application records, not automatically trusted labels. Use data_origin=observed unless representativeness is established; generated data must remain synthetic.

Deduplicate normalized exact text; group related campaigns/templates within one split. The validator rejects exact duplicates and cross-split campaign IDs, normalized templates and template similarity >=0.90. This heuristic cannot prove semantic independence; manually review candidates and consider source/time holdouts. Keep synthetic fixtures outside real evaluation.

Freeze a versioned reviewed corpus before assessing it:

```powershell
python -m ml.evaluation.evaluate_rules private/reviewed-v1.csv --manifest private/test-v1.json --freeze-test
python -m ml.evaluation.evaluate_rules private/reviewed-v1.csv --manifest private/test-v1.json --output private/rules-v1.json
```

Manifest/report paths are exclusive. The manifest hashes all held-out fields; changed held-out text/labels/provenance fail verification. This is a reproducibility guard, not access control. Hide the final test from rule authors, log changes, and obtain a new independent holdout after test-driven tuning. The report also records a full input digest.

High/Medium become Scam flags; other results abstain. No-match never becomes a Legitimate decision. Reports include composition, a 3x3 matrix, precision/recall/F1, false-positive IDs, explicit false negatives, missed Scams including abstentions, inconclusive rate and decision coverage. Recall counts abstained Scams as missed. Uncertain truth is excluded from binary metrics. Precision is unavailable without legitimate controls. English/Sinhala/Tamil/Singlish are always listed, including zero counts. Fewer than 100 examples or 20 of either known class is insufficient/pilot; passing these counts does not guarantee statistical adequacy or representativeness. Error IDs enable controlled review without copying raw messages into reports.

Local median/p95/max rule latency and environment are recorded; this is not network/production capacity. Optional `--compare` fits character TF-IDF + Logistic Regression on train only and selects a decision-function threshold on validation only; both known classes are required there. It reports identical held-out metrics. The combined diagnostic requires positive agreement; other outcomes abstain. Assess its precision/coverage tradeoff without assuming improvement. No calibration/probability claim or API model activation occurs.

`python scripts/verify_rules_evaluator.py` validates the workflow with explicitly synthetic temporary fixtures, including optional comparison. This cannot replace a reviewed corpus. The existing training validator remains binary by default; this evaluator additionally supports Uncertain.
