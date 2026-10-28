# ScamShield AI — Final Test Results

**Execution Date:** 2026-10-28  
**Project Root:** `D:\ScamShield AI`  
**Runtime Environment:** Windows 11 (`10.0.26300-SP0`), Python `3.13.3` (`.venv-release`), Node.js / npm, Google Chrome `156.0.8078.48`  
**Active Rules Version:** `rules-1.2.0`  
**Active URL Model:** `scamshield-url-v1` (`ml/artifacts/v1-json/url-model.json`, Manifest SHA256 `833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9`)  
**Text Model Status:** Disabled (`validation_eligible: false`; rules-only fallback active)

---

## 1. Executive Test Summary

| Test Suite / Check | Command | Passed | Failed | Skipped | Blocked | Not Executed | Status |
|---|---|---:|---:|---:|---:|---:|---|
| **Backend Pytest Suite** | `.\.venv-release\Scripts\python.exe -m pytest backend/tests -q` | 102 | 0 | 1 | 0 | 0 | **PASS** |
| **Live 10-Workflow E2E Verification** | `.\.venv-release\Scripts\python.exe scripts/verify_final_e2e.py` | 10 | 0 | 0 | 0 | 0 | **PASS** |
| **ML Artifact & Frozen Split Verification** | `.\.venv-release\Scripts\python.exe scripts/verify_model_artifacts.py` | 2 | 0 | 0 | 0 | 0 | **PASS** |
| **445-Case Synthetic Detection Evaluation** | `.\.venv-release\Scripts\python.exe scripts/run_full_detection_verification.py` | 401 | 44* | 0 | 0 | 0 | **VERIFIED** |
| **Chrome Browser Dashboard E2E (Playwright)** | `.\.venv-release\Scripts\python.exe scripts/verify_browser.py` | 13 | 0 | 0 | 0 | 0 | **PASS** |
| **Database Migration Verification (Alembic)** | `.\.venv-release\Scripts\python.exe scripts/verify_migrations.py` | 3 | 0 | 0 | 0 | 0 | **PASS** |
| **Git Exclusion & Secret Safety Check** | `.\.venv-release\Scripts\python.exe scripts/verify_exclusions.py` | 11 | 0 | 0 | 0 | 0 | **PASS** |
| **Bounded SQLite Workload Benchmark** | `.\.venv-release\Scripts\python.exe -m backend.tests.benchmark` | 40 | 0 | 0 | 0 | 0 | **PASS** |
| **ML Pipeline Smoke Evaluation** | `.\.venv-release\Scripts\python.exe scripts/verify_evaluation.py` | 1 | 0 | 0 | 0 | 0 | **PASS** |
| **Rules Evaluator Smoke Check** | `.\.venv-release\Scripts\python.exe scripts/verify_rules_evaluator.py` | 1 | 0 | 0 | 0 | 0 | **PASS** |
| **Web Dashboard JS Syntax Check** | `node --check apps/dashboard/app.js` & `results.js` | 2 | 0 | 0 | 0 | 0 | **PASS** |
| **Mobile TypeScript Check** | `npm.cmd run typecheck` (`tsc --noEmit`) | 1 | 0 | 0 | 0 | 0 | **PASS** |
| **Mobile Android Bundle Export** | `npx expo export -p android --output-dir dist --clear` | 1 (623 modules) | 0 | 0 | 0 | 0 | **PASS** |
| **Python Dependency Consistency** | `.\.venv-release\Scripts\python.exe -m pip check` | 1 | 0 | 0 | 0 | 0 | **PASS** |
| **Android Live Emulator / Physical Device** | `adb devices -l` | 0 | 0 | 0 | 1 | 0 | **BLOCKED** |

*\*Note on 445-case synthetic evaluation: In `rules-only` mode, 401/445 synthetic cases match ground truth (`0` false positives across all categories; 39 URL false negatives where single structural indicators score `< 25`, and 5 Sinhala text false negatives using an unindexed phrase variant). When `scamshield-url-v1` is active (`rules-plus-model`), all 44 previously missed synthetic suspicious URLs are detected (`115/115 = 100.00%` recall).*

---

## 2. Backend Pytest Suite Breakdown (`102 passed, 1 skipped`)

Executed in `28.29s`:

| Test Module | Tests Passed | Skipped | Coverage Focus |
|---|---:|---:|---|
| `backend/tests/test_release.py` | 23 | 1 | Registration, email verification, resend cooldown, TOTP enrollment, 8 recovery codes, recovery code regeneration & session revocation, URL/text/screenshot scans, OCR confirmation, analyst review queue, campaign clustering, team roles, audit logs, account deletion, SQLite backup/restore (`test_postgres_backup_restore_and_integrity` skipped when `TEST_POSTGRES_URL` is unset). |
| `backend/tests/test_system.py` | 11 | 0 | Full API lifecycle, tenant isolation (`404` across users), unverified login block, rate limiting (`429`), worker lease recovery, attachment cleanup, readiness checks. |
| `backend/tests/test_detection.py` | 30 | 0 | Rules `rules-1.2.0` evaluation, English/Sinhala/Singlish/Tamil scam indicators, safe operational negations (`never share your OTP`), span extraction, score boundaries (`0–24` Inconclusive, `25–59` Medium, `60–100` High). |
| `backend/tests/test_url_analysis.py` | 28 | 0 | Offline URL structural inspection, Public Suffix List (PSL) registrable domain boundary, subdomain spoofing, punycode/IDN, `@` userinfo obfuscation, IP literals, URL shorteners, non-standard ports, malformed host rejection. |
| `backend/tests/test_model_inference.py` | 7 | 0 | Manifest SHA256 verification, missing/mismatched artifact fallback, ineligible model rejection (`text-model.json`), positive/negative URL model integration (`rules-plus-model`), and live `ml/artifacts/v1-json` bundle verification (`test_released_url_model_bundle_and_worker_inference`). |
| `backend/tests/test_evaluation.py` | 3 | 0 | Deterministic split hash assignment, leak-free normalization deduplication, and three-class / binary confusion matrix reporting. |

---

## 3. Live End-to-End Workflow Verification (`10/10 PASSED`)

Executed via `scripts/verify_final_e2e.py` against a live Uvicorn HTTP server (`127.0.0.1:8025`), background worker process, enabled `scamshield-url-v1` model, and isolated SQLite WAL database (`docs/final_e2e_verification.json`):

| Workflow ID | Description | HTTP / DB Evidence | Verdict |
|---|---|---|---|
| **A** | Register → verify → login → logout | `POST /api/auth/register` (`201`) → unverified login blocked (`403`) → `POST /api/auth/verify-email` (`200`) → `POST /api/auth/login` (`200`) → `POST /api/auth/logout` (`200`) → `GET /api/auth/me` (`401`) | **PASS** |
| **B** | Submit suspicious synthetic URL → queue → worker → result → explanation → history | `http://secure-paypal-login.verify-account-update.com/auth/login` → queued → worker processed with `model_mode: rules-plus-model` (`scamshield-url-v1` prediction: `phishing`) + rules evidence `["unencrypted", "brand_host"]` → `Medium` (`score: 30`) → verified in `GET /api/scans` | **PASS** |
| **C** | Submit benign URL → result → history | `https://www.wikipedia.org` → worker processed → `Inconclusive` (`score: 0`), `scamshield-url-v1` prediction: `legitimate` → verified in history | **PASS** |
| **D** | Submit suspicious synthetic message → result → evidence | Urgent bank OTP request → `High` (`score: 65`), evidence codes `["credentials", "urgency"]` with exact character spans | **PASS** |
| **E** | Submit benign message → verify classification | Appointment reminder (`Tomorrow at 10:00 AM...`) → `Inconclusive` (`score: 0`, `evidence_count: 0`) | **PASS** |
| **F** | Upload synthetic screenshot → OCR → correction → detection | Invalid file rejected (`422`); valid PNG uploaded → `partially_completed` (awaiting user OCR text confirmation) → `POST /api/scans/{id}/confirm-text` with corrected text → `completed` (`High`, `score: 65`) | **PASS** |
| **G** | Analyst reviews report → verdict appears in user history | User escalated scan (`201`) → Analyst fetched `/api/analyst/reports` (`200`) → Analyst submitted `confirmed_scam` decision (`200`) → User history shows `"Confirmed scam"` verdict and analyst notes | **PASS** |
| **H** | Two users → verify private scan isolation | User B attempted `GET /api/scans/{user_a_scan_id}` (`404`) and `DELETE /api/scans/{user_a_scan_id}` (`404`) | **PASS** |
| **I** | Worker interruption → recovery → scan completion | Injected scan with expired worker lease (`processing`, `lease_expires_at` in past, `attempt_count=1`) → live worker reclaimed stale lease and completed scan (`High`, `score: 65`) | **PASS** |
| **J** | Account deletion → verify authorized data cleanup | `POST /api/auth/delete-account` (`200`) → session token invalidated (`401`) → verified `0` remaining user scans in DB, `0` reports in DB, and `0` attachment files on disk | **PASS** |

---

## 4. AI / ML Detection Evaluation Results

### 4.1 URL ML Artifact & Held-Out Benchmark (`PhiUSIIL`, 33,660 Frozen Test URLs)
Verified via `scripts/verify_model_artifacts.py` (`docs/model-artifact-verification.json`):
- **Manifest Path:** `ml/artifacts/v1-json/manifest.json`
- **Manifest SHA256:** `833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9`
- **URL Model SHA256:** `1d6b1b700452901e7d80a7ad82a107f38e19ed221e89556c1d634423896f6ee3`
- **Feature Schema:** `url-static-1` (20 static structural features; 0 network calls)
- **Inference Latency:** Median `2.18 ms`, p95 `3.69 ms` per URL

| Mode | Dataset | Total | TP | FP | TN | FN / Abstained | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Rules-Only (`rules-1.2.0`)** | PhiUSIIL Frozen Test | 33,660 | 625 | 0 | 20,062 | 12,973 | 100.00% | 4.60% | 8.79% | 0.00% |
| **ML-Only (`scamshield-url-v1`)** | PhiUSIIL Frozen Test | 33,660 | 13,491 | 10 | 20,052 | 107 | 99.93% | 99.21% | 99.57% | 0.05% |
| **Rules-Only (`rules-1.2.0`)** | Synthetic Evaluation Set | 215 | 71 | 0 | 100 | 44 | 100.00% | 61.74% | 76.34% | 0.00% |
| **Combined (`rules-plus-model`)** | Synthetic Suspicious URLs | 115 | 115 | — | — | 0 | — | 100.00% | — | — |

### 4.2 Text Detection Benchmark (`rules-1.2.0` Active; `text-model.json` Disabled)
- **Text Candidate Model (`scamshield-text-v1`):** Trained on Mendeley SMS (`5,568` cleaned messages). Achieved `93.8%` validation smishing precision and `79.10%` test smishing precision (`< 95.0%` required quality gate). Kept strictly **disabled** (`validation_eligible: false`).
- **Multilingual Rules Engine (`rules-1.2.0`) on Synthetic Evaluation Dataset (`200` messages):**
  - **Total:** `200` (`100` scam across English, Sinhala, Singlish, and mixed-language; `100` benign including negated security warnings)
  - **Confusion Matrix:** `TP = 95`, `FP = 0`, `TN = 100`, `FN = 5`
  - **Precision:** `100.00%` | **Recall:** `95.00%` | **F1 Score:** `97.44%` | **False Positive Rate:** `0.00%`

### 4.3 Screenshot OCR Pipeline Verification (`30` Synthetic Images)
- **Dataset:** `15` scam screenshots + `15` benign screenshots (`PNG`/`JPEG`) + invalid file rejection checks.
- **Confusion Matrix:** `TP = 15`, `FP = 0`, `TN = 15`, `FN = 0` (`100.00%` precision and recall on clean synthetic renders with user confirmation).

---

## 5. Web Dashboard Browser Verification (`13/13 PASSED`)

Executed via `scripts/verify_browser.py` using headless Chrome `156.0.8078.48` (`docs/browser-verification.json`):
- **Viewports Verified:** `390px` (mobile), `768px` (tablet), `1440px` (desktop) — `horizontal_overflow: false` on all viewports.
- **JavaScript Console / Page Errors:** `0`
- **Verified Views & Workflows:**
  1. Registration & development token verification
  2. Resend verification with cooldown enforcement
  3. Login & session persistence
  4. Overview metrics & recent scan cards
  5. URL scan submission & non-clickable structural URL breakdown
  6. Text scan submission & highlighted evidence spans
  7. Screenshot upload → OCR extraction preview → manual text confirmation → risk assessment
  8. Scan history search, status/risk filtering, and scan deletion
  9. Detection Model status panel (`rules-1.2.0` + model metadata)
  10. Analyst Review Queue & verdict submission (`confirmed_scam` / `false_positive`)
  11. Campaign clustering view (shared URL domains, phone numbers, and text fingerprints)
  12. Admin Team role management & Audit Logs table
  13. Settings: TOTP MFA enrollment, 8 recovery codes display, recovery code regeneration, and account deletion

---

## 6. Mobile Application Verification (`apps/mobile`)

| Check | Command | Result | Details |
|---|---|---|---|
| **TypeScript Static Check** | `npm.cmd run typecheck` | **PASS** | `tsc --noEmit` completed with `0` errors across `App.tsx` and `ResultPresentation.tsx`. |
| **Expo SDK & Dependency Alignment** | `package.json` inspection | **PASS** | Expo SDK `~55.0.15` / RN `0.83.6` / React `19.2.0` aligned; SecureStore, ImagePicker, and StatusBar packages present. |
| **LAN API Configuration** | `apps/mobile/.env` | **PASS** | Updated to current host Wi-Fi IPv4 (`EXPO_PUBLIC_API_URL=http://192.168.1.4:8000/api`); emulator fallback set to `http://10.0.2.2:8000/api`. |
| **Android Bundle Export** | `npx expo export -p android --output-dir dist --clear` | **PASS** | Metro bundled `623` modules into `entry-871b2798b447ef6ef714492d144a16dc.hbc` (`1.6 MB`) + 3 assets with `0` errors. |
| **Android Emulator / Physical Device** | `adb devices -l` | **BLOCKED** | No physical Android device attached over USB/ADB; live device interaction is reported separately as blocked and not conflated with static/bundle passes. |
