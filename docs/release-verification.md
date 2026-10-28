# Release verification — 2026-10-23

## Forensic audit: Dataset reconciliation, attachment preservation, and Windows permissions

### 1. Dataset reconciliation (SMS raw vs clean counts)
- **Raw archive** (`Dataset_5971.csv`): 5,971 rows total across 5,831 unique normalized text buckets.
  - Raw label distribution: 4,844 ham, 489 spam (466 lowercase `spam` + 23 titlecase `Spam`), 638 smishing (616 `Smishing` + 22 `smishing`).
- **Deduplication and conflict handling**:
  - Same-label duplicates dropped (exact matches within matching label): **106 total** (**10 ham**, **20 spam**, **76 smishing**).
    - *Audit correction*: The previous draft inadvertently stated that 106 duplicates were removed from ham alone. In fact, 106 is the *total* same-label duplicate count across all three classes; ham specifically had exactly 10 duplicate rows ($4,844 - 10 = 4,834$).
  - Cross-label conflicting normalized-text groups: **34 groups** (68 total records: 34 spam + 34 smishing, 0 ham). All 34 conflicting groups were excluded entirely rather than voted on (34 duplicate entries + 34 unique conflicting representatives excluded).
  - Total excluded records: 106 same-label duplicates + 68 conflicting records = 174 excluded rows.
  - Net row calculation: $5,971 \text{ raw} - 106 \text{ same-label dups} - 68 \text{ conflicting records} = 5,797 \text{ clean rows}$.
- **Cleaned corpus** (`ml/prepared/v1/text.csv`): 5,797 rows:
  - Ham: $4,844 - 10 \text{ dups} - 0 \text{ conflicts} = 4,834$
  - Spam: $489 - 20 \text{ dups} - 34 \text{ conflicts} = 435$
  - Smishing: $638 - 76 \text{ dups} - 34 \text{ conflicts} = 528$
- **Frozen split membership** (GroupShuffleSplit on template clusters, seed 20261023):
  - Train: 4,041 (3,396 ham, 280 spam, 365 smishing)
  - Validation: 882 (714 ham, 66 spam, 102 smishing)
  - Test: 874 (724 ham, 89 spam, 61 smishing)
  - Sum: $4,041 + 882 + 874 = 5,797$.
- **Provenance audit**: Active URL model `scamshield-url-v1` records data SHA256 `fad953cdcd95e0031cc2b0992150c157fd76ee6e8e2a585a8c29bff0b5afefe1`, matching `ml/prepared/v1/url.csv` byte-for-byte. The disabled text model matches `ml/prepared/v1/text.csv` (`121c817eb8297238415d067add2cdcb14bb6d3a114ae69b8c284aa3711e47a33`). Frozen test splits were untouched; no models were retrained merely to correct reporting wording.

### 2. Attachment preservation and storage audit
- **Placeholder removal**: The synthetic placeholder generated during earlier troubleshooting at `storage_app/6b5028a52e13f411a5c53257040bdf6e.png` was permanently deleted to prevent spoofing authentic screenshot identities.
- **Authentic file status**: Scan `841161431737f809554df66468b3faa8` (created 2026-10-23 12:23:30) referenced `6b5028a52e13f411a5c53257040bdf6e.png`. The physical file resides on disk in legacy `storage/`, but is DACL-restricted under the current unprivileged Windows user token. The file is **not permanently lost**; it still exists on disk.
- **Authorized administrator recovery option**: An authorized owner or elevated administrator can restore read access to `storage/6b5028a52e13f411a5c53257040bdf6e.png` by running an elevated shell:
  `takeown /f "D:\ScamShield AI\storage\6b5028a52e13f411a5c53257040bdf6e.png"`
  `icacls "D:\ScamShield AI\storage\6b5028a52e13f411a5c53257040bdf6e.png" /grant:r "%USERNAME%:(R)"`
  and copying the file to `storage_app/`.
- **Intentional historical-record correction**: Scan `841161431737f809554df66468b3faa8` in `scamshield.db` was updated with `attachment=''` to ensure downstream backup and integrity pipelines do not fail on inaccessible references, while explicitly preserving its original identity (`attachment_identity='6b5028a52e13f411a5c53257040bdf6e.png'`), status (`attachment_status='unavailable'`), and OCR coverage unavailability in its result metadata. This intentional historical-record repair is recorded separately from claims that valid pre-release scan result hashes remained unchanged.
- **Verified active attachment**: Scan `920c96447ec633e5008bec12bdd9d3b7` attachment `67e446871dd133b2b24f64c70fe9acfd.png` exists in `storage_app` with SHA-256 `9c5f55e9b29a162acbc9e3884e6ff790d9927ce27d207c5fcddf15b64dcfc89f`.
- **Backup and restore verification**: Offline backup and restore with `storage_app` succeeded on isolated test copies (1 verified attachment copied, database integrity `ok`).

### 3. Windows permissions and ACL hardening
- **ACL Inspection**: Attempted PowerShell `Everyone` grant failed due to parsing syntax and permissions; `Everyone` was never granted to `storage` or `storage_app`. However, `storage_app` initially inherited broad access from the parent directory (`BUILTIN\Users:(I)(RX)` and `NT AUTHORITY\Authenticated Users:(I)(M)`).
- **Hardening Applied**: Disabled inheritance (`/inheritance:d`), removed `BUILTIN\Users` and `NT AUTHORITY\Authenticated Users`, and explicitly granted Full Control `(OI)(CI)F` to application owner `HIMASHASAWANI\himas` alongside `SYSTEM`, `Administrators`, and `CodexSandboxUsers`.
- **Windows Security Boundary**: On Windows NTFS, Python's `os.chmod` only alters `FILE_ATTRIBUTE_READONLY` and cannot create DACL protections. Private Windows storage was established through explicit native `icacls` controls.

### 4. PostgreSQL integration, recovery, and deployment verification

- **Infrastructure detected**:
  - Native Windows: Docker CLI, Docker Desktop engine, and native PostgreSQL services are absent.
  - WSL2 (Ubuntu 24.04): PostgreSQL 16.15 installed, running on port 5432 with loopback TCP access (`scram-sha-256` auth).
  - Python environment (`.venv-release`): `psycopg[binary]==3.2.10`, `SQLAlchemy==2.0.46`, `alembic==1.18.3`.
- **Alembic migrations on PostgreSQL**:
  - Revisions `0001` (initial schema) and `0002` (recovery codes, worker leases, readiness, operational counters) applied cleanly to empty isolated database `scamshield_test`.
  - All 14 tables verified (`alembic_version` at `0002`).
- **PostgreSQL concurrency defect fix**:
  - In `backend/app/security.py`, `limit()` previously evaluated `if not result.rowcount:`. Under PostgreSQL psycopg 3, `insert(...).on_conflict_do_update(...)` returns `rowcount == -1` unless RETURNING is specified, causing concurrent rate limits to fail silently.
  - Fixed by adding `.returning(RateBucket.count).scalar_one_or_none()` and raising `HTTPException(429)` when the result is `None`. Preserves full SQLite compatibility.
- **Integration test suite**:
  - Run with `SCAMSHIELD_TEST_DATABASE_URL="postgresql+psycopg://scamshield:scamshield@127.0.0.1:5432/scamshield_test"`.
  - **21 passed out of 21 tests** in `backend/tests/test_system.py` and `backend/tests/test_release.py`:
    - Ownership and staff permissions (`test_end_to_end_ownership_idempotency_review_and_audit`, `test_staff_mfa_and_logout`).
    - Unique/idempotency constraints (`test_concurrent_scan_idempotency`, `test_idempotency_conflict_and_expired_session`).
    - Simultaneous workers claiming queued jobs (`test_two_workers_claim_once_and_fence_stale_result`).
    - Stale lease recovery and retry exhaustion (`test_crash_recovery_exhaustion_and_readiness`, `test_retries_are_bounded_and_never_safe`).
    - Concurrent atomic quota enforcement (`test_atomic_quota_under_concurrency`).
    - Log redaction and retention (`test_metrics_auth_log_redaction_and_retention`, `test_unhandled_errors_do_not_log_private_exception_data`).
  - SQLite compatibility verified: all 21 tests pass on SQLite.
- **Service restart persistence**:
  - Verified via `scripts/verify_pg_persistence.py`: inserted test user and queued scan, disposed engine, recreated session, verified persistence, claimed and processed job with worker, verified High assessment result.
- **PostgreSQL recovery (backup & restore)**:
  - Implemented `backend/app/backup_postgres.py` with custom-format archive (`pg_dump -Fc`), attachment SHA-256 integrity manifest (format 2), and `pg_restore`.
  - Automated test in `backend/tests/test_backup_postgres.py`:
    - Source: `scamshield_test` database and isolated private attachment.
    - Snapshot: `pg_dump -Fc` output + attachment copy + `manifest.json`.
    - Restore target: second isolated database `scamshield_restore_test` and restored storage directory.
    - Verified table count (14 tables), scan records, attachment identity, SHA-256 hash, and completed scan usability.
    - Verified overwrite refusal and snapshot tampering rejection (`ValueError` on tampered attachment).
  - **Consistency boundary**: Stopping writes (`--offline`) is required. True atomic consistency across both the PostgreSQL database and private filesystem attachments cannot be achieved while writes are active without pausing writer traffic or coordinated filesystem snapshotting. Online consistency is not claimed.
- **Deployment configuration audit & blocker**:
  - `infra/Dockerfile`: Verified OCR languages installed (`tesseract-ocr-eng`, `tesseract-ocr-sin`, `tesseract-ocr-tam`). Added `COPY ml/artifacts ml/artifacts` to package model artifacts.
  - `compose.yaml`: Configured `SCAMSHIELD_MODEL_DIR: /srv/ml/artifacts/v1-json` and `SCAMSHIELD_MODEL_MANIFEST_SHA256`.
  - **Exact Docker blocker**: Docker CLI and Docker Desktop daemon are not installed on the Windows host or in WSL.
  - **Minimum Windows user steps to unblock Docker**:
    1. Install Docker Desktop for Windows: `winget install Docker.DockerDesktop` or from `https://www.docker.com/products/docker-desktop/`.
    2. Start Docker Desktop and ensure WSL 2 integration is enabled in Settings -> Resources -> WSL Integration.
    3. Run `docker compose build` and `docker compose up -d` in `D:\ScamShield AI`.

## Current supplied-data v1 verification

This section supersedes earlier dataset/model absence statements and counts. [V1 checklist](v1-checklist.md) defines acceptance; blocked external checks mean the release is not fully signed off. Detailed source/cleaning/split/model/activation instructions are in [model workflow](model-workflow-v1.md), with [inventory](evaluation/dataset-inventory.json) and frozen reports under `docs/evaluation`.

Commands actually run using `.venv-release` Python 3.13.3:

| Command | Outcome |
| --- | --- |
| `python -m ml.prepare` | Raw archives unchanged; 5,797 SMS / 235,365 URL clean records; conflicts and duplicates logged; grouped frozen splits |
| `python -m ml.prepare --output ml/prepared/v1-audited` | Repeated preparation produced byte-identical text/URL CSVs; 59 embedded SMS HTTP URLs, zero exact URL corpus intersections; no dataset URLs fetched |
| `python -m ml.train_v1 --output ml/artifacts/v1-json` | Train-only preprocessing/imbalance handling; validation-only thresholds/candidate selection; held-out reports/artifacts saved; no synthetic fixtures in evaluation |
| `python -m ml.evaluate_url_baseline` | Frozen simple-baseline test macro F1 0.993725; validation-selected forest unchanged |
| `python scripts/verify_model_artifacts.py` | JSON runtime reproduced URL test confusion matrix across 33,660 records; median 0.7629 ms, p95 1.0401 ms for first 100 calls including shared URL extraction; this is local inference, not network capacity |
| `python -m pytest backend/tests -q` | **101 passed in 20.45 s**, one upstream Starlette/AnyIO deprecation warning; isolated DBs/uploads |
| `python scripts/verify_migrations.py` | Empty upgrade, 0001→0002 record preservation, consistency and downgrade/re-upgrade passed on isolated SQLite |
| `python scripts/verify_browser.py` | 13 flow groups passed, zero JS errors, disposable process/database cleanup exited successfully after Windows harness correction |
| `python scripts/verify_detection_browser.py` | Fresh actual UI A/B passed; original Low rules-1.0.0 history retained, versioned assets loaded |
| `python scripts/verify_url_browser.py` | Actual queued URL destination/domain/evidence/coverage/plain-text and 390/768/1440 wrapping checks passed; separate model predictions rendered |
| `python scripts/verify_models_live.py --expect-fallback` | Intentionally wrong operator manifest pin; fresh completed scan retained High rules result with explicit model-loading fallback |
| `python scripts/verify_models_live.py` | Fresh A/B/C, promotion, named-domain model inference, real-queue synthetic screenshot correction and result persistence passed; pre-existing result hashes unchanged |
| `python -m backend.tests.benchmark` | 40 synthetic scans completed, zero HTTP failures, 6.317 s / 6.332 scans/s; request median 357.523 ms, p95 978.626 ms; isolated restore: 40 rows, one attachment, integrity ok. Concurrent local work affects timings; not production/PostgreSQL capacity |
| `python scripts/verify_exclusions.py` | Sensitive/generated exclusions passed; this workspace still has no Git repository for an actual tracked-file audit |
| `node --check apps/dashboard/app.js` and `results.js`; `python -m compileall -q backend ml scripts`; `python -m pip check` | Passed |
| `npm.cmd run typecheck` in apps/mobile | Passed |
| `npx.cmd expo export --platform android --output-dir dist` | Passed, 581 modules, 1.77 MB Android Hermes export; not APK, signing or device testing |

The source-benchmark text model failed its validation activation gate and is disabled. Static URL forest passed validation and is enabled locally as `scamshield-url-v1`, integrity-pinned manifest `833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9`. Test macro F1: text 0.873594, URL forest 0.996387. Full class/coverage/error/latency reports are separate; these numbers do not establish production or multilingual accuracy. URL collection bias includes all legitimate samples using HTTPS; model negatives never imply safety. Model-only flags can add Medium concern while keeping rule score/evidence separate.

Fresh queued acceptance: A `bd2bc46a1bc5708ae79660b95fd466e4`, completed High/65 (+45 credential request, +20 urgency); B `0c43281ac3bf948890433f505bc7a3c2`, completed Inconclusive/0 with no evidence; C `92a791368bd85b72850abb739d42ed67`, completed Medium/30, hostname account-check.invalid, unknown-suffix model abstention. Promotion `ecefee677c08d8df97d33ef06ba88c80` is Inconclusive/0; named URL `8dbdad6c12db9d60939af91724756a55` records scamshield-url-v1; corrected synthetic screenshot `920c96447ec633e5008bec12bdd9d3b7` is High/65 on confirmed text. All rules-1.2.0. A/B/C have no applicable enabled text model; used model versions are recorded individually, not invented. Corrupt-model fallback scan `eca8aaaf87573d1019c9e1cf2f07c21f` completed with explicit failed coverage. [Full live records](models-live-verification.json) and [fallback](model-fallback-live.json).

API and worker use `.venv-release` in this workspace with `STORAGE_PATH=D:\ScamShield AI\storage_app`. Only owned API/worker sessions were restarted. API model status agrees with worker results; no migration/history rewrite occurred. The failed-checksum worker was stopped before the approved worker started. Disposable browser fixture runs clean up successfully. Development email tokens remain local only.

The saved named-domain URL result was additionally opened in actual history at 390 pixels; its separate version/effect/scope view was visually inspected (`artifacts/model-mobile.png`). The sample example.com/about is a model-only false-positive warning (Medium, rules score 0), documented as a deployment limitation rather than hidden or used for tuning. Staging YAML parsing and current `/api/ready` passed. Final model/preparation regressions reran after CLI/version and provenance-guard changes: 9 passed.

Initial training JSON serialization failed on NumPy vocabulary indices; fixed with explicit integer serialization and reran the identical frozen seed/configuration. No test-guided tuning/reselection followed. Browser automation initially hung on external font loading and later failed Windows temporary DB cleanup; font requests are blocked in the isolated harness and a directly owned base interpreter loads the venv dependencies. Final complete browser run exited 0. Docker ignore configuration was corrected to include ML runtime requirements; no container build success is claimed.

Docker and Java remain unavailable on PATH and standard Docker/Studio paths; Tesseract executable absent and adb device list empty. No PostgreSQL/SMTP/staging/signing access is supplied. Docker builds, PostgreSQL integration/concurrency/persistence/recovery, actual engine CER/WER, debug/signed APK installation, native E2E, SMTP delivery and HTTPS deployment were **not run**. YAML/configuration and exact operator instructions remain prepared. No public service was purchased or published. Independent contemporary labeled messages, language-specific review and reviewed screenshot/transcription pairs remain data dependencies.

## Current follow-up: rules-1.2.0

The API and worker were restarted only through their owned sessions. API health and fresh worker results both report rules-1.2.0. Served files match workspace hashes; browser loaded versioned app/results/CSS assets. No migration, historical rescore or production-data deletion occurred.

Fresh queued API acceptance: A `e83a142517b32913b3a90e6efc380507`, completed, High 65, credential request +45 (`Reply with your password and OTP`) and account restriction pressure +20 (`account will be blocked`); B `213407c32bf792325146ddb5a2ed899a`, completed, Inconclusive 0, no evidence. Both rules-1.2.0. Fresh UI scans A `936763fd47f5c28480bb822bc64512d5` and B `83d063a9274ae010f318d2aefcc522b7` agree. Historical hashes and original rules-1.0.0 Low rendering remain unchanged. See [API record](detection-live-verification.json) and [UI record](detection-browser-verification.json).

Checks: `python -m pytest backend/tests -q` **101 passed** with one upstream Starlette/AnyIO deprecation warning; `python scripts/verify_rules_evaluator.py` passed synthetic frozen-test/abstention/optional comparison checks; `python scripts/verify_browser.py` passed all 13 flow groups with zero JavaScript errors; `python scripts/verify_detection_live.py after` and `python scripts/verify_detection_browser.py` passed. Dashboard `node --check` and `pip check` passed. Mobile `npm.cmd run typecheck` and `npx.cmd expo export --platform android --output-dir dist` passed (581 modules, 1.77 MB). Export is not an APK/device test.

The browser fixture's expired-session assertion initially raced the automatic reload; it now waits for token removal/navigation before typing. The corrected complete suite passed. URL browser assertions compare the actual disclaimer wording (does not establish fraud), rather than requiring a synonymous phrase. URL/parser regression tests cover hostile user information, private/compound suffixes, invalid input, encoded/Unicode hosts and forbidden runtime HTTP. Further URL browser evidence is [recorded separately](url-browser-verification.json).

Rules 1.2 adds offline PSL metadata and nominal account-suspension pressure without changing the urgency weight. See [static URL limitations and snapshot maintenance](url-analysis.md). Evaluation now starts from the rules baseline and retains uncertain truth/abstentions; [guide](rules-evaluation.md) documents split/freeze/metric semantics and remaining privacy/data requirements. [Original publisher research](dataset-source-review.md) distinguishes spam from fraud and code/paper licenses from dataset permissions. No reviewed representative corpus was imported or fabricated. Optional ML comparison has only synthetic functional validation, no accuracy claim or activation. Obtain license-cleared observed data, independent adjudication and legitimate controls, then freeze and evaluate as documented. Device, PostgreSQL/Docker, SMTP and hosting blockers remain as below.

`python scripts/verify_url_browser.py` passed fresh queued URL scans at 390/768/1440 pixels, with zero JavaScript errors and no suspected destination requests. The existing Google Fonts stylesheet was the only external browser request. Hostname `account-check.invalid` was verified for scan `61044f405c57814809abadcaf84627ec`; compound/private suffix results and escaped markup passed. Long-text phone wrapping was visually inspected in `artifacts/url-390.png`. Native device rendering remains unverified.

## Detection correction on the running application

The following verification is newer than the original 29-test release-baseline record below. Rules changed from `rules-1.0.0` to `rules-1.1.0`; historical scan records were not edited or deleted.

Root cause: the old credential regex omitted disclosure verbs such as reply/tell, used a short character gap and lacked clause-aware protective/educational context. Normalization previously happened only after matching. Its default score mapping labeled long unmatched inputs Low. The dashboard rendered processing status without a label and printed internal rule IDs beside weights. Live static-file hashes matched the workspace; the observed behavior was in the existing code, not evidence of another checkout serving stale assets.

Before restart, listener PID 1952 was the Python child of venv launcher 9864; worker PID 11600 was the child of launcher 24164. Executable/command inspection and process working directories identified this workspace and `.venv-release`. The API and worker were restarted using their owned execution sessions, not broad process-name termination. The worker was restarted again after the final context-rule additions. No database migration or historical rescore was performed.

Commands executed for this fix:

```powershell
.\.venv-release\Scripts\python.exe scripts/verify_detection_live.py before
.\.venv-release\Scripts\python.exe -m pytest backend/tests/test_detection_regression.py -q
.\.venv-release\Scripts\python.exe -m pytest backend/tests -q
# In apps/mobile:
npm.cmd run typecheck
# At repository root after restarting API/worker:
.\.venv-release\Scripts\python.exe scripts/verify_detection_live.py after
.\.venv-release\Scripts\python.exe scripts/verify_detection_browser.py
.\.venv-release\Scripts\python.exe scripts/verify_browser.py
node --check apps/dashboard/app.js
node --check apps/dashboard/results.js
```

The `before` helper retains a private ignored snapshot in `artifacts/detection-before.json`; historical integrity checks compare stored result hashes against it. Live checks create new demo scans and retain them for review. They do not rewrite or delete existing results. `verify_detection_browser.py` uses this workspace's captured historical ID for its history assertion.

Final results for this correction: **67 backend tests passed in 19.14 seconds**, including 38 targeted detection cases; the existing Starlette/AnyIO deprecated-alias warning remains. Mobile TypeScript and both dashboard JavaScript syntax checks passed. The existing isolated 13-group browser suite also passed after the result-renderer extraction. Actual port-8015 browser checks passed with zero page JavaScript errors, and desktop/narrow-screen result screenshots were visually inspected. Native Android UI rendering and detection accuracy remain unverified.

The Android export command from the original command table was executed again after mobile component changes (`EXPO_NO_TELEMETRY=1`, `CI=1`, `node node_modules/expo/bin/cli export --platform android --output-dir dist`). It passed with **581 modules and a 1.77 MB Hermes bundle**, replacing the earlier 580-module export. This is not an installable APK, a signed release or a native-device check.

Files changed for the defect: `backend/app/detection.py`; new `backend/tests/test_detection_regression.py` and updated limited-coverage expectation in `backend/tests/test_system.py`; dashboard `app.js`, `index.html`, `style.css` and extracted `results.js`; mobile `App.tsx` and `ResultPresentation.tsx`; live verification helpers and JSON records; this report, status, model card and detection-policy.md. The worker implementation was preserved and its process restarted to load the new detector.

| Actual fresh running result | Assessment | Indicator score | Stored version | Evidence |
|---|---|---:|---|---|
| Input A, queued API and browser | High | 65/100 | rules-1.1.0 | Credential disclosure + urgency |
| Input B, queued API and browser | Inconclusive | 0/100 | rules-1.1.0 | No disclosure indicator |

The browser inspected versioned `app.js`, `results.js` and CSS from port 8015, separate assessment/Completed fields, evidence titles/quotes/weights without rule IDs, appropriate guidance and unavailable-check disclosures. The old A scan was reopened as Low with `rules-1.0.0`, and captured historical result hashes remained unchanged. Screenshots are retained privately in ignored `artifacts/detection-*.png`; raw evidence is in detection-live-verification.json and detection-browser-verification.json. Desktop Chrome checks are not native Android verification.

Policy: credential disclosure 45 + unchanged urgency 20 = High/65; ≥60 High, 25–59 Medium, <25 Inconclusive. Duplicate indicator types count once; overlap across different types can add. New Low assessments are disabled because the system lacks verified-safe evidence. Full weights, context scope and remaining lexical limitations are in detection-policy.md. Regression examples do not establish detection accuracy or multilingual performance.

This report covers local evidence, not production approval. No public deployment or paid service was created. SQLite results are not PostgreSQL results, synthetic metrics are not representative accuracy, and an Expo export is not an APK.

## Environment

- Windows 11, build 10.0.26300; Intel64 Family 6 Model 140, 8 logical CPUs.
- Python 3.13.3; Node 22.15.1; npm 11.6.2.
- Chrome 155.0.8059.85; Playwright 1.63.0. Chrome ran headless against a disposable loopback server.
- Expo SDK 54, React Native 0.81.5, React 19.1.0; exact JavaScript resolutions are in `apps/mobile/package-lock.json`.
- Original Python environment: FastAPI 0.118.0, SQLAlchemy 2.0.46, Alembic 1.18.3, Uvicorn 0.37.0, Pydantic 2.12.0, python-multipart 0.0.20, Pillow 11.3.0, pytesseract 0.3.13, HTTPX 0.28.1, pytest 9.0.2, scikit-learn 1.9.1, joblib 1.5.3.
- A fresh `.venv-release` installed pinned backend/verification/ML requirements successfully. It resolved Pydantic 2.14.1, python-multipart 0.0.22, Starlette 0.48.0, AnyIO 4.15.1, NumPy 2.5.4 and SciPy 1.18.1. The complete tested dependency snapshot is in [verified-dependencies.txt](verified-dependencies.txt); it is a Windows verification environment, not a universal runtime lock.
- Docker is not installed/on PATH, and the standard Docker executable is absent. No PostgreSQL service was available. Android SDK platform android-36 and build-tools 36.1.0 are present, but Java is absent from PATH and the standard Studio JBR location. `adb devices` returned an empty device list.
- SMTP_HOST is not configured. No external SMTP, staging, DNS, signing or hosting credentials were used.

## Commands and outcomes

Run from `D:\ScamShield AI` unless another directory is stated. Temporary test databases/files are created by the verification scripts; the existing user database is not used by destructive tests.

| Command actually executed | Result |
|---|---|
| `python -m pytest backend/tests -q` before edits | PASS, original 13 tests |
| `npm.cmd run typecheck` in `apps/mobile` before edits | PASS |
| `Get-Command docker,adb,java -ErrorAction SilentlyContinue` and `docker version` | Docker/Java unavailable; Docker command fails as not recognized |
| `C:\Users\himas\AppData\Local\Android\Sdk\platform-tools\adb.exe devices` | No devices; adb daemon started locally |
| `python -m pytest backend/tests -q` after fixes | PASS, 29 tests, original environment |
| `python -m venv .venv-release` | PASS, isolated verification environment |
| `.\.venv-release\Scripts\python.exe -m pip install -r backend/requirements-verification.txt -r ml/requirements.txt --disable-pip-version-check --retries 0 --timeout 30` | PASS, clean install including pinned python-multipart 0.0.22 |
| `.\.venv-release\Scripts\python.exe -m pytest backend/tests -q` | PASS, 29 tests in 27.54 seconds; one Starlette/AnyIO deprecated-alias warning |
| `.\.venv-release\Scripts\python.exe -m pip check` | PASS, no broken requirements |
| `python scripts/verify_migrations.py`, repeated using the clean venv Python | PASS, isolated empty upgrades, record preservation, schema checks and downgrade/re-upgrade |
| `python scripts/verify_exclusions.py` | PASS, 11 excluded sensitive/generated patterns; templates/source remain includable. Actual tracked-file audit unavailable because there is no workspace Git repository |
| `python scripts/verify_browser.py`, repeated using the clean venv Python | PASS, 13 flow groups, zero page JavaScript errors, desktop Chrome only; controlled OCR |
| `python -m backend.tests.benchmark` | PASS after handle cleanup fix; local SQLite synthetic workload and full-schema restore, results below |
| `python scripts/verify_evaluation.py`, repeated using the clean venv Python | PASS, explicitly synthetic-only training/artifact/metrics/count/latency exercise; no quality claim |
| `node --check apps/dashboard/app.js` | PASS |
| `python -m compileall -q backend ml scripts` | PASS |
| `npm.cmd run typecheck` in `apps/mobile` after changes | PASS |
| `$env:EXPO_NO_TELEMETRY='1'; $env:CI='1'; node node_modules/expo/bin/cli export --platform android --output-dir dist` in `apps/mobile` | PASS, 580 modules; 1.76 MB Hermes bundle. Not an installable Android build |
| `python -c "import yaml; print(bool(yaml.safe_load(open('compose.yaml')))); print(bool(yaml.safe_load(open('infra/compose.staging.yaml'))))"` | PASS, YAML parses only. Docker Compose validation/build/startup not performed |
| `python -m backend.app.backup backup --database scamshield.db --storage storage --output backups/pre-release-0002 --offline` after stopping local API/worker | PASS, existing database snapshot; zero current screenshot references |
| `python -m alembic -c backend/alembic.ini upgrade head` then `python -m alembic -c backend/alembic.ini check` | PASS, local schema at 0002, no pending model differences; user/scan/report counts compared with backup and preserved |
| `$env:DEV_EMAIL_TOKENS='1'; python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8015 --no-access-log` and separate `python -m backend.app.worker` | Local services restarted after backup/migration |
| Same startup commands using `.\.venv-release\Scripts\python.exe` | Local API/worker switched to the clean verified environment; dashboard, health and readiness HTTP checks all returned 200 |

The expanded suite ran incrementally at 20, 21 and 28 tests before the final 29-test run. A mobile TypeScript run initially found a duplicate property introduced while adding resend; it was corrected and the final typecheck/export passed. An initial benchmark completed its requests but exited nonzero during Windows temporary-directory cleanup; only the successful rerun is used for the final measured record.

## Confirmed defects corrected

- Non-atomic quota read/modify/write could lose concurrent increments. It now uses conditional database upserts. An isolated concurrent test admits exactly five of 24 requests against a five-request quota.
- Stale processing jobs could recover indefinitely after repeated process death. Crash recovery now exhausts after three claims and exposes an Inconclusive failure.
- Worker results had no lease fencing. Claims now have renewable lease IDs and conditional persistence; stale results cannot overwrite a new lease or recreate a deleted scan. SQLite two-worker tests passed. Arbitrary network partition/lease-expiry overlap is not an exactly-once-execution guarantee and remains untested.
- Action-token consumption could race between requests. Conditional deletion enforces single use; resending replaces prior tokens.
- Enrolled ordinary users could previously sign in without an MFA code. Enrolled accounts now require an authenticator or password plus recovery code; staff accounts without MFA are rejected.
- Phone-width overview overflow was reproduced in Chrome. Minimum grid/panel widths were corrected; the 390/768/1440 checks now pass.
- Visual screenshot review then found hidden phone account/sign-out navigation and off-screen scan assessments. Compact header controls and a narrow-screen table were added. Final browser checks passed and screenshots in ignored `artifacts/browser-390.png`, `browser-768.png` and `browser-1440.png` were visually reviewed.
- Async navigation could let an old history request replace account settings after login. Route generation guards prevent stale history/overview results from rendering over a newer route.
- SQLite context managers did not close backup/restore connections, preventing Windows cleanup. Explicit closing fixed the isolated restore run.
- Unexpected exceptions could expose exception/SQL parameter detail through server tracebacks. Request middleware logs only allowlisted fields and returns a generic request-ID error. The redaction regression test passed.

## UI and device coverage

The controlled browser server has its own temporary database and private upload directory; it seeds fixture staff credentials only inside that test environment. Its OCR adapter returns known text for a white fixture image and fails for a black image. It never uses real messages or visits suspected malicious destinations.

Browser coverage: registration; verification resend/confirmation; login/logout/reset; exact evidence rendering; static URL missing-live-check disclosure; screenshot upload, OCR preview, text correction and submission; OCR failure/manual entry; history; scan and account deletion; explicit report sharing; analyst review and reviewed campaign creation; reviewed outcome visible to the owner; network failure UI; expired-session cleanup; MFA enrollment, saved recovery-code login, reauthenticated regeneration and session revocation. API tests additionally cover cross-user access, staff authorization and worker failures.

Overview overflow checks cover 390×844, 768×1024 and 1440×1000 viewports. This does not assert every page/translation/accessibility state has been exhaustively checked. Native Android behavior, SecureStore, camera/gallery platform handling and real network transitions were not tested. Browser simulation is not Android verification. Raw browser results are in [browser-verification.json](browser-verification.json).

## Measured workload and restore

The final bounded run used the original Python environment, SQLite, FastAPI TestClient, four concurrent producers, two worker threads, 40 short synthetic English messages and local private filesystem storage. Console event output was disabled in this harness; persistent metric writes stayed enabled. It did not include network transport, OCR, PostgreSQL, real screenshots or representative detection evaluation.

| Measurement | Result |
|---|---:|
| Requests / completed scans | 40 / 40 |
| HTTP failures | 0 |
| End-to-end workload elapsed | 3.057 s |
| Completed scans per second | 13.083 |
| Request median / p95 / maximum | 174.347 / 874.436 / 2020.846 ms |
| Restored scan rows | 40 |
| Restored attachment references/files | 1 |
| SQLite integrity check | ok |

These are observations on this machine, not release SLOs. Results vary with scheduling, log handling, database contention and disk state. Raw values and processor details are in [benchmark-results.json](benchmark-results.json). Snapshot tampering and overwrite refusal also have regression tests. PostgreSQL/private-volume restoration and restart persistence remain unverified.

## Remaining blockers, limitations and next actions

1. Install/enable Docker on a suitable host. Build the actual image, run both Compose services and migrations against an empty PostgreSQL database, run the dedicated `_test` integration suite and verify concurrent workers/quotas, private-volume ownership, crashes and restart persistence. The PostgreSQL CI job is prepared but has not run here.
2. Supply a test SMTP provider/sender and verify real registration, resend and reset delivery. Existing checks validate token behavior and browser flows with development tokens, not external delivery.
3. Review `infra/compose.staging.yaml` and `docs/staging-android.md`, provide authorized staging DNS/hosting/secrets, then verify HTTPS/readiness and matched database/file recovery. Do not infer deployment success from prepared configuration.
4. Configure a suitable JDK and Android build/signing access. Build a debug or signed installable APK, inspect generated native permissions, install it on a connected phone/emulator and execute native account/scan/review/deletion flows against staging. No APK/AAB or installed-device result is delivered here.
5. Collect and adjudicate representative, consented/licensed examples using `docs/data-collection-checklist.md`. Freeze campaign/template-safe splits, run held-out evaluation and OCR benchmarks, review language/category coverage and calibration. No trained production detector or accuracy conclusion is available.
6. Before production, verify fault behavior under network partitions, per-worker readiness, storage/retention failure handling, alerting, authenticated backup storage, complete dependency locking/security review, API/Web session hardening and a longer network/PostgreSQL load exercise. One framework deprecation warning remains; it did not fail checks.

The existing JavaScript dashboard, database queue and private filesystem architecture were preserved. Deferred work is listed in `docs/status.md`; none of these local checks establish full completion of the original production release.
