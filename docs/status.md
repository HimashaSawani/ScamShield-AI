# Acceptance and delivery status

## Manual Expo Go testing on a physical phone — in progress (2026-10-24)

This is **manual Expo Go (development) testing only**. adb-based automation, standalone APK build/installation and device verification remain **pending**; none of them was completed in this session.

- Setup verified: `apps/mobile` is Expo SDK 54 (`expo@54.0.38`, RN 0.81.5); `npx expo install --check` reports dependencies up to date; `npm run typecheck` passes. Native modules are only `expo-secure-store`, `expo-image-picker`, `expo-status-bar`, all included in Expo Go — no custom native code is needed.
- **Compatibility blocker:** the phone's installed Expo Go targets **SDK 58**, and Expo Go runs one SDK only. The project was not upgraded (out of scope). Testing requires Expo Go for SDK 54 on the phone (`https://expo.dev/go?sdkVersion=54&platform=android&device=true`). Observed 16:53: after scanning the `npx expo start --go --lan --clear` QR, Metro logged "Project is incompatible with this version of Expo Go (SDK 58 vs 54)". This confirms the phone reaches Metro over the LAN; the app itself did not load.
- Mobile API base: `apps/mobile/.env` `EXPO_PUBLIC_API_URL=http://192.168.1.6:8015/api` (laptop Wi-Fi IPv4; `/api` prefix matches `App.tsx` paths). Emulator default `10.0.2.2` stays as the code fallback.
- Backend: `.venv-release` API (`--host 0.0.0.0 --port 8015`) and one worker, using root `scamshield.db`, `STORAGE_PATH=D:\ScamShield AI\storage_app`, `DEV_EMAIL_TOKENS=1`, model dir `ml/artifacts/v1-json` with manifest pin `833de7d2…a9` (checksum re-verified). An earlier API started without this configuration was stopped. `GET http://192.168.1.6:8015/api/health` → `{"status":"ok","version":"rules-1.2.0"}` from the laptop; reachability **from the phone is not yet confirmed**. Development only; no public tunnel or port forwarding.
- Dependency incident: an interrupted `npm install` left 100+ partially extracted packages and empty lockfile entries. Recovered by regenerating `package-lock.json` with the same `package.json` ranges and running `npm ci` (1,017 packages). The earlier `ECOMPROMISED` error came from the **npx cache lock** (`libnpmexec/with-lock.js`) while npx tried to fetch `expo@58` because the local `expo` was missing. The project lockfile was not the cause.
- Manual checklist results (login, text scan, URL scan, screenshot correction, history): **not yet recorded**.

## Dataset and inference release candidate — current

The newly supplied archives were processed without changing raw data or running bundled scripts. Historical-source benchmark results, versions, splits, licenses, limitations and exact commands are in [model workflow v1](model-workflow-v1.md); [full acceptance checklist](v1-checklist.md) defines the remaining sign-off work. **101 backend tests passed**, mobile TypeScript/export passed, Chrome flows passed and the SQLite workload/restore reran successfully. The three-class SMS model failed validation eligibility and is disabled. The domain-grouped static URL forest passed and is enabled locally as `scamshield-url-v1`; no probabilities or safe verdicts are displayed. Its data-only JSON inference reproduced the frozen 33,660-URL confusion matrix.

Fresh [queued results](models-live-verification.json): A High 65 (`bd2bc46a1bc5708ae79660b95fd466e4`), B Inconclusive 0 (`0c43281ac3bf948890433f505bc7a3c2`), C Medium 30 (`92a791368bd85b72850abb739d42ed67`) with correct hostname, promotion Inconclusive 0 (`ecefee677c08d8df97d33ef06ba88c80`), named-domain URL uses the model (`8dbdad6c12db9d60939af91724756a55`), confirmed screenshot text produces High 65 (`920c96447ec633e5008bec12bdd9d3b7`). Fresh browser UI scans: A `936763fd47f5c28480bb822bc64512d5`, B `83d063a9274ae010f318d2aefcc522b7`. Fresh live API scans: A `e83a142517b32913b3a90e6efc380507`, B `213407c32bf792325146ddb5a2ed899a`. A separate corrupt-checksum scan verified explicit rules-only [fallback](model-fallback-live.json). Historical hashes stayed unchanged. API and worker were restarted safely without a migration. No representative deployment, multilingual or OCR accuracy claim follows from the supplied benchmark. Required Docker/PostgreSQL, JDK/APK/device, real OCR and SMTP/TLS checks remain blocked; earlier counts and absence-of-model/dataset statements below are historical milestones superseded here.

## Current follow-up — rules-1.2.0

Implemented and verified locally: **101 backend tests**, mobile TypeScript, fresh 581-module Android JavaScript/Hermes export, dashboard syntax, frozen-test evaluator synthetic smoke, the 13-group Chrome suite, and new queued API/browser A/B scans. Input A remains High 65 (credential request 45 + urgency 20); B is Inconclusive 0 with no indicators. Both complete on rules-1.2.0. Historical hashes are unchanged. Current machine-readable results: [API](detection-live-verification.json), [browser](detection-browser-verification.json).

Dashboard/mobile now expose plain-text URLs, actual hostname, offline PSL registrable domain, user-information/subdomain details, and completed/failed/unavailable checks. IDNA, private suffixes, co.uk, IP addresses, unknown suffixes, invalid URLs and no-network behavior have regression coverage. `.invalid` is explicitly unavailable rather than guessed. See [URL policy](url-analysis.md). Native mobile rendering remains implemented but unverified on a device.

Implemented: rules-first evaluator with Uncertain labels, frozen manifest, leakage guards, abstention-aware metrics, per-language counts, error IDs and latency/environment. Optional train-only TF-IDF/Logistic Regression and validation-threshold agreement comparison are diagnostic only; synthetic smoke passed, no model activated. [Annotation guide](rules-evaluation.md), [empty collection template](../ml/data/collection-template.csv), and [publisher-source review](dataset-source-review.md) are delivered. English, Sinhala/Singlish and Tamil candidates were researched; a license-cleared, independently adjudicated benchmark and representative controls remain a **data dependency**, not a claim that datasets do not exist. No accuracy or calibration claim.

Fresh [URL browser checks](url-browser-verification.json) passed at 390/768/1440 pixels: actual-hostname/user-information separation, compound/private suffix boundaries, unavailable reserved suffix, non-clickable text, escaped markup and long-text overflow. No suspected destination was requested; the existing Google Fonts stylesheet was the only external browser request. Phone screenshot wrapping was visually inspected.

External blockers and deferred release work listed below still apply. Prior sections document earlier milestones and versions; this section supersedes their current test/version counts.

## Detection defect correction — rules-1.1.0

The credential-request defect was reproduced on the actual port-8015 application, corrected and verified using fresh queued API and browser scans. Input A now returns **High, 65/100**, with credential-disclosure and urgency evidence. Input B returns **Inconclusive, 0/100**, with no credential-request indicator. Both new results store `rules-1.1.0`. Historical result hashes remain unchanged, and an old Low/20 scan was reopened with its original `rules-1.0.0` result.

New assessments no longer default to Low under limited coverage. Clause-scoped request/credential matching, local negation and educational-context handling replace the former short verb/keyword regex. Dashboard/mobile presentation separates assessment, processing status, evidence title, original span and weight; internal signal IDs are hidden from evidence text. See [policy and limitations](detection-policy.md), [live API evidence](detection-live-verification.json) and [live browser evidence](detection-browser-verification.json). These are functional examples, not accuracy claims. Native device rendering remains unverified.

Detection-fix validation: **67 backend tests passed** (38 targeted detection regressions plus the existing suite), mobile TypeScript passed, JavaScript syntax checks passed, and the existing 13-group browser suite passed after extracting the result renderer. Fresh live API/browser acceptance passed with no page JavaScript errors. One existing Starlette/AnyIO deprecation warning remains; it did not fail tests. Desktop and narrow-screen result screenshots were inspected. No historical result was rescored.

The updated mobile JavaScript/Hermes export was rebuilt successfully: **581 modules, 1.77 MB**, including the new result components. This replaces the earlier baseline export; it is still not an APK or real-device verification.

Updated 2026-10-23. This is a verified local baseline with prepared release infrastructure, **not a production-ready release**. No deployment, model-accuracy or calibrated-probability claim is made.

The final clean-environment rerun passed all 29 backend tests, browser flows, migrations, synthetic evaluation and `pip check`. Exact versions are in [verified-dependencies.txt](verified-dependencies.txt). Local services now use that verified environment. Layout screenshots at 390/768/1440 pixels were visually reviewed; phone account/sign-out access and scan assessment visibility were corrected. Screenshots are in ignored `artifacts/browser-*.png`.

## Implemented and verified

- Backend suite: **29 tests passed** using isolated SQLite databases and temporary uploads. Coverage includes ownership/RBAC, account lifecycle, MFA/recovery, token reuse, concurrent quotas/idempotency/worker claims, stale-result fencing, bounded retries/crash recovery, OCR adapters/fallback, reports/campaigns, deletion/retention, protected metrics, log redaction and backup integrity.
- Verification resend API/UI: generic responses, per-IP limits, per-address cooldown and replacement single-use expiring tokens. Dashboard browser tests passed; mobile source typechecks/bundles. Actual SMTP delivery remains unverified.
- Hashed single-use MFA recovery codes, password plus authenticator/recovery reauthentication for regeneration, audit records and session revocation. Browser enrollment, recovery login and regeneration passed. No admin bypass was added.
- Chrome automation passed 13 flow groups: registration/resend/verification/login/reset, text evidence, static URL coverage disclosure, controlled OCR preview/correction/failure/manual fallback, history/deletion, explicit sharing, analyst decisions/grouping, reviewed user outcomes, network failure, expired sessions and MFA recovery. No JavaScript errors. Overview layouts passed at 390, 768 and 1440 pixels. These are not Android device tests.
- Atomic database-backed rate counters, renewable job leases and fenced result persistence. SQLite concurrency checks passed; PostgreSQL checks remain blocked.
- Structured allowlisted request/scan/job logs, generic failure responses and protected admin metrics for errors/latency, queue/stale counts, processing duration/failures, retry exhaustion and OCR failures. Worker readiness passed locally.
- Isolated migration checks: empty upgrade, 0001 → 0002 record preservation, schema consistency and downgrade/re-upgrade. The existing local database was backed up and migrated with user/scan/report counts preserved. Backup: `backups/pre-release-0002` (private, ignored).
- Offline SQLite/private-file backup and isolated restore passed integrity/tamper and overwrite checks. Full-schema recovery restored 40 scan records and one attachment reference. Windows handle cleanup was fixed and rerun.
- Bounded workload: 40 synthetic messages, 4 clients, 2 worker threads, 40 completed, zero HTTP failures; 3.057 seconds, 13.083 scans/second, request median 174.347 ms and p95 874.436 ms. Console logs were disabled; persistent metrics remained enabled. This is local SQLite/TestClient performance, not PostgreSQL/network/production capacity. See [raw results](benchmark-results.json).
- Mobile TypeScript and fresh Expo Android export passed (580 modules). Export is JavaScript/Hermes output, not an APK.
- Dataset checks reject missing labels/provenance/dates, duplicate records/text, campaign/template leakage, near-duplicate templates and implicit synthetic evaluation. Train-only fitting, validation-only thresholds, held-out metrics/counts/latency and artifact saving passed an explicitly synthetic smoke exercise. No representative accuracy result exists.
- Ignore rules passed checks in a temporary Git repository for environment secrets, uploads, databases, backups, signing material and generated bundles. This workspace has no `.git`, so an actual tracked-file audit is unavailable.

- PostgreSQL 16.15 integration: Alembic revisions 0001 and 0002 applied cleanly to empty isolated database `scamshield_test`. 21/21 integration and release tests passed against PostgreSQL (ownership/RBAC, unique/idempotency constraints, concurrent worker claims, stale lease recovery, retry exhaustion, atomic quotas, log redaction). Service restart persistence verified (`scripts/verify_pg_persistence.py`).
- PostgreSQL concurrency defect corrected: `limit()` in `backend/app/security.py` updated with `.returning(RateBucket.count).scalar_one_or_none()` and `None` check to handle psycopg 3 rowcount semantics while preserving full SQLite compatibility.
- PostgreSQL recovery tooling and verification: `backend/app/backup_postgres.py` implements custom-format snapshot (`pg_dump -Fc`), attachment SHA-256 integrity manifest (format 2), and `pg_restore`. Automated test (`backend/tests/test_backup_postgres.py`) passed: restored into isolated `scamshield_restore_test` database and storage, verified table counts, scan records, attachment hashes, overwrite refusal, and tampering rejection. Offline confirmation (`--offline`) is required to guarantee database/filesystem consistency; online consistency across disparate storage layers is not claimed.
- Dataset reconciliation: Reconciled raw (5,971: 4,844 ham, 489 spam, 638 smishing), same-label duplicates (106: 10 ham, 20 spam, 76 smishing), cross-label conflicts (68 records in 34 groups: 34 spam, 34 smishing), and clean corpus (5,797: 4,834 ham, 435 spam, 528 smishing). Ham duplicates removed were 10 ($4,844 - 10 = 4,834$), correcting the previous reporting error that attributed all 106 duplicates to ham. Frozen splits untouched.

## Implemented but not verified

- Docker images, container execution, non-root UID/private-volume ownership, worker healthcheck, persistence and staging Compose/Caddy HTTPS. Configuration prepared (`infra/Dockerfile` updated with model artifacts; `compose.yaml` updated with model directory/hash), but container startup was not executed due to missing Docker runtime.
- Actual Tesseract engine recognition and installed language data. Automated OCR success/failure uses controlled fixtures, not recognition-quality evidence.
- Native mobile account lifecycle, SecureStore, phone/emulator layouts and network transitions. Source typechecks and exports only.
- Staging TLS/provider email delivery and release-image rollback.

## Blocked by external access or data

- Docker CLI and Docker Desktop daemon are absent on the Windows host and WSL. Docker image build and Compose stack runtime execution remain blocked. Minimum Windows steps: install Docker Desktop (`winget install Docker.DockerDesktop` or from `https://www.docker.com/products/docker-desktop/`), start Docker Desktop with WSL 2 backend, and run `docker compose build` / `docker compose up -d`.
- SMTP credentials are not configured. DNS/hosting/TLS access is not supplied, and public publication is not authorized.
- Android SDK/adb are present, but no Java executable was found on PATH or the standard Studio JBR path, and `adb devices` lists no devices. Expo/signing account access and a staging backend were not supplied. Debug APK, signed release APK/AAB and real-device E2E remain blocked.
- Representative consented/licensed annotated data is absent. Production model evaluation, calibration and multilingual conclusions remain blocked. See [data collection checklist](data-collection-checklist.md).

## Deferred

- Offline mobile SQLite cache; live URL reputation/fetching; trained-model activation/release UI; managed monitoring/alerts and fault-tolerance tests under network partitions.
- Campaign time/template ranking and advanced merge/split controls. Current grouping uses reviewed report lists with explicit shared-domain/phone evidence.
- Migration to Next.js, Celery/Redis or S3. The existing dashboard, database queue and private filesystem were preserved as requested.
- Demo video/presentation and production publication.

See [release verification](release-verification.md) for commands, versions, failures fixed, coverage and next actions. Dashboard/API and worker were restarted at **http://localhost:8015** after the backed-up migration.
