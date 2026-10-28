# ScamShield AI

Local release candidate for message/URL detection, screenshot OCR, mobile scanning and analyst investigation. A separate worker persists versioned results. Explainable rules have an optional locally trained static URL classifier; the three-class text candidate remains disabled after failing its validation gate. Historical-source benchmark results are measured, but production accuracy, calibrated probabilities and multilingual performance are not established.

## Start on Windows

From `D:\ScamShield AI`:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
$env:DEV_EMAIL_TOKENS = '1'
.\.venv\Scripts\python.exe -m alembic -c backend/alembic.ini upgrade head
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --no-access-log
```

Open **http://localhost:8000**. In another terminal from the same project folder:

```powershell
.\.venv\Scripts\python.exe -m backend.app.worker
```

Register, use the development email token shown in the verification dialog, sign in, paste a message, and open the result. The worker must run for queued scans to finish. In development the verification token is returned only when `DEV_EMAIL_TOKENS=1`; otherwise configure SMTP. `.env.example` documents settings; plain Python commands read environment variables, not `.env` automatically.

Interactive API documentation: **http://localhost:8000/docs**.

If port 8000 is occupied, launch with `--port 8015`, open `http://localhost:8015`, and use that port in the mobile API URL. Validation used port 8015 because another process already owned port 8000.

## Staff access

Create the first administrator through a local operator command, which prompts for a password and prints a new TOTP enrollment secret:

```powershell
.\.venv\Scripts\python.exe -m backend.app.manage create-admin --email admin@example.com
```

Add the secret to an authenticator app; enter the current code at login. Regular users can enroll an authenticator under Account & privacy. Admins may then promote them using Team & roles. Privileged logins require MFA. There are no default privileged credentials.

For an optional local demo, run `python -m backend.app.demo`. On localhost the login page shows `demo@scamshield.test` / `ScamShieldDemo123!` and a **Try demo** button that fills and submits the login form. The demo is a regular user account; use sample content only. It is provisioned explicitly, never automatically at startup or deployment.

## Mobile app

<p align="center">
  <img src="docs/images/android-app.jpg" alt="ScamShield AI Android Mobile App" width="340" />
</p>

```powershell
cd apps/mobile
npm.cmd ci
$env:EXPO_PUBLIC_API_URL = 'http://YOUR-PC-LAN-IP:8000/api'
npm.cmd start
```

Use an Expo Go version compatible with SDK 54, or an Expo development build, on the same network. Android emulator defaults to `http://10.0.2.2:8000/api`. Physical devices need the PC’s LAN address; localhost points to the phone itself. Allow the API through the local firewall as appropriate. Release builds must use an HTTPS endpoint.

Mobile sessions use Expo SecureStore. Scan history is read from the server; offline SQLite caching is not implemented. For an Android APK, configure your Expo/EAS account and run `npx eas-cli build --platform android --profile preview`. No APK has been built or signed in this environment.

## Docker development stack

```powershell
$env:POSTGRES_PASSWORD = 'choose-a-long-random-url-safe-password'
docker compose up --build
```

Dashboard/API: `http://localhost:8000`; development email inbox: `http://localhost:8025`. Includes PostgreSQL, API, worker, Tesseract with English/Sinhala/Tamil language packs, and Mailpit. Compose is for local development; production needs TLS, external mail delivery, protected networking and backups. Docker execution has not been validated here.

On Windows without Docker, install Tesseract and `eng`, `sin`, `tam` data separately and add its executable to PATH. Missing OCR is shown as Inconclusive with manual text entry. OCR extraction always requires user confirmation before detection.

## Checks

```powershell
python -m pytest backend/tests -q
node --check apps/dashboard/app.js
cd apps/mobile
npm.cmd run typecheck
```

See [architecture](docs/architecture.md), [acceptance and status](docs/status.md), [operations](docs/operations.md), [dataset and model cards](docs/model-data.md), and [demo script](docs/demo.md).

## Release verification

See [the verification record](docs/release-verification.md) and [staging/Android instructions](docs/staging-android.md). No public deployment has been made. The existing local database was backed up to `backups/pre-release-0002` before migration 0002; the local dashboard and worker run at **http://localhost:8015**.

Additional reproducible checks (destructive fixtures use temporary databases):

```powershell
python -m pip install -r backend/requirements-verification.txt -r ml/requirements.txt
python scripts/verify_migrations.py
python scripts/verify_exclusions.py
python scripts/verify_browser.py
python -m backend.tests.benchmark
python scripts/verify_evaluation.py
```

Browser automation uses installed Chrome on Windows; set CHROME_PATH for another executable. It uses controlled OCR fixtures and does not visit suspected malicious URLs. Verification dependencies are separate from normal backend startup requirements. Evaluation fixtures are explicitly synthetic and make no accuracy claim.

Verification resend is on the login page. Authenticator enrollment shows eight recovery codes once. Login accepts a password plus authenticator or unused recovery code. Regeneration under Account & privacy requires reauthentication and revokes all sessions. Save codes privately. Resend responses remain generic during cooldown.

`/api/health` checks the database; `/api/ready` requires a recent worker heartbeat; `/api/admin/metrics` requires an admin session. Dashboard requests remain same-origin, and mobile API URLs use EXPO_PUBLIC_API_URL.

This implementation deliberately uses a database-backed queue, private filesystem storage, and a buildless dashboard to make local setup small. PostgreSQL is supported; Celery/Redis, S3, Next.js, calibrated ML, and production hosting from the broader plan remain future work. No public site was deployed.

## Current detection and evaluation

The supplied Mendeley SMS and PhiUSIIL archives have now been inventoried, cleaned, split, trained and evaluated. The URL model `scamshield-url-v1` is enabled on the local port-8015 worker; the text candidate failed validation and stays disabled. Rules-only is still the default when model configuration is absent. See the [complete commands, measured results, activation/fallback and source limitations](docs/model-workflow-v1.md), [v1 acceptance checklist](docs/v1-checklist.md) and [fresh running results](docs/models-live-verification.json). Backend suite now passes **101 tests**. PostgreSQL/Docker, installable Android/device, real OCR quality and external delivery remain blocked; v1 is not fully signed off.

Local API/dashboard and worker run at http://localhost:8015 with rules-1.2.0. Fresh A/B scans and 92 backend tests pass; historical results remain unchanged. See [current status](docs/status.md) and [runtime evidence](docs/detection-live-verification.json). Scores are indicator sums, not probabilities; no indicators means Inconclusive.

New URL results expose the actual hostname, offline PSL domain boundary and unavailable live checks as non-clickable text on dashboard/mobile. See [URL policy and limitations](docs/url-analysis.md).

The earlier rules-first evaluator, [annotation guide](docs/rules-evaluation.md), [collection template](ml/data/collection-template.csv) and [publisher dataset review](docs/dataset-source-review.md) remain available. Run `python scripts/verify_rules_evaluator.py` for synthetic software validation. The supplied-data workflow above adds measured historical-source benchmarks and optional URL inference; representative deployment accuracy and calibration remain unestablished.
