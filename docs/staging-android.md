# Staging and Android delivery

Current optional model release: see [model workflow v1](model-workflow-v1.md). The image now installs pinned ML dependencies; model artifacts are excluded from the build and mounted read-only from `infra/models` at `/models`. Only set SCAMSHIELD_MODEL_DIR and its reviewed manifest pin after copying the approved data-only bundle. Default is rules-only. Keep artifact/manifest/report/code-image versions with matched database/private-file backups; rollback the pin and code deliberately and restart API/workers together. The text model failed eligibility and remains disabled. Docker execution is still unverified.

No deployment or paid service was created. Configuration in `infra/compose.staging.yaml` is prepared but unverified because Docker is unavailable on this machine.

## Prepare staging

1. Finish the PostgreSQL/container checks below on a Docker host, including restart persistence and private-volume ownership.
2. Build a versioned image with `docker build -f infra/Dockerfile -t scamshield:YOUR_RELEASE_TAG .`. Use a registry/image digest appropriate to the actual host; do not use an unreviewed latest tag.
3. Copy `.env.staging.example` to a protected `.env.staging` and supply the image tag, DNS hostname, URL-safe PostgreSQL password, SMTP credentials, sender and retention period. Keep it out of source control. Prefer a secret manager for a hosted deployment.
4. Validate with `docker compose --env-file .env.staging -f infra/compose.staging.yaml config --quiet`. Do not print the expanded configuration into shared logs; it contains secrets.
5. After hosting authorization, point DNS to the host and allow ports 80/443 for Caddy certificate issuance. Caddy proxies HTTPS to the private API, limits request bodies and adds security headers. Verify certificate issuance and hostname before using real accounts.
6. Start with `docker compose --env-file .env.staging -f infra/compose.staging.yaml up -d`. The migration service must complete before API starts. Check `/api/health` and `/api/ready`; the latter requires a recent worker heartbeat.
7. Confirm SMTP delivery and password reset at the actual provider. Development tokens are explicitly disabled. Do not deploy the optional local demo account or development Mailpit inbox.

Containers use UID 10001 for API/worker, private `/data`, read-only root filesystems in staging, shared screenshot volumes and writable temporary directories for Tesseract. Verify actual ownership/modes inside the running images; these declarations have not been container-tested. API liveness depends on the database; readiness depends on a worker heartbeat. The worker healthcheck currently detects any live worker, not each individual replica: use per-instance heartbeats before replica-level orchestration.

## PostgreSQL verification still required

Use only a new dedicated database ending in `_test`. The test suite destroys its test schema. It refuses other database names when SCAMSHIELD_TEST_DATABASE_URL is configured.

```powershell
$env:DATABASE_URL = 'postgresql+psycopg://USER:PASSWORD@HOST:5432/scamshield_test'
$env:SCAMSHIELD_TEST_DATABASE_URL = $env:DATABASE_URL
python -m alembic -c backend/alembic.ini upgrade head
python -m alembic -c backend/alembic.ini check
python -m pytest backend/tests -q
```

The CI PostgreSQL job prepares this path automatically, but it has not run here. Separately test full containers: enqueue a scan, stop/restart API and worker, and check records, attachments and review outcomes persist. Run two worker containers against the same queue. Verify one active claim, lease renewal, stale-owner fencing and bounded crash recovery on PostgreSQL. Test upload directory ownership and file modes; Windows chmod results are not Linux permission verification.

## Rollback

Retain the previous API/worker image, database dump and screenshot snapshot as a matched release set. Migration 0002 adds leases, recovery codes, heartbeats and counters. Restore the prior image only after schema-compatibility review; old workers do not understand the new lease protocol and must not run alongside new workers. For destructive reversals restore into a fresh database and storage volume, verify it, and switch traffic deliberately. Do not downgrade the live database as an automatic rollback action.

## Android

Application ID: `lk.scamshield.app`. Expo SDK 54 / React Native 0.81.5. The app requests photo selection; camera and microphone permissions are disabled in the image-picker plugin. Android manifest permissions still need inspection after native generation. SecureStore holds the bearer session; EXPO_PUBLIC_API_URL configures the endpoint at build/start time.

```powershell
cd apps/mobile
$env:EXPO_PUBLIC_API_URL = 'https://YOUR_STAGING_HOST/api'
npm.cmd ci
npm.cmd run typecheck
npx expo export --platform android --output-dir dist
```

- **Expo export:** JavaScript/Hermes and assets only; not an installable app.
- **Debug APK:** requires a JDK and Android build tools. After configuring JAVA_HOME/ANDROID_HOME, run `npx expo prebuild --platform android --no-install`, then in `android`, run `.\gradlew.bat assembleDebug`. Debug signing is for development only.
- **Signed release APK:** `npx eas-cli build --platform android --profile preview` requires Expo/EAS account access and signing configuration. Confirm the returned artifact type and signature; a queued build is not a delivered APK.
- **Production AAB:** the production profile requests an Android App Bundle. It is separate from a directly installable APK.
- **Real-device E2E:** install the actual artifact with `adb install`, exercise login/verification/reset, text/URL/screenshot scans, failure states, history, reviews, deletion and expired sessions against staging. Check physical screenshots and network transitions. Browser checks and exports do not count as this verification.

Local inspection found SDK platform android-36 and build-tools 36.1.0, but no Java on PATH or the standard Android Studio JBR location. `adb devices` returned no connected devices. No build/signing account or staging credentials were supplied. Debug APK, signed release APK and real-device results therefore remain blocked. Never commit keystores, signing passwords or service-account credentials.
