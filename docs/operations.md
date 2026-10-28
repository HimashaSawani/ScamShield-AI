# Operations and recovery

## Deployment

Use separate development and staging databases/storage. Install pinned dependencies, configure SMTP, disable `DEV_EMAIL_TOKENS`, run Alembic upgrade once as a controlled release step, then start API and worker independently. Place API behind an HTTPS reverse proxy, enforce request size limits before multipart parsing, restrict allowed hosts/network access and use managed secrets. Never publish the local Mailpit inbox. Use an external managed PostgreSQL database and protected storage in production; private filesystem storage must be backed up and shared by workers.

The Python API serves dashboard assets at `/` and OpenAPI at `/docs`. Mobile requests need the `/api` suffix in EXPO_PUBLIC_API_URL. No CORS is needed for same-origin web or native mobile. The browser keeps its bearer token in sessionStorage and clears it at logout; adopt secure HttpOnly cookie sessions and CSP for a hardened web deployment. Application text is escaped before rendering. Fonts use Google Fonts with system fallbacks.

## Backup and deletion

The offline SQLite snapshot/restore tool has been exercised against an isolated full-schema database with 40 scans and one attachment. Stop API and workers first, then use new destination directories:

```powershell
python -m backend.app.backup backup --database scamshield.db --storage storage --output backups/NEW_SNAPSHOT --offline
python -m backend.app.backup restore --source backups/NEW_SNAPSHOT --output backups/NEW_RESTORE --offline
```

Restoration refuses overwrite, verifies file hashes and attachment references, and runs SQLite integrity checks. Hashes detect corruption; they do not authenticate a backup from an untrusted party. Backup files contain account/session data: restrict access and encrypt them using operator-managed storage. These SQLite results do not verify PostgreSQL recovery. For PostgreSQL, stop writers, create a pg_dump plus matching screenshot-volume snapshot, restore into a new database/volume, verify references and exercise the application before switching traffic. PostgreSQL restore remains blocked here.

For local SQLite, stop API/worker or use SQLite’s backup API for a consistent copy. For PostgreSQL use encrypted `pg_dump` backups with restricted access and matching private screenshot snapshots. A backup must include the migration revision, image tag, database and screenshot volume. Suggested initial policy: daily backups, 7-day backup expiry, tested quarterly; this is an operator policy to configure, not an implemented backup scheduler.

Restore into a fresh staging database and screenshot volume, run migration verification, start a worker and API, and validate login, scan, history, report and private image handling. Measure recovery time and document it before production. Account/scan deletion removes active records and files; old backups retain data until expiry. Review audit retention and deletion requests separately; audits omit message contents but retain actor/target identifiers.

Retention cleanup runs hourly in the worker, default 90 days via RETENTION_DAYS. It removes scan inputs, screenshots, feedback and reports and skips currently processing jobs. Explicit user deletion can remove an active scan; result writes are fenced by the surviving scan and lease so a deleted scan is not recreated. Large-scale deletion/filesystem atomicity and network-partition behavior still need operational exercises.

## Release and rollback

Build versioned API/worker images together. Apply additive migrations before traffic, retain the previous image, and verify `/api/health`. Rollback by restoring the previous image only when compatible with the current schema. Restore database/storage snapshots for destructive schema reversals. Rule versions are embedded in results; changing rules requires a source release. Trained-model release switching/rollback is not implemented.

## Monitoring and limits

Structured logs allowlist event names, generated request IDs, scan/job IDs, route templates, status, duration and attempts. They omit message text, credentials, tokens, OTPs and personal details. Unexpected request errors return a generic response so framework tracebacks do not dump SQL/input values. An admin session can read persistent counters and queue/stale counts at `/api/admin/metrics`. `/api/health` checks API/database liveness; `/api/ready` also requires a worker heartbeat newer than 90 seconds. Counts are cumulative; request latency uses a total/count, not a histogram. An external metrics scraper, alerts, retention for operational counters/audits, worker-specific replica checks, storage quotas and production fault injection remain future work. Development-token mode must stay local.

The durable DB queue is intended for a small deployment. Conditional claims, renewable leases and fenced writes prevent a stale owner from overwriting a newer result. OCR uses a 45-second timeout; leases renew every 20 seconds and become stale after 180 seconds. Retries and crash recovery exhaust after three attempts. SQLite concurrency tests passed; PostgreSQL and network-partition fault tests have not. Console logging was disabled in the bounded benchmark while persistent metrics remained active. See benchmark-results.json for measured local results, which are not production capacity targets.
# Optional model release operations

Current [dataset/model workflow](model-workflow-v1.md) supplies exact train/verify/activate/fallback commands. Keep the approved data-only bundle, manifest pin, source/split checksums and evaluation reports with the release image and matched database/private-file backups. Generated models are not included in the database backup command: copy them separately into protected versioned release storage. To roll back, restore the prior approved model directory/pin or clear both model variables for rules-only, restart API and workers, submit a fresh acceptance scan and confirm stored versions. Never rescore historical results implicitly. Stage models read-only and never accept uploaded executable artifacts. API/worker configurations must agree. Failure coverage and negative predictions must never imply verified safety.

