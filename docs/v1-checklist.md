# V1 acceptance checklist — 2026-10-23

V1 is a locally verified release candidate. Required PostgreSQL/container, Android installation, real OCR and external delivery checks remain blocked; the complete release is not signed off. Current checks supersede earlier milestone counts in status/release notes.

| Area | Current state | Evidence / remaining acceptance |
| --- | --- | --- |
| Registration, verification/resend, login/reset | Implemented and locally verified | Backend and 13-group Chrome suite; real provider email unverified |
| Staff MFA/recovery | Implemented and verified | Enrollment, recovery-code login, regeneration/reauthentication and revocation; no privileged bypass |
| Roles and ownership | Implemented and verified | Cross-user/staff API tests and analyst browser flows |
| Text rules | Implemented and verified | Fresh A High/65; B Inconclusive/0; clause/context regressions; multilingual accuracy unverified |
| Text model | Trained/evaluated; disabled | Three distinct publisher labels; validation gate failed; no activation |
| Static URLs | Implemented and verified | Shared production extractor, offline PSL, no destination fetching, safe display, failed/unavailable coverage |
| URL model | Enabled locally; source-benchmark verified | Domain-grouped held-out report and production JSON parity; external/time-held-out evaluation missing |
| Screenshots/OCR/correction | Pipeline verified | Real queue upload + manual correction and controlled engine fixtures; Tesseract binary/reviewed transcription corpus absent; no OCR quality claim |
| Evidence, coverage, versions | Implemented and verified | Separate badges/title/span/weight, model predictions separate, stored history hashes unchanged; narrow-screen Chrome checks |
| History/deletion/account deletion | Implemented and verified | Isolated backend/browser destructive tests; live acceptance adds sample history without deleting user data |
| Explicit sharing/analyst decisions/campaigns | Implemented and verified | Consent, separate decisions, staff checks, shared-domain/phone relationships; no feedback-to-label automation |
| Queue recovery/quotas/retention | Implemented and SQLite-verified | Atomic claims/counters, stale leases, bounded recovery and deletion tests; PostgreSQL behavior unverified |
| Data preparation/evaluation | Implemented and run | Actual archive inventory, conflicts/dedup/template/domain splits, training-only fitting, frozen validation selection and held-out reports |
| Dashboard | Implemented and Chrome-verified | 13 flow groups + live A/B/URL flows at 390/768/1440, zero JS errors; remaining accessibility/localization review deferred |
| Mobile | Implemented; source/export verified | TypeScript and Android Hermes export; installable debug/signed APK and device E2E blocked by JDK/signing/device access |
| Backup/recovery | SQLite verified | New isolated workload restores 40 rows/one attachment and integrity check; PostgreSQL/private-volume recovery unverified |
| Docker/PostgreSQL | Configuration prepared; execution blocked | Docker executable/runtime absent; no PostgreSQL service supplied; no SQLite substitution |
| Staging/email/TLS | Configuration and instructions prepared | Secret placeholders, private storage, health/readiness, read-only models and rollback; SMTP/DNS/hosting unavailable; no public deployment |
| Metrics/load | SQLite local verification | Bounded 40-request run; protected metrics/log redaction; not production capacity or network benchmark |
| Delivery/docs/demo | Delivered for local v1 | README, model workflow/cards/reports, deployment/recovery and demo; external acceptance dependencies explicitly remain |

Confirmed defects fixed during this follow-up: model JSON vocabulary export needed NumPy integer conversion; Windows browser fixture cleanup killed only a venv launcher; external font loading could hang offline browser tests; Docker ignore rules originally hid the newly required ML requirements file. Final checks passed after corrections. No application architecture rewrite or data migration occurred.

Outside v1: offline mobile cache, live URL fetching/reputation, advanced campaign time/template ranking, managed monitoring/alerts, model release UI, production fault-tolerance exercises, Next.js/Celery/S3 migration. No paid services, public publishing, signing material or fabricated benchmark records were created.

Remaining operator actions: review the [model/data workflow](model-workflow-v1.md) and source limitations; provision a Docker/PostgreSQL test host and execute [staging checks](staging-android.md); provide test SMTP/DNS/hosting only if deployment is desired; configure JDK/build/signing and connect a device; install Tesseract/language packs and obtain reviewed consented screenshot/transcription pairs; obtain independent contemporary language-specific evaluation data. A user-supplied dataset alone does not satisfy external-validity or OCR acceptance.
