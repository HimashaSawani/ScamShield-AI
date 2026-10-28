# ScamShield AI — Reproducible Local Portfolio Demo Guide

This guide provides an exact, step-by-step **2–3 minute local portfolio demonstration** of ScamShield AI for technical interviews, portfolio walkthroughs, and LinkedIn video recordings. All inputs are synthetic and safe; no external URLs are fetched or visited.

---

## 1. Prerequisites & Pre-Demo Startup (PowerShell)

Open two PowerShell terminals in `D:\ScamShield AI`.

### Terminal 1 — Database Migration, Demo Account & FastAPI Server
```powershell
cd "D:\ScamShield AI"
$env:DATABASE_URL = "sqlite:///./scamshield.db"
$env:STORAGE_PATH = "./storage"
$env:DEV_EMAIL_TOKENS = "1"
$env:SCAMSHIELD_MODEL_DIR = "D:\ScamShield AI\ml\artifacts\v1-json"
$env:SCAMSHIELD_MODEL_MANIFEST_SHA256 = "833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9"

# Ensure schema is at head and provision the local demo account
.\.venv-release\Scripts\python.exe -m alembic -c backend/alembic.ini upgrade head
.\.venv-release\Scripts\python.exe -m backend.app.demo

# Start the API & Web Dashboard on port 8000
.\.venv-release\Scripts\python.exe -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --no-access-log
```

### Terminal 2 — Durable Background Queue Worker (with URL ML Enabled)
```powershell
cd "D:\ScamShield AI"
$env:DATABASE_URL = "sqlite:///./scamshield.db"
$env:STORAGE_PATH = "./storage"
$env:SCAMSHIELD_MODEL_DIR = "D:\ScamShield AI\ml\artifacts\v1-json"
$env:SCAMSHIELD_MODEL_MANIFEST_SHA256 = "833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9"

.\.venv-release\Scripts\python.exe -m backend.app.worker
```

### Verify Health & Readiness
```powershell
Invoke-RestMethod http://localhost:8000/api/health
# Expected: @{status=ok; version=rules-1.2.0}

Invoke-RestMethod http://localhost:8000/api/ready
# Expected: @{status=ready}
```

---

## 2. Reproducible 2–3 Minute Live Walkthrough

Open **`http://localhost:8000`** in Chrome or Edge.

### Step 1: One-Tap Demo Login & Workspace Overview (0:00 – 0:30)
1. On the login screen, point out the localhost-only **Explore the Demo** card (`demo@scamshield.test` / `ScamShieldDemo123!`).
2. Click **Try demo — fill & sign in ↗**.
3. On the **Overview** dashboard (`#overview`), highlight:
   - Live scan counters (**Total scans**, **High risk signals**, **Analysis completed**, **In progress**).
   - Quick-scan entry points for **Message**, **Screenshot**, and **URL**.
   - Transparent non-guarantee notice: scores represent deterministic indicator weights, never calibrated probabilities or safety guarantees.

### Step 2: Text Scam Detection & Negation Protection (0:30 – 1:15)
1. Navigate to **New scan** (`#scan`) and select **▤ Message**.
2. Paste a synthetic credential-theft message:
   ```text
   URGENT: Your bank account will be blocked today. Reply with your password and OTP immediately to keep your account active.
   ```
3. Click **Analyze message ↗**.
4. In the result modal, highlight:
   - **Assessment:** `High` | **Processing:** `Completed` | **Indicator score:** `65/100` (`rules-1.2.0`).
   - Exact character-level `<mark>` highlights on `"account will be blocked"` (`+20` urgency) and `"Reply with your password and OTP"` (`+45` credential disclosure request).
5. Close the modal and scan a **legitimate protective OTP notification**:
   ```text
   Your verification code is 123456. Never share this code with anyone. Our staff will never ask for your password or OTP.
   ```
6. Highlight that the result is **`Inconclusive` (`0/100`)** with **zero false-positive credential flags**, demonstrating clause-scoped negation protection (`Never share...`, `never ask...`).
7. *(Optional Multilingual Check)* Paste a Sinhala or Singlish scam message:
   ```text
   Urgent alert: Obe bank account eka block wela. Ikmanin otp ewanna nathnam account close wei.
   ```
   Show that local-language/Singlish action rules (`ikmanin`, `otp ewanna`) trigger `High` (`65/100`) with exact span evidence.

### Step 3: Offline URL Inspection & Integrity-Pinned URL ML (1:15 – 1:55)
1. In **New scan** (`#scan`), switch to the **↗ URL** tab.
2. Paste a deceptive user-info URL:
   ```text
   https://bank.invalid@account-check.invalid/login
   ```
3. Click **Analyze link ↗** and highlight:
   - **URL destination details** card renders the link as non-clickable plain text (never visits or resolves the destination).
   - Separates **User information before `@`** (`bank.invalid`) from the **Actual hostname** (`account-check.invalid`).
   - Shows `URL model abstained: IP/unknown suffix outside reviewed named-domain scope`.
4. Next, scan a named-domain phishing-style URL where static rules alone score below the `Medium` threshold (`20/100`):
   ```text
   https://apple-verify.example.com/login
   ```
5. Point out:
   - **Offline PSL boundary:** Registrable domain `example.com`, subdomain `apple-verify`.
   - **Model predictions:** `rules-plus-model` with active **`scamshield-url-v1`** (`prediction: phishing`), which elevates an otherwise `Inconclusive` (`20/100`) result to `Medium` without fabricating rule evidence spans or altering the deterministic indicator score.

### Step 4: Screenshot Upload, OCR Preview & Manual Confirmation (1:55 – 2:30)
1. In **New scan** (`#scan`), select **▧ Screenshot**.
2. Upload any valid PNG or JPEG screenshot (up to 5 MB).
   - Server validates file signature, dimensions, strips EXIF metadata, and stores a re-encoded PNG in private storage (`./storage`).
3. Show the **OCR Confirmation Step** (`awaiting_confirmation` when Tesseract is installed, or `partially_completed` manual-entry fallback when Tesseract is absent):
   - Explain why ScamShield AI **always requires human text confirmation** before running scam rules (preventing OCR hallucinations from silently producing false assessments).
4. Enter or confirm:
   ```text
   URGENT: Reply with your OTP code immediately to avoid account suspension.
   ```
5. Click **Confirm text & analyze ↗** and show the resulting `High` (`65/100`) assessment.

### Step 5: Scan History, Detection Model Transparency & Analyst Workflow (2:30 – 3:00)
1. Click **Scan history** (`#history`) and filter scans using the live search bar.
2. Open a completed scan and click **Request analyst review** to explicitly share that scan with staff (unreported scans remain private to the owner).
3. Click **Detection model** (`#model`) to show versioned rules (`rules-1.2.0`), active integrity-pinned model status (`scamshield-url-v1`), supported language patterns (`English · Sinhala · Tamil · Singlish`), and explicit coverage boundaries.
4. *(Optional Staff/Admin View)* Create an admin in terminal (`.\.venv-release\Scripts\python.exe -m backend.app.manage create-admin --email admin@scamshield.test`), sign in with TOTP MFA, review the submitted report in **Review queue** (`#queue`), inspect shared entities in **Campaign graph** (`#campaigns`), and view **Team & roles** (`#users`) and **Audit history** (`#audit`).
