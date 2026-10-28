"""Full End-to-End Live Verification of ScamShield AI (Workflows A through J).
Starts a real FastAPI/Uvicorn server and a real background worker process against an isolated
SQLite WAL database with SCAMSHIELD_MODEL_DIR and SCAMSHIELD_MODEL_MANIFEST_SHA256 enabled.
Never modifies or deletes user data in the primary scamshield.db.
"""
import base64
import hashlib
import hmac
import io
import json
import os
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SHA256 = "833de7d2d619c033da5fbb71d266793861e498ef5cbcd592a283df843c6ff5a9"


def totp_code(secret_b32: str) -> str:
    key = base64.b32decode(secret_b32)
    block = hmac.new(key, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
    offset = block[-1] & 15
    val = (struct.unpack(">I", block[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{val:06d}"


def main():
    with tempfile.TemporaryDirectory(prefix="scamshield-final-e2e-", ignore_cleanup_errors=True) as tmp:
        folder = Path(tmp)
        db_path = folder / "e2e-live.db"
        storage_path = folder / "storage"
        storage_path.mkdir(parents=True, exist_ok=True)

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        base_url = f"http://127.0.0.1:{port}/api"
        env = {
            **os.environ,
            "DATABASE_URL": f"sqlite:///{db_path}",
            "STORAGE_PATH": str(storage_path),
            "DEV_EMAIL_TOKENS": "1",
            "SCAMSHIELD_MODEL_DIR": str(ROOT / "ml" / "artifacts" / "v1-json"),
            "SCAMSHIELD_MODEL_MANIFEST_SHA256": MANIFEST_SHA256,
        }
        env.pop("SMTP_HOST", None)

        # 1. Run database migrations
        subprocess.run(
            [sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "upgrade", "head"],
            cwd=ROOT,
            env=env,
            check=True,
        )

        # 2. Provision demo account explicitly via backend.app.demo
        subprocess.run([sys.executable, "-m", "backend.app.demo"], cwd=ROOT, env=env, check=True)

        py_exe = sys._base_executable if os.name == "nt" else sys.executable
        if os.name == "nt":
            env["PYTHONPATH"] = str(Path(sys.prefix) / "Lib" / "site-packages") + os.pathsep + str(ROOT)

        api_log = (folder / "api.log").open("w", encoding="utf-8")
        worker_log = (folder / "worker.log").open("w", encoding="utf-8")

        server = subprocess.Popen(
            [py_exe, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
            cwd=ROOT,
            env=env,
            stdout=api_log,
            stderr=api_log,
        )
        worker = subprocess.Popen(
            [py_exe, "-m", "backend.app.worker"],
            cwd=ROOT,
            env=env,
            stdout=worker_log,
            stderr=worker_log,
        )

        def api(path, method="GET", body=None, token=None, headers_extra=None):
            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            if headers_extra:
                headers.update(headers_extra)
            data = None
            if body is not None:
                if isinstance(body, (bytes, bytearray)):
                    data = body
                else:
                    headers["Content-Type"] = "application/json"
                    data = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(f"{base_url}{path}", data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw = resp.read().decode("utf-8")
                    return resp.status, json.loads(raw) if raw else {}
            except urllib.error.HTTPError as err:
                raw = err.read().decode("utf-8")
                try:
                    return err.code, json.loads(raw)
                except Exception:
                    return err.code, {"error": raw}

        def poll_scan(scan_id, token, timeout_s=30):
            deadline = time.time() + timeout_s
            while time.time() < deadline:
                st, data = api(f"/scans/{scan_id}", token=token)
                assert st == 200, f"Poll failed: {st} {data}"
                if data["status"] not in ("queued", "processing"):
                    return data
                time.sleep(0.25)
            raise TimeoutError(f"Scan {scan_id} did not finish within {timeout_s}s")

        workflows = {}
        try:
            # Wait for /api/ready (verifies both API and worker heartbeat)
            for _ in range(80):
                try:
                    st, data = api("/ready")
                    if st == 200:
                        break
                except urllib.error.URLError:
                    pass
                time.sleep(0.25)
            else:
                raise RuntimeError("API and worker failed readiness check")

            st_health, health_data = api("/health")
            assert st_health == 200 and health_data.get("status") == "ok"

            # -----------------------------------------------------------------
            # WORKFLOW A: Register -> Verify -> Login -> Logout
            # -----------------------------------------------------------------
            email_a = "alice_e2e@scamshield.test"
            pwd_a = "AliceSecurePass123!"
            st_reg, reg_res = api("/auth/register", "POST", {"email": email_a, "password": pwd_a})
            assert st_reg == 201 and "development_token" in reg_res
            # Unverified login must be rejected with 403
            st_unver, _ = api("/auth/login", "POST", {"email": email_a, "password": pwd_a})
            assert st_unver == 403
            # Verify email
            st_ver, ver_res = api("/auth/verify", "POST", {"token": reg_res["development_token"]})
            assert st_ver == 200
            # Login
            st_log, log_res = api("/auth/login", "POST", {"email": email_a, "password": pwd_a})
            assert st_log == 200 and "token" in log_res
            token_a = log_res["token"]
            # Logout
            st_out, _ = api("/auth/logout", "POST", token=token_a)
            assert st_out == 200
            st_me_after, _ = api("/me", token=token_a)
            assert st_me_after == 401
            # Log back in for subsequent workflows
            _, log_res = api("/auth/login", "POST", {"email": email_a, "password": pwd_a})
            token_a = log_res["token"]
            workflows["A_register_verify_login_logout"] = {
                "status": "PASS",
                "evidence": {
                    "register_http": st_reg,
                    "unverified_login_http": st_unver,
                    "verify_http": st_ver,
                    "login_http": st_log,
                    "logout_http": st_out,
                    "post_logout_me_http": st_me_after,
                },
            }

            # Verify /api/model reports active URL ML model
            st_mod, mod_data = api("/model", token=token_a)
            assert st_mod == 200
            assert mod_data["models"]["mode"] == "rules-plus-model"
            assert mod_data["models"]["enabled"] == [{"kind": "url", "version": "scamshield-url-v1"}]

            # -----------------------------------------------------------------
            # WORKFLOW B: Suspicious synthetic URL -> queue -> worker -> result -> explanation -> history
            # -----------------------------------------------------------------
            susp_url = "http://paypal-login-verify.example.com/portal/signin"
            st_b, scan_b_init = api("/scans", "POST", {"kind": "url", "text": susp_url}, token=token_a)
            assert st_b == 202
            scan_b = poll_scan(scan_b_init["id"], token_a)
            assert scan_b["status"] == "completed"
            assert scan_b["result"]["assessment"] in ("High", "Medium")
            assert scan_b["result"]["model_mode"] == "rules-plus-model"
            assert any(m["version"] == "scamshield-url-v1" and m["prediction"] == "phishing" for m in scan_b["result"]["models"])
            st_hist, hist_a = api("/scans", token=token_a)
            assert st_hist == 200 and any(s["id"] == scan_b["id"] for s in hist_a)
            workflows["B_suspicious_url_scan"] = {
                "status": "PASS",
                "evidence": {
                    "scan_id": scan_b["id"],
                    "assessment": scan_b["result"]["assessment"],
                    "score": scan_b["result"]["score"],
                    "model_mode": scan_b["result"]["model_mode"],
                    "models": scan_b["result"]["models"],
                    "evidence_codes": [e["code"] for e in scan_b["result"]["evidence"]],
                    "in_history": True,
                },
            }

            # -----------------------------------------------------------------
            # WORKFLOW C: Benign URL -> result -> history
            # -----------------------------------------------------------------
            benign_url = "https://www.southbankmosaics.com"
            st_c, scan_c_init = api("/scans", "POST", {"kind": "url", "text": benign_url}, token=token_a)
            assert st_c == 202
            scan_c = poll_scan(scan_c_init["id"], token_a)
            assert scan_c["status"] == "completed"
            assert scan_c["result"]["assessment"] == "Inconclusive"
            assert scan_c["result"]["score"] == 0
            assert scan_c["result"]["models"][0]["prediction"] == "legitimate"
            workflows["C_benign_url_scan"] = {
                "status": "PASS",
                "evidence": {
                    "scan_id": scan_c["id"],
                    "assessment": scan_c["result"]["assessment"],
                    "score": scan_c["result"]["score"],
                    "model_prediction": scan_c["result"]["models"][0]["prediction"],
                },
            }

            # -----------------------------------------------------------------
            # WORKFLOW D: Suspicious synthetic message -> result -> evidence
            # -----------------------------------------------------------------
            susp_msg = "URGENT: Your bank account will be suspended today. Reply with your password and OTP immediately."
            st_d, scan_d_init = api("/scans", "POST", {"kind": "text", "text": susp_msg}, token=token_a)
            assert st_d == 202
            scan_d = poll_scan(scan_d_init["id"], token_a)
            assert scan_d["status"] == "completed"
            assert scan_d["result"]["assessment"] == "High"
            assert scan_d["result"]["score"] == 65
            assert {"credentials", "urgency"} <= {e["code"] for e in scan_d["result"]["evidence"]}
            workflows["D_suspicious_message_scan"] = {
                "status": "PASS",
                "evidence": {
                    "scan_id": scan_d["id"],
                    "assessment": scan_d["result"]["assessment"],
                    "score": scan_d["result"]["score"],
                    "evidence_codes": [e["code"] for e in scan_d["result"]["evidence"]],
                },
            }

            # -----------------------------------------------------------------
            # WORKFLOW E: Benign message -> verify classification
            # -----------------------------------------------------------------
            benign_msg = "Your verification code is 654321. Never share this code with anyone. Our staff will never ask for your password or OTP."
            st_e, scan_e_init = api("/scans", "POST", {"kind": "text", "text": benign_msg}, token=token_a)
            assert st_e == 202
            scan_e = poll_scan(scan_e_init["id"], token_a)
            assert scan_e["status"] == "completed"
            assert scan_e["result"]["assessment"] == "Inconclusive"
            assert scan_e["result"]["score"] == 0
            assert scan_e["result"]["evidence"] == []
            workflows["E_benign_message_scan"] = {
                "status": "PASS",
                "evidence": {
                    "scan_id": scan_e["id"],
                    "assessment": scan_e["result"]["assessment"],
                    "score": scan_e["result"]["score"],
                    "evidence_count": len(scan_e["result"]["evidence"]),
                },
            }

            # -----------------------------------------------------------------
            # WORKFLOW F: Upload synthetic screenshot -> OCR -> correction -> detection
            # -----------------------------------------------------------------
            # Also verify invalid file rejection
            boundary = "----ScamShieldBoundaryE2E"
            bad_body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="bad.png"\r\n'
                f"Content-Type: image/png\r\n\r\n"
                f"not-a-valid-png-payload\r\n"
                f"--{boundary}--\r\n"
            ).encode("utf-8")
            st_bad_img, _ = api(
                "/scans/screenshot",
                "POST",
                bad_body,
                token=token_a,
                headers_extra={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
            assert st_bad_img == 422

            # Valid synthetic PNG upload
            img = Image.new("RGB", (320, 120), "white")
            draw = ImageDraw.Draw(img)
            draw.text((15, 45), "URGENT: Send OTP now", fill="black")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            good_body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="synthetic.png"\r\n'
                f"Content-Type: image/png\r\n\r\n"
            ).encode("utf-8") + buf.getvalue() + f"\r\n--{boundary}--\r\n".encode("utf-8")
            st_f, scan_f_init = api(
                "/scans/screenshot",
                "POST",
                good_body,
                token=token_a,
                headers_extra={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
            assert st_f == 202
            scan_f_ocr = poll_scan(scan_f_init["id"], token_a)
            assert scan_f_ocr["status"] in ("awaiting_confirmation", "partially_completed")
            ocr_stage_status = scan_f_ocr["status"]
            st_conf, _ = api(
                f"/scans/{scan_f_init['id']}/confirm",
                "POST",
                {"kind": "text", "text": "URGENT: Your account is suspended. Reply with your OTP immediately."},
                token=token_a,
            )
            assert st_conf == 200
            scan_f_done = poll_scan(scan_f_init["id"], token_a)
            assert scan_f_done["status"] == "completed"
            assert scan_f_done["result"]["assessment"] == "High"
            workflows["F_screenshot_ocr_correction_detection"] = {
                "status": "PASS",
                "evidence": {
                    "invalid_image_http": st_bad_img,
                    "scan_id": scan_f_done["id"],
                    "ocr_stage_status": ocr_stage_status,
                    "final_status": scan_f_done["status"],
                    "final_assessment": scan_f_done["result"]["assessment"],
                    "final_score": scan_f_done["result"]["score"],
                },
            }

            # -----------------------------------------------------------------
            # WORKFLOW G & H: Two users -> private scan isolation & Analyst review reflection
            # -----------------------------------------------------------------
            email_b = "bob_analyst@scamshield.test"
            pwd_b = "BobAnalystPass123!"
            _, reg_b = api("/auth/register", "POST", {"email": email_b, "password": pwd_b})
            api("/auth/verify", "POST", {"token": reg_b["development_token"]})
            _, log_b = api("/auth/login", "POST", {"email": email_b, "password": pwd_b})
            token_b = log_b["token"]

            # Workflow H: User B attempts to read or delete User A's private scan
            st_iso_read, _ = api(f"/scans/{scan_d['id']}", token=token_b)
            st_iso_del, _ = api(f"/scans/{scan_d['id']}", "DELETE", token=token_b)
            assert st_iso_read == 404 and st_iso_del == 404
            workflows["H_two_user_private_scan_isolation"] = {
                "status": "PASS",
                "evidence": {
                    "cross_user_read_http": st_iso_read,
                    "cross_user_delete_http": st_iso_del,
                },
            }

            # Workflow G: Enroll MFA for User B, promote to admin/analyst, review User A's report
            secret_b = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
            st_mfa, mfa_res = api("/auth/mfa", "POST", {"secret": secret_b, "otp": totp_code(secret_b)}, token=token_b)
            assert st_mfa == 200 and len(mfa_res.get("recovery_codes", [])) == 8

            with sqlite3.connect(db_path) as con:
                con.execute("UPDATE users SET role = 'admin' WHERE email = ?", (email_b,))
                con.commit()

            # User A submits scan_d for analyst review
            st_rep, rep_res = api(
                f"/scans/{scan_d['id']}/report",
                "POST",
                {"reason": "Suspicious bank OTP demand"},
                token=token_a,
            )
            assert st_rep == 201
            report_id = rep_res["id"]

            # Analyst/Admin B fetches queue and submits decision
            st_q, queue_list = api("/reports", token=token_b)
            assert st_q == 200 and any(r["id"] == report_id for r in queue_list)
            st_dec, _ = api(
                f"/reports/{report_id}/decision",
                "POST",
                {"verdict": "Confirmed scam", "reason": "Verified credential harvesting + urgency"},
                token=token_b,
            )
            assert st_dec == 200

            # Verify verdict appears in User A's scan history
            _, scan_d_reflected = api(f"/scans/{scan_d['id']}", token=token_a)
            assert scan_d_reflected["reviews"][0]["verdict"] == "Confirmed scam"
            workflows["G_analyst_review_verdict_in_history"] = {
                "status": "PASS",
                "evidence": {
                    "report_id": report_id,
                    "queue_http": st_q,
                    "decision_http": st_dec,
                    "user_history_verdict": scan_d_reflected["reviews"][0]["verdict"],
                },
            }

            # -----------------------------------------------------------------
            # WORKFLOW I: Worker interruption -> recovery -> scan completion
            # -----------------------------------------------------------------
            worker.terminate()
            worker.wait(timeout=10)

            st_i, scan_i_init = api(
                "/scans",
                "POST",
                {"kind": "text", "text": "URGENT: Send your OTP code now to unblock account."},
                token=token_a,
            )
            assert st_i == 202
            scan_i_id = scan_i_init["id"]
            # Simulate an interrupted worker holding a stale lease (>180s old)
            with sqlite3.connect(db_path) as con:
                con.execute(
                    "UPDATE scans SET status = 'processing', lease = 'crashed-worker-lease', updated = ?, attempts = 1 WHERE id = ?",
                    (time.time() - 240, scan_i_id),
                )
                con.commit()

            # Restart worker and verify stale lease recovery + completion
            worker = subprocess.Popen(
                [py_exe, "-m", "backend.app.worker"],
                cwd=ROOT,
                env=env,
                stdout=worker_log,
                stderr=worker_log,
            )
            scan_i_done = poll_scan(scan_i_id, token_a, timeout_s=30)
            assert scan_i_done["status"] == "completed"
            assert scan_i_done["result"]["assessment"] == "High"
            workflows["I_worker_interruption_and_recovery"] = {
                "status": "PASS",
                "evidence": {
                    "scan_id": scan_i_id,
                    "recovered_from_stale_lease": True,
                    "final_status": scan_i_done["status"],
                    "final_assessment": scan_i_done["result"]["assessment"],
                },
            }

            # -----------------------------------------------------------------
            # WORKFLOW J: Account deletion -> verify authorized data cleanup
            # -----------------------------------------------------------------
            st_del_acc, _ = api("/me", "DELETE", token=token_a)
            assert st_del_acc == 200
            st_after_del, _ = api("/scans", token=token_a)
            assert st_after_del == 401
            # Verify User A's scans, reports, and screenshot attachments are cleaned up
            with sqlite3.connect(db_path) as con:
                remaining_scans = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                remaining_reports = con.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            remaining_files = list(storage_path.glob("*.png"))
            assert remaining_scans == 0 and remaining_reports == 0 and len(remaining_files) == 0
            workflows["J_account_deletion_data_cleanup"] = {
                "status": "PASS",
                "evidence": {
                    "delete_http": st_del_acc,
                    "post_delete_scans_http": st_after_del,
                    "remaining_user_scans_in_db": remaining_scans,
                    "remaining_reports_in_db": remaining_reports,
                    "remaining_attachments_on_disk": len(remaining_files),
                },
            }

            summary = {
                "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "all_passed": all(w["status"] == "PASS" for w in workflows.values()),
                "workflow_count": len(workflows),
                "workflows": workflows,
            }
            out_file = ROOT / "docs" / "final_e2e_verification.json"
            out_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            print(json.dumps(summary, indent=2))
        finally:
            for proc in (worker, server):
                try:
                    proc.terminate()
                    proc.wait(timeout=10)
                except Exception:
                    pass
            api_log.close()
            worker_log.close()


if __name__ == "__main__":
    main()
