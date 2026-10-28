"""Verify PostgreSQL persistence across service restarts and correct database/storage paths."""
import os
import json
import secrets
from pathlib import Path
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

# Target isolated PostgreSQL database
PG_URL = os.getenv("SCAMSHIELD_TEST_DATABASE_URL", "postgresql+psycopg://scamshield:scamshield@127.0.0.1:5432/scamshield_test")
TEST_STORAGE = Path("D:/ScamShield AI/storage_test_pg")
TEST_STORAGE.mkdir(parents=True, exist_ok=True)

os.environ["DATABASE_URL"] = PG_URL
os.environ["STORAGE_PATH"] = str(TEST_STORAGE)

from backend.app.db import Base, User, Scan, Session, now
from backend.app.worker import process_one

def run_persistence_verification():
    print(f"Connecting to test database: {PG_URL}")
    engine = create_engine(PG_URL)
    LocalSession = sessionmaker(engine, expire_on_commit=False)

    # 1. Populate test data
    test_user_id = secrets.token_hex(16)
    test_scan_id = secrets.token_hex(16)
    test_email = f"persist_{secrets.token_hex(4)}@example.com"
    
    with LocalSession() as db:
        user = User(
            id=test_user_id,
            email=test_email,
            password="salt:dummyhash",
            role="user",
            verified=1
        )
        db.add(user)
        db.flush()
        scan = Scan(
            id=test_scan_id,
            owner_id=test_user_id,
            kind="text",
            text="Your bank account will be blocked today. Reply with your password and OTP immediately to keep your account active.",
            status="queued",
            created=now(),
            updated=now()
        )
        db.add(scan)
        db.commit()
    print("Step 1: Test user and scan written to PostgreSQL.")

    # 2. Simulate complete service shutdown / restart: dispose engine
    engine.dispose()
    print("Step 2: Service stopped (engine disposed).")

    # 3. Simulate new service startup: new engine and session
    new_engine = create_engine(PG_URL)
    NewSession = sessionmaker(new_engine, expire_on_commit=False)
    with NewSession() as db:
        user_check = db.scalar(select(User).where(User.id == test_user_id))
        scan_check = db.scalar(select(Scan).where(Scan.id == test_scan_id))
        assert user_check is not None, "User record lost after restart!"
        assert user_check.email == test_email
        assert scan_check is not None, "Scan record lost after restart!"
        assert scan_check.status == "queued"
    print("Step 3: Service restarted; verified persisted state in PostgreSQL.")

    # 4. Worker processes the queued job against PostgreSQL
    while True:
        with NewSession() as db:
            scan_check = db.scalar(select(Scan).where(Scan.id == test_scan_id))
            if scan_check.status == "completed":
                break
        worked = process_one()
        assert worked, "Worker queue ran out before test scan was completed"
    
    with NewSession() as db:
        completed_scan = db.scalar(select(Scan).where(Scan.id == test_scan_id))
        assert completed_scan.status == "completed", f"Expected completed, got {completed_scan.status}"
        res = json.loads(completed_scan.result)
        assert res.get("assessment") == "High", f"Expected High assessment, got {res.get('assessment')}"
    print(f"Step 4: Worker processed persisted job successfully. Result assessment: {res.get('assessment')}")

    # 5. Clean up test records
    with NewSession() as db:
        db.execute(text("DELETE FROM scans WHERE id = :sid"), {"sid": test_scan_id})
        db.execute(text("DELETE FROM users WHERE id = :uid"), {"uid": test_user_id})
        db.commit()
    new_engine.dispose()
    print("Step 5: Cleaned up test records. Persistence verification PASSED!")

if __name__ == "__main__":
    run_persistence_verification()
