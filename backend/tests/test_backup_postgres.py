"""Test PostgreSQL backup and recovery with attachment integrity and usability verification."""
import os
import secrets
import tempfile
from pathlib import Path
import psycopg
import pytest
from sqlalchemy import create_engine, select, text
from backend.app.backup_postgres import backup_postgres, restore_postgres, checksum
from backend.app.db import Base, User, Scan, Session, now

PG_HOST = "127.0.0.1"
PG_PORT = 5432
PG_USER = "scamshield"
PG_PASS = "scamshield"

SRC_DB = "scamshield_test"
RESTORE_DB = "scamshield_restore_test"

SRC_URL = f"postgresql+psycopg://{PG_USER}:{PG_PASS}@{PG_HOST}:{PG_PORT}/{SRC_DB}"
RESTORE_URL = f"postgresql+psycopg://{PG_USER}:{PG_PASS}@{PG_HOST}:{PG_PORT}/{RESTORE_DB}"

@pytest.fixture(scope="module")
def pg_available():
    try:
        conn = psycopg.connect(f"postgresql://{PG_USER}:{PG_PASS}@{PG_HOST}:{PG_PORT}/postgres", connect_timeout=3)
        conn.close()
        return True
    except Exception:
        pytest.skip("PostgreSQL test instance is not reachable")

def test_postgres_backup_restore_and_integrity(pg_available, tmp_path):
    # Ensure restore database exists and is empty
    with psycopg.connect(f"postgresql://{PG_USER}:{PG_PASS}@{PG_HOST}:{PG_PORT}/postgres", autocommit=True) as admin_conn:
        with admin_conn.cursor() as cur:
            cur.execute(f"DROP DATABASE IF EXISTS {RESTORE_DB}")
            cur.execute(f"CREATE DATABASE {RESTORE_DB} OWNER {PG_USER}")

    # Set up source environment
    src_storage = tmp_path / "src_storage"
    src_storage.mkdir()
    fixture_attachment = "fixture_test_image.png"
    (src_storage / fixture_attachment).write_bytes(b"\x89PNG\r\n\x1a\ncontrolled-attachment-bytes-for-pg-test")
    expected_hash = checksum(src_storage / fixture_attachment)

    engine_src = create_engine(SRC_URL)
    Base.metadata.create_all(engine_src)

    test_uid = secrets.token_hex(16)
    test_sid = secrets.token_hex(16)

    with engine_src.connect() as conn:
        conn.execute(text("DELETE FROM scans WHERE attachment = :att"), {"att": fixture_attachment})
        conn.execute(
            text("INSERT INTO users (id, email, password, role, verified, mfa_secret) VALUES (:id, :email, 'hash', 'user', 1, '')"),
            {"id": test_uid, "email": f"test_{test_uid}@example.com"}
        )
        conn.execute(
            text("INSERT INTO scans (id, owner_id, kind, text, normalized, status, result, attachment, created, updated, attempts, lease) "
                 "VALUES (:id, :owner_id, 'screenshot', 'Test scan text', '', 'completed', '{\"assessment\":\"High\"}', :att, :t, :t, 1, '')"),
            {"id": test_sid, "owner_id": test_uid, "att": fixture_attachment, "t": now()}
        )
        conn.commit()

    # Perform PostgreSQL backup
    snapshot_dir = tmp_path / "pg_snapshot"
    manifest = backup_postgres(SRC_URL, src_storage, snapshot_dir)
    assert manifest["format"] == 2
    assert manifest["engine"] == "postgresql"
    assert manifest["offline_required"] is True
    assert manifest["attachments"] >= 1
    assert f"storage/{fixture_attachment}" in manifest["files"]
    assert manifest["files"][f"storage/{fixture_attachment}"] == expected_hash

    # Restore into second isolated environment
    restored_storage = tmp_path / "restored_storage"
    result = restore_postgres(snapshot_dir, RESTORE_URL, restored_storage)

    assert result["database_status"] == "ok"
    assert result["restored_attachments"] >= 1
    assert result["tables_verified"] >= 10
    assert result["scans_verified"] >= 1

    # Verify restored attachment identity, hash, and content
    restored_file = restored_storage / fixture_attachment
    assert restored_file.is_file()
    assert checksum(restored_file) == expected_hash
    assert restored_file.read_bytes() == b"\x89PNG\r\n\x1a\ncontrolled-attachment-bytes-for-pg-test"

    # Verify restored records and usability
    engine_restored = create_engine(RESTORE_URL)
    with engine_restored.connect() as conn:
        row = conn.execute(text("SELECT id, owner_id, attachment, status, result FROM scans WHERE id = :sid"), {"sid": test_sid}).fetchone()
        assert row is not None
        assert row.attachment == fixture_attachment
        assert row.status == "completed"
        assert "High" in row.result

    # Refuse overwrite if target snapshot exists
    with pytest.raises(FileExistsError):
        backup_postgres(SRC_URL, src_storage, snapshot_dir)

    # Refuse overwrite if restored storage exists and is not empty
    with pytest.raises(FileExistsError):
        restore_postgres(snapshot_dir, RESTORE_URL, restored_storage)

    # Detect tampering in snapshot
    (snapshot_dir / f"storage/{fixture_attachment}").write_bytes(b"tampered-content")
    bad_storage = tmp_path / "bad_storage"
    with pytest.raises(ValueError, match="integrity check failed"):
        restore_postgres(snapshot_dir, RESTORE_URL, bad_storage)
