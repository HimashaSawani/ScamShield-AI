"""Global pytest configuration: ensures complete database and storage isolation for test suite."""
import os
import shutil
import tempfile
from pathlib import Path
import pytest

# Allocate isolated temporary directory for test database and storage
TEST_DIR = Path(tempfile.mkdtemp(prefix='scamshield-pytest-'))
TEST_DB = TEST_DIR / 'test.db'
TEST_STORAGE = TEST_DIR / 'storage'
TEST_STORAGE.mkdir(parents=True, exist_ok=True)

# Set environment variables BEFORE any application modules are imported
os.environ['DATABASE_URL'] = f'sqlite:///{TEST_DB.as_posix()}'
os.environ['STORAGE_PATH'] = str(TEST_STORAGE)
os.environ['DEV_EMAIL_TOKENS'] = '1'
os.environ['SCAMSHIELD_DEMO_EMAIL'] = 'demo@scamshield.test'
os.environ['SCAMSHIELD_DEMO_PASSWORD'] = 'ScamShieldTestPassword123!'

from backend.app.db import Base, engine

@pytest.fixture(scope='session', autouse=True)
def test_environment_lifecycle():
    Base.metadata.create_all(engine)
    yield
    engine.dispose()
    try:
        shutil.rmtree(TEST_DIR, ignore_errors=True)
    except Exception:
        pass

