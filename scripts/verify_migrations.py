"""Exercise additive migration on isolated existing records, never user data."""
from pathlib import Path
import os
import sqlite3
from contextlib import closing
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='scamshield-migrations-') as folder:
    database=Path(folder)/'migration-test.db'
    env={**os.environ,'DATABASE_URL':'sqlite:///'+str(database)}
    def migrate(*args):
        subprocess.run([sys.executable,'-m','alembic','-c','backend/alembic.ini',*args],cwd=ROOT,env=env,check=True)
    migrate('upgrade','0001')
    with closing(sqlite3.connect(database)) as db:
        db.execute("INSERT INTO users VALUES ('preserved-user','fixture@example.test','not-a-real-password','user',1,'')")
        db.execute("INSERT INTO scans VALUES ('preserved-scan','preserved-user','text','original fixture','normalized fixture','completed','{}','',NULL,1,1,1)")
        db.commit()
    migrate('upgrade','head');migrate('check')
    with closing(sqlite3.connect(database)) as db:
        assert db.execute('SELECT text,lease FROM scans').fetchone()==('original fixture','')
        assert db.execute('SELECT id FROM users').fetchone()[0]=='preserved-user'
    migrate('downgrade','base');migrate('upgrade','head');migrate('check')
    print('PASS: migration 0001 -> 0002 preserved isolated user/scan records; empty upgrade and downgrade/re-upgrade succeeded.')
