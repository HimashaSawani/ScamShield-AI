import sqlite3
import pytest
from backend.app.backup import backup, restore

def test_offline_restore_and_integrity(tmp_path):
    database=tmp_path/'source.db';storage=tmp_path/'source-files';storage.mkdir()
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE scans (id TEXT, attachment TEXT)')
        db.execute("INSERT INTO scans VALUES ('scan-1','fixture.png')")
    (storage/'fixture.png').write_bytes(b'controlled-attachment-fixture')
    manifest=backup(database,storage,tmp_path/'snapshot')
    result=restore(tmp_path/'snapshot',tmp_path/'restored')
    assert manifest['attachments']==1
    assert result=={'restored_attachments':1,'database_integrity':'ok'}
    with sqlite3.connect(tmp_path/'restored/database.db') as db:
        assert db.execute('SELECT id FROM scans').fetchone()[0]=='scan-1'
    assert (tmp_path/'restored/storage/fixture.png').read_bytes()==b'controlled-attachment-fixture'
    with pytest.raises(FileExistsError):
        restore(tmp_path/'snapshot',tmp_path/'restored')
    (tmp_path/'snapshot/storage/fixture.png').write_bytes(b'tampered')
    with pytest.raises(ValueError,match='integrity'):
        restore(tmp_path/'snapshot',tmp_path/'rejected')
