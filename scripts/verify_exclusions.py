"""Test ignore rules in a temporary Git repository without changing the workspace."""
from pathlib import Path
import shutil
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='scamshield-ignore-') as folder:
    path=Path(folder)
    subprocess.run(['git','init','--quiet',str(path)],check=True)
    shutil.copyfile(ROOT/'.gitignore',path/'.gitignore')
    excluded=['.env','.env.staging','storage/private.png','scamshield.db','scamshield.db-wal','data.sqlite3','apps/mobile/dist/bundle.hbc','apps/mobile/android/app/release.keystore','private.jks','credentials.json','backups/snapshot/database.db']
    for name in excluded:
        result=subprocess.run(['git','-C',str(path),'check-ignore','--no-index',name],capture_output=True,text=True)
        assert result.returncode==0,name
    for name in ['.env.example','.env.staging.example','README.md','apps/dashboard/app.js']:
        assert subprocess.run(['git','-C',str(path),'check-ignore','--no-index',name],capture_output=True).returncode==1,name
    print(f'PASS: {len(excluded)} sensitive/generated path patterns excluded; templates/source remain includable.')
    print('Workspace tracking status: '+('Git repository exists; review git status separately.' if (ROOT/'.git').exists() else 'No Git repository exists here; actual tracked-file audit is unavailable.'))
