"""Offline SQLite/private-file snapshot and restore; refuses destination overwrite."""
import argparse
import hashlib
import json
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def references(database):
    with closing(sqlite3.connect(f'{database.resolve().as_uri()}?mode=ro', uri=True)) as db:
        return {row[0] for row in db.execute("SELECT attachment FROM scans WHERE attachment != ''")}

def safe_name(name):
    return name == Path(name).name and '/' not in name and '\\' not in name and name not in ['.', '..']

def backup(database, storage, output):
    database, storage, output = map(Path, (database, storage, output))
    if not database.is_file():
        raise ValueError('Source database does not exist')
    names = references(database)
    if any(not safe_name(n) or not (storage/n).is_file() or (storage/n).is_symlink() for n in names):
        raise ValueError('Missing or unsafe attachment reference')
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    with closing(sqlite3.connect(f'{database.resolve().as_uri()}?mode=ro', uri=True)) as source, closing(sqlite3.connect(output/'database.db')) as target:
        source.backup(target)
    (output/'storage').mkdir(mode=0o700)
    for name in names:
        shutil.copyfile(storage/name, output/'storage'/name)
        (output/'storage'/name).chmod(0o600)
    files = ['database.db'] + ['storage/'+n for n in sorted(names)]
    manifest = {'format':1, 'offline_required':True, 'attachments':len(names), 'files':{f:checksum(output/f) for f in files}}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    (output/'database.db').chmod(0o600)
    return manifest

def restore(source, output):
    source, output = Path(source), Path(output)
    manifest=json.loads((source/'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('format')!=1 or 'database.db' not in manifest.get('files',{}):
        raise ValueError('Unsupported snapshot format')
    for name, expected in manifest['files'].items():
        if name!='database.db' and not (name.startswith('storage/') and safe_name(name[8:])):
            raise ValueError('Unsafe snapshot filename')
        path=source/name
        if path.is_symlink() or checksum(path)!=expected:
            raise ValueError('Snapshot integrity check failed')
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    (output/'storage').mkdir(mode=0o700)
    for name in manifest['files']:
        shutil.copyfile(source/name,output/name)
        (output/name).chmod(0o600)
    names=references(output/'database.db')
    if any(not safe_name(n) or not (output/'storage'/n).is_file() for n in names):
        raise ValueError('Restored attachment references do not resolve')
    return {'restored_attachments':len(names),'database_integrity':check_database(output/'database.db')}

def check_database(database):
    with closing(sqlite3.connect(database)) as db:
        return db.execute('PRAGMA integrity_check').fetchone()[0]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['backup','restore'])
    parser.add_argument('--database',type=Path)
    parser.add_argument('--storage',type=Path)
    parser.add_argument('--source',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--offline',action='store_true',help='Confirm that writers and retention are stopped')
    args=parser.parse_args()
    if not args.offline:
        parser.error('Stop API/worker writers and confirm --offline first')
    if args.command=='backup':
        if not args.database or not args.storage:
            parser.error('--database and --storage are required')
        result=backup(args.database,args.storage,args.output)
    else:
        if not args.source:
            parser.error('--source is required')
        result=restore(args.source,args.output)
    print(json.dumps(result,indent=2))

if __name__=='__main__':
    main()
