"""PostgreSQL and private attachment snapshot and restore tooling.

Refuses destination overwrite. Requires stopping writes (--offline)
to guarantee cross-subsystem consistency between relational database
attachment references and filesystem storage objects.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from contextlib import closing
from pathlib import Path
from urllib.parse import urlparse
import psycopg

def checksum(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def safe_name(name: str) -> bool:
    return name == Path(name).name and '/' not in name and '\\' not in name and name not in ['.', '..']

def parse_pg_url(url: str):
    # Remove SQLAlchemy dialect prefix if present
    clean_url = re.sub(r'^[a-zA-Z0-9\+_]+://', 'postgresql://', url)
    parsed = urlparse(clean_url)
    return {
        'host': parsed.hostname or '127.0.0.1',
        'port': str(parsed.port or 5432),
        'user': parsed.username or 'postgres',
        'password': parsed.password or '',
        'dbname': parsed.path.lstrip('/') or 'postgres',
        'raw_url': clean_url
    }

def to_wsl_path(path: Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive.rstrip(':').lower()
    if drive:
        tail = resolved.as_posix()[len(resolved.drive):]
        if not tail.startswith('/'):
            tail = '/' + tail
        return f'/mnt/{drive}{tail}'
    return resolved.as_posix()

def run_pg_tool(tool_name: str, conn_info: dict, args: list[str]):
    """Execute pg_dump or pg_restore either locally or via WSL if native binary is unavailable."""
    # Check if native tool is available
    native_tool = shutil.which(tool_name)
    env = dict(os.environ)
    if conn_info.get('password'):
        env['PGPASSWORD'] = conn_info['password']

    if native_tool:
        cmd = [
            native_tool,
            '-h', conn_info['host'],
            '-p', conn_info['port'],
            '-U', conn_info['user'],
            '-d', conn_info['dbname']
        ] + args
        res = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if res.returncode != 0:
            raise RuntimeError(f"{tool_name} failed (code {res.returncode}): {res.stderr}")
        return res

    # Otherwise use WSL
    wsl_args = []
    for arg in args:
        # Translate Windows paths in arguments to WSL paths
        if ':' in arg or '\\' in arg:
            wsl_args.append(to_wsl_path(Path(arg)))
        else:
            wsl_args.append(arg)

    pw_prefix = f"PGPASSWORD='{conn_info['password']}' " if conn_info.get('password') else ""
    cmd_str = f"{pw_prefix}{tool_name} -h {conn_info['host']} -p {conn_info['port']} -U {conn_info['user']} -d {conn_info['dbname']} " + " ".join(f"'{a}'" for a in wsl_args)
    cmd = ['wsl.exe', '-d', 'Ubuntu', 'bash', '-c', cmd_str]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"WSL {tool_name} failed (code {res.returncode}): {res.stderr}\nCommand: {cmd_str}")
    return res

def references_postgres(conn_info: dict) -> set[str]:
    conn_str = f"postgresql://{conn_info['user']}:{conn_info['password']}@{conn_info['host']}:{conn_info['port']}/{conn_info['dbname']}"
    with closing(psycopg.connect(conn_str)) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT attachment FROM scans WHERE attachment != '' AND attachment IS NOT NULL")
            return {row[0] for row in cur.fetchall()}

def backup_postgres(database_url: str, storage_path: Path, output_path: Path) -> dict:
    storage_path = Path(storage_path).resolve()
    output_path = Path(output_path).resolve()
    conn_info = parse_pg_url(database_url)

    if output_path.exists():
        raise FileExistsError(f"Destination output path already exists: {output_path}")

    names = references_postgres(conn_info)
    for n in names:
        if not safe_name(n):
            raise ValueError(f"Unsafe attachment reference: {n}")
        file_path = storage_path / n
        if not file_path.is_file() or file_path.is_symlink():
            raise ValueError(f"Missing or invalid attachment file: {n}")

    output_path.mkdir(parents=True, mode=0o700)
    dump_file = output_path / 'database.dump'

    # Dump database in custom format (-Fc)
    run_pg_tool('pg_dump', conn_info, ['-Fc', '-f', str(dump_file)])
    if not dump_file.is_file() or dump_file.stat().st_size == 0:
        raise RuntimeError("Database dump was not generated or is empty")

    storage_out = output_path / 'storage'
    storage_out.mkdir(mode=0o700)
    for n in names:
        shutil.copyfile(storage_path / n, storage_out / n)

    files = ['database.dump'] + [f'storage/{n}' for n in sorted(names)]
    manifest = {
        'format': 2,
        'engine': 'postgresql',
        'offline_required': True,
        'database_dump': 'database.dump',
        'attachments': len(names),
        'files': {f: checksum(output_path / f) for f in files}
    }
    (output_path / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest

def restore_postgres(snapshot_path: Path, target_database_url: str, output_storage_path: Path) -> dict:
    snapshot_path = Path(snapshot_path).resolve()
    output_storage_path = Path(output_storage_path).resolve()
    conn_info = parse_pg_url(target_database_url)

    manifest_file = snapshot_path / 'manifest.json'
    if not manifest_file.is_file():
        raise ValueError("Missing manifest.json in snapshot")

    manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
    if manifest.get('format') != 2 or manifest.get('engine') != 'postgresql':
        raise ValueError(f"Unsupported snapshot format or engine: {manifest}")

    dump_filename = manifest.get('database_dump', 'database.dump')
    if dump_filename not in manifest.get('files', {}):
        raise ValueError(f"Missing {dump_filename} in manifest files")

    # Verify integrity of all snapshot files
    for name, expected in manifest['files'].items():
        if name != dump_filename and not (name.startswith('storage/') and safe_name(name[8:])):
            raise ValueError(f"Unsafe snapshot filename: {name}")
        path = snapshot_path / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Snapshot file missing or symlink: {name}")
        if checksum(path) != expected:
            raise ValueError(f"Snapshot integrity check failed for {name}")

    if output_storage_path.exists() and any(output_storage_path.iterdir()):
        raise FileExistsError(f"Target storage path already exists and is not empty: {output_storage_path}")
    output_storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Restore database dump using pg_restore
    dump_path = snapshot_path / dump_filename
    # Clean existing schema if any or restore objects
    run_pg_tool('pg_restore', conn_info, ['--clean', '--if-exists', str(dump_path)])

    # Restore files into storage
    for name in manifest['files']:
        if name.startswith('storage/'):
            base = name[8:]
            shutil.copyfile(snapshot_path / name, output_storage_path / base)

    # Verification: check database integrity and attachments
    names = references_postgres(conn_info)
    for n in names:
        if not safe_name(n) or not (output_storage_path / n).is_file():
            raise ValueError(f"Restored attachment reference missing or unsafe: {n}")
        if checksum(output_storage_path / n) != manifest['files'].get(f'storage/{n}'):
            raise ValueError(f"Restored attachment hash mismatch: {n}")

    conn_str = f"postgresql://{conn_info['user']}:{conn_info['password']}@{conn_info['host']}:{conn_info['port']}/{conn_info['dbname']}"
    with closing(psycopg.connect(conn_str)) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
            table_count = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM scans")
            scan_count = cur.fetchone()[0]

    return {
        'restored_attachments': len(names),
        'database_status': 'ok',
        'tables_verified': table_count,
        'scans_verified': scan_count
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['backup', 'restore'])
    parser.add_argument('--database-url', type=str, required=True, help='PostgreSQL connection URL')
    parser.add_argument('--storage', type=Path, help='Storage path (for backup)')
    parser.add_argument('--output-storage', type=Path, help='Storage path (for restore)')
    parser.add_argument('--source', type=Path, help='Source snapshot directory (for restore)')
    parser.add_argument('--output', type=Path, help='Output snapshot directory (for backup)')
    parser.add_argument('--offline', action='store_true', help='Confirm that API/worker writers are stopped')
    args = parser.parse_args()

    if not args.offline:
        parser.error('Stopping API/worker writers and passing --offline is required for consistent backup/restore')

    if args.command == 'backup':
        if not args.storage or not args.output:
            parser.error('--storage and --output are required for backup')
        result = backup_postgres(args.database_url, args.storage, args.output)
    else:
        if not args.source or not args.output_storage:
            parser.error('--source and --output-storage are required for restore')
        result = restore_postgres(args.source, args.database_url, args.output_storage)

    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
