"""Bounded synthetic workload; isolated SQLite only, never a PostgreSQL claim."""
import json
import os
import platform
from pathlib import Path
import statistics
import tempfile
import threading
import time
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor

def main():
    with tempfile.TemporaryDirectory(prefix='scamshield-benchmark-') as tmp:
        root=Path(tmp)
        os.environ['DATABASE_URL']='sqlite:///'+str(root/'benchmark.db')
        os.environ['STORAGE_PATH']=str(root/'storage')
        from fastapi.testclient import TestClient
        from backend.app.db import Base,engine,Session,User,Scan
        from backend.app.security import password_hash
        from backend.app.main import app
        from backend.app.worker import process_one
        from backend.app.observability import logger
        logger.disabled=True
        from backend.app.backup import backup,restore
        from sqlalchemy import select
        from PIL import Image
        Base.metadata.create_all(engine)
        with Session() as db:
            db.add(User(id='benchmark-user',email='benchmark@fixture.test',password=password_hash('BenchmarkPassword123!'),verified=1,role='user'));db.commit()
        client=TestClient(app)
        token=client.post('/api/auth/login',json={'email':'benchmark@fixture.test','password':'BenchmarkPassword123!'}).json()['token']
        headers={'Authorization':'Bearer '+token}
        timings=[];statuses=[];stop=threading.Event()
        def consume():
            while not stop.is_set():
                if not process_one():stop.wait(.02)
        def submit(i):
            start=time.perf_counter()
            response=client.post('/api/scans',headers={**headers,'Idempotency-Key':'load-'+str(i)},json={'text':f'Urgent send your OTP immediately. Synthetic load fixture {i}'})
            return response.status_code,(time.perf_counter()-start)*1000
        start=time.perf_counter()
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures=[workers.submit(consume) for _ in range(2)]
            try:
                with ThreadPoolExecutor(max_workers=4) as producers:
                    for status,elapsed in producers.map(submit,range(40)):
                        statuses.append(status);timings.append(elapsed)
                deadline=time.monotonic()+60
                while time.monotonic()<deadline:
                    with Session() as db:
                        rows=db.scalars(select(Scan)).all()
                        if len(rows)==40 and all(r.status=='completed' for r in rows):break
                    time.sleep(.05)
                else:raise RuntimeError('Workload did not complete within 60 seconds')
            finally:
                stop.set()
                for future in futures:future.result(timeout=10)
        duration=time.perf_counter()-start
        # Add a real attachment record, then execute an offline restore of the full schema.
        (root/'storage').mkdir(exist_ok=True)
        Image.new('RGB',(40,40),'white').save(root/'storage'/'fixture.png')
        with Session() as db:
            row=db.scalar(select(Scan));row.attachment='fixture.png';db.commit()
        backup(root/'benchmark.db',root/'storage',root/'snapshot')
        recovery=restore(root/'snapshot',root/'restored')
        import sqlite3
        with closing(sqlite3.connect(root/'restored'/'database.db')) as db:
            recovered_scans=db.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
        assert recovered_scans==40 and recovery['restored_attachments']==1 and all(s==202 for s in statuses)
        result={'engine':'SQLite, local TestClient; not network or PostgreSQL performance','hardware':{'os':platform.platform(),'processor':platform.processor(),'logical_cpus':os.cpu_count(),'python':platform.python_version()},'dataset':'40 synthetic short English messages; no detection-quality claim','requests':40,'client_concurrency':4,'worker_threads':2,'http_failures':sum(s!=202 for s in statuses),'completed_scans':len(rows),'elapsed_seconds':round(duration,3),'scans_per_second':round(40/duration,3),'request_latency_ms':{'median':round(statistics.median(timings),3),'p95':round(sorted(timings)[37],3),'max':round(max(timings),3)},'restore':{**recovery,'scans':recovered_scans}}
        Path('docs/benchmark-results.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps(result,indent=2))
        engine.dispose()

if __name__=='__main__':main()
