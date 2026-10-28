"""Allowlisted event fields only; never log inputs, auth headers or exceptions."""
import json
import logging
import secrets
import time
from sqlalchemy import select, func
from fastapi.responses import JSONResponse
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from .db import Session, Metric, Scan, WorkerHeartbeat, now

logger = logging.getLogger('scamshield')
logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())

def event(name, **fields):
    allowed = {'request_id', 'scan_id', 'job_id', 'status', 'duration_ms', 'attempt', 'method', 'route'}
    logger.info(json.dumps({'event': name, **{k:v for k,v in fields.items() if k in allowed}}))

def count(name, value=0):
    with Session() as db:
        insert = postgres_insert if db.bind.dialect.name == 'postgresql' else sqlite_insert
        statement = insert(Metric).values(name=name, count=1, total=value)
        db.execute(statement.on_conflict_do_update(index_elements=['name'], set_={'count':Metric.count+1, 'total':Metric.total+value}))
        db.commit()

def snapshot(db):
    states = dict(db.execute(select(Scan.status, func.count()).group_by(Scan.status)).all())
    stale = db.scalar(select(func.count()).select_from(Scan).where(Scan.status=='processing', Scan.updated < now()-180))
    return {'scans_by_state': states, 'stale_jobs': stale, 'counters': {m.name:{'count':m.count,'total':m.total} for m in db.scalars(select(Metric)).all()}}

def ready(db):
    return bool(db.scalar(select(WorkerHeartbeat.id).where(WorkerHeartbeat.updated > now()-90).limit(1)))

async def request_log(request, call_next):
    request_id = secrets.token_hex(12)
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        response.headers['X-Request-ID'] = request_id
        return response
    except Exception:
        # Do not let framework tracebacks serialize SQL parameters or inputs.
        event('request_failed', request_id=request_id, status=500)
        return JSONResponse({'detail':'Request failed. Please retry or contact support.','request_id':request_id},status_code=500,headers={'X-Request-ID':request_id})
    finally:
        elapsed = (time.perf_counter()-start)*1000
        route = getattr(request.scope.get('route'), 'path', 'static-or-unmatched')
        event('request', request_id=request_id, status=status, duration_ms=round(elapsed,2), method=request.method, route=route)
        try:
            count('request_latency_ms', elapsed)
            if status >= 400:
                count('request_errors')
        except Exception:
            event('metrics_unavailable', request_id=request_id)
