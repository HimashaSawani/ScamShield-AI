import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, String, Text, Integer, ForeignKey, UniqueConstraint, Index, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

def now():
    return datetime.now(timezone.utc).timestamp()

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./scamshield.db')
engine = create_engine(
    DATABASE_URL,
    connect_args={'check_same_thread': False, 'timeout': 30} if DATABASE_URL.startswith('sqlite') else {}
)

if DATABASE_URL.startswith('sqlite'):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

Session = sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True)
    password: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default='user')
    verified: Mapped[int] = mapped_column(Integer, default=0)
    mfa_secret: Mapped[str] = mapped_column(String, default='')

class LoginSession(Base):
    __tablename__ = 'sessions'
    token: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    expires: Mapped[float]

class ActionToken(Base):
    __tablename__ = 'action_tokens'
    token: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    purpose: Mapped[str] = mapped_column(String)
    expires: Mapped[float]

class Scan(Base):
    __tablename__ = 'scans'
    __table_args__ = (UniqueConstraint('owner_id', 'request_key'), Index('ix_scans_queue', 'status', 'created'), Index('ix_scans_owner', 'owner_id', 'created'))
    id: Mapped[str] = mapped_column(String, primary_key=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    kind: Mapped[str] = mapped_column(String)
    text: Mapped[str] = mapped_column(Text, default='')
    normalized: Mapped[str] = mapped_column(Text, default='')
    status: Mapped[str] = mapped_column(String, default='queued')
    result: Mapped[str] = mapped_column(Text, default='{}')
    attachment: Mapped[str] = mapped_column(String, default='')
    request_key: Mapped[str | None] = mapped_column(String, nullable=True)
    created: Mapped[float] = mapped_column(default=now)
    updated: Mapped[float] = mapped_column(default=now)
    attempts: Mapped[int] = mapped_column(default=0)
    lease: Mapped[str] = mapped_column(String, default='')

class Feedback(Base):
    __tablename__ = 'feedback'
    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String)
    owner_id: Mapped[str] = mapped_column(String)
    comment: Mapped[str] = mapped_column(Text)
    created: Mapped[float] = mapped_column(default=now)

class Report(Base):
    __tablename__ = 'reports'
    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, unique=True)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default='pending')
    created: Mapped[float] = mapped_column(default=now)

class Decision(Base):
    __tablename__ = 'review_decisions'
    id: Mapped[str] = mapped_column(String, primary_key=True)
    report_id: Mapped[str] = mapped_column(String)
    analyst_id: Mapped[str] = mapped_column(String)
    verdict: Mapped[str] = mapped_column(String)
    reason: Mapped[str] = mapped_column(Text)
    created: Mapped[float] = mapped_column(default=now)

class Campaign(Base):
    __tablename__ = 'campaigns'
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    report_ids: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)

class Audit(Base):
    __tablename__ = 'audit_events'
    id: Mapped[str] = mapped_column(String, primary_key=True)
    actor: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    target: Mapped[str] = mapped_column(String)
    created: Mapped[float] = mapped_column(default=now)

class RateBucket(Base):
    __tablename__ = 'rate_buckets'
    key: Mapped[str] = mapped_column(String, primary_key=True)
    count: Mapped[int] = mapped_column(default=0)
    expires: Mapped[float]

class RecoveryCode(Base):
    __tablename__ = 'recovery_codes'
    token: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)

class WorkerHeartbeat(Base):
    __tablename__ = 'worker_heartbeats'
    id: Mapped[str] = mapped_column(String, primary_key=True)
    updated: Mapped[float] = mapped_column(default=now)

class Metric(Base):
    __tablename__ = 'operational_metrics'
    name: Mapped[str] = mapped_column(String, primary_key=True)
    count: Mapped[int] = mapped_column(default=0)
    total: Mapped[float] = mapped_column(default=0.0)
