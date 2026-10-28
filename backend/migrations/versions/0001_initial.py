"""Initial schema. This migration freezes the initial column definitions."""
from alembic import op
import sqlalchemy as sa

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('users', sa.Column('id', sa.String(), primary_key=True), sa.Column('email', sa.String(), unique=True, nullable=False), sa.Column('password', sa.String(), nullable=False), sa.Column('role', sa.String(), nullable=False), sa.Column('verified', sa.Integer(), nullable=False), sa.Column('mfa_secret', sa.String(), nullable=False))
    op.create_table('sessions', sa.Column('token', sa.String(), primary_key=True), sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False), sa.Column('expires', sa.Float(), nullable=False))
    op.create_table('action_tokens', sa.Column('token', sa.String(), primary_key=True), sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False), sa.Column('purpose', sa.String(), nullable=False), sa.Column('expires', sa.Float(), nullable=False))
    op.create_table('scans', sa.Column('id', sa.String(), primary_key=True), sa.Column('owner_id', sa.String(), sa.ForeignKey('users.id'), nullable=False), sa.Column('kind', sa.String(), nullable=False), sa.Column('text', sa.Text(), nullable=False), sa.Column('normalized', sa.Text(), nullable=False), sa.Column('status', sa.String(), nullable=False), sa.Column('result', sa.Text(), nullable=False), sa.Column('attachment', sa.String(), nullable=False), sa.Column('request_key', sa.String(), nullable=True), sa.Column('created', sa.Float(), nullable=False), sa.Column('updated', sa.Float(), nullable=False), sa.Column('attempts', sa.Integer(), nullable=False), sa.UniqueConstraint('owner_id', 'request_key'))
    op.create_index('ix_scans_queue', 'scans', ['status','created'])
    op.create_index('ix_scans_owner', 'scans', ['owner_id','created'])
    op.create_table('feedback', sa.Column('id', sa.String(), primary_key=True), sa.Column('scan_id', sa.String(), nullable=False), sa.Column('owner_id', sa.String(), nullable=False), sa.Column('comment', sa.Text(), nullable=False), sa.Column('created', sa.Float(), nullable=False))
    op.create_table('reports', sa.Column('id', sa.String(), primary_key=True), sa.Column('scan_id', sa.String(), unique=True, nullable=False), sa.Column('reason', sa.Text(), nullable=False), sa.Column('status', sa.String(), nullable=False), sa.Column('created', sa.Float(), nullable=False))
    op.create_table('review_decisions', sa.Column('id', sa.String(), primary_key=True), sa.Column('report_id', sa.String(), nullable=False), sa.Column('analyst_id', sa.String(), nullable=False), sa.Column('verdict', sa.String(), nullable=False), sa.Column('reason', sa.Text(), nullable=False), sa.Column('created', sa.Float(), nullable=False))
    op.create_table('campaigns', sa.Column('id', sa.String(), primary_key=True), sa.Column('name', sa.String(), nullable=False), sa.Column('report_ids', sa.Text(), nullable=False), sa.Column('reason', sa.Text(), nullable=False))
    op.create_table('audit_events', sa.Column('id', sa.String(), primary_key=True), sa.Column('actor', sa.String(), nullable=False), sa.Column('action', sa.String(), nullable=False), sa.Column('target', sa.String(), nullable=False), sa.Column('created', sa.Float(), nullable=False))
    op.create_table('rate_buckets', sa.Column('key', sa.String(), primary_key=True), sa.Column('count', sa.Integer(), nullable=False), sa.Column('expires', sa.Float(), nullable=False))

def downgrade():
    for table in ['rate_buckets', 'audit_events', 'campaigns', 'review_decisions', 'reports', 'feedback', 'scans', 'action_tokens', 'sessions', 'users']:
        op.drop_table(table)
