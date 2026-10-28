"""Recovery codes, worker leases, readiness and operational counters."""
from alembic import op
import sqlalchemy as sa
revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('scans', sa.Column('lease', sa.String(), nullable=False, server_default=''))
    op.create_table('recovery_codes', sa.Column('token', sa.String(), primary_key=True), sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False))
    op.create_index('ix_recovery_codes_user_id', 'recovery_codes', ['user_id'])
    op.create_table('worker_heartbeats', sa.Column('id', sa.String(), primary_key=True), sa.Column('updated', sa.Float(), nullable=False))
    op.create_table('operational_metrics', sa.Column('name', sa.String(), primary_key=True), sa.Column('count', sa.Integer(), nullable=False), sa.Column('total', sa.Float(), nullable=False))

def downgrade():
    for table in ['operational_metrics', 'worker_heartbeats', 'recovery_codes']:
        op.drop_table(table)
    op.drop_column('scans', 'lease')
