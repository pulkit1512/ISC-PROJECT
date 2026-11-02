"""Initial patient-owned portal schema."""
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    from alembic import op
    from database import metadata
    metadata.create_all(op.get_bind())

def downgrade():
    raise RuntimeError('Destructive downgrade is disabled; restore an explicitly selected backup instead.')
