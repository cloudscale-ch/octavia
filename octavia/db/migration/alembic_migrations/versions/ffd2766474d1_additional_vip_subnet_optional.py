"""additional_vip_subnet_optional

Revision ID: ffd2766474d1
Revises: 60fcee3bf5b6
Create Date: 2023-03-08 08:51:26.429115

"""

# revision identifiers, used by Alembic.
revision = 'ffd2766474d1'
down_revision = '60fcee3bf5b6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # Remove not NULL from subnet_id column
    op.alter_column('additional_vip', 'subnet_id', nullable=True,
                    existing_type=sa.String(36))
