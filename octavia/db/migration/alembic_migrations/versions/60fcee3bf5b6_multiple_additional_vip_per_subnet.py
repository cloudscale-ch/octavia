"""multiple_additional_vip_per_subnet

Revision ID: 60fcee3bf5b6
Revises: 31f7653ded67
Create Date: 2022-12-19 09:04:24.701546

"""

# revision identifiers, used by Alembic.
revision = '60fcee3bf5b6'
down_revision = '31f7653ded67'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # Drop the old primary key
    op.drop_constraint(u'pk_add_vip_load_balancer_subnet',
                       u'additional_vip',
                       u'primary')

    # Create a new unique key including the ip_address column
    op.create_unique_constraint(u'pk_add_vip_load_balancer_subnet_ip_address',
                                u'additional_vip',
                                [u'load_balancer_id', u'subnet_id',
                                 u'ip_address'])
