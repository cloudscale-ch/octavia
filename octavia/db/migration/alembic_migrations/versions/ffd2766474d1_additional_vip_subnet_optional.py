#    Copyright 2023 cloudscale.ch AG
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""additional_vip_subnet_optional

Revision ID: ffd2766474d1
Revises: 60fcee3bf5b6
Create Date: 2023-03-08 08:51:26.429115

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'ffd2766474d1'
down_revision = '60fcee3bf5b6'


def upgrade():
    # Remove not NULL from subnet_id column
    op.alter_column('additional_vip', 'subnet_id', nullable=True,
                    existing_type=sa.String(36))
