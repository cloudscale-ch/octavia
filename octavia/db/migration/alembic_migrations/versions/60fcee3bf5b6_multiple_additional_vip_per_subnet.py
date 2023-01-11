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

"""multiple_additional_vip_per_subnet

Revision ID: 60fcee3bf5b6
Revises: 31f7653ded67
Create Date: 2022-12-19 09:04:24.701546

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '60fcee3bf5b6'
down_revision = '31f7653ded67'


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
