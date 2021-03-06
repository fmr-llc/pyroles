"""initial table setup

Revision ID: 262e44fe3bd2
Revises: None
Create Date: 2014-08-08 11:53:04.355332

"""

# revision identifiers, used by Alembic.
revision = '262e44fe3bd2'
down_revision = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('t_group_ancestors',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('group_id', sa.Integer(), nullable=True),
    sa.Column('ancestor_id', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    schema='pyroles'
    )
    op.create_table('t_rbac_ref_types',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(256), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    schema='pyroles'
    )
    op.create_table('t_rbac_usergroups',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(256), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    schema='pyroles'
    )
    op.create_table('t_rbac_groups',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('parent_id', sa.Integer(), nullable=True),
    sa.Column('name', sa.String(256), nullable=False),
    sa.Column('deleted', sa.Boolean(), nullable=True),
    sa.Column('max_vms', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['parent_id'], ['pyroles.t_rbac_groups.id'], ),
    sa.PrimaryKeyConstraint('id'),
    schema='pyroles'
    )
    op.create_table('t_rbac_roles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(256), nullable=False),
    sa.Column('description', sa.String(256), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    schema='pyroles'
    )
    op.create_table('t_rbac_permissions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(256), nullable=False),
    sa.Column('reftype_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['reftype_id'], ['pyroles.t_rbac_ref_types.id'], ),
    sa.PrimaryKeyConstraint('id'),
    schema='pyroles'
    )
    op.create_table('t_rbac_users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(256), nullable=False),
    sa.Column('corpid', sa.String(256), nullable=False),
    sa.Column('password', sa.String(256), nullable=False),
    sa.Column('api_key', sa.String(256), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('last_accessed_at', sa.DateTime(), nullable=True),
    sa.Column('disclaimer_accepted', sa.DateTime(), nullable=True),
    sa.Column('group_id', sa.Integer(), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['group_id'], ['pyroles.t_rbac_groups.id'], ),
    sa.PrimaryKeyConstraint('id'),
    schema='pyroles'
    )
    op.create_table('t_rbac_usergroup_roles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('usergroup_id', sa.Integer(), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.Column('group_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['group_id'], ['pyroles.t_rbac_groups.id'], ),
    sa.ForeignKeyConstraint(['role_id'], ['pyroles.t_rbac_roles.id'], ),
    sa.ForeignKeyConstraint(['usergroup_id'], ['pyroles.t_rbac_usergroups.id'], ),
    sa.PrimaryKeyConstraint('id'),
    schema='pyroles'
    )
    op.create_table('t_rbac_ad_groups',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ad_group_name', sa.String(256), nullable=False),
    sa.Column('rbac_usergroup_id', sa.Integer(), nullable=True),
    sa.Column('rbac_group_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['rbac_group_id'], ['pyroles.t_rbac_groups.id'], ),
    sa.ForeignKeyConstraint(['rbac_usergroup_id'], ['pyroles.t_rbac_usergroups.id'], ),
    sa.PrimaryKeyConstraint('id'),
    schema='pyroles'
    )
    op.create_table('t_rbac_user_usergroups',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('usergroup_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['pyroles.t_rbac_users.id'], ),
    sa.ForeignKeyConstraint(['usergroup_id'], ['pyroles.t_rbac_usergroups.id'], ),
    sa.PrimaryKeyConstraint('user_id', 'usergroup_id'),
    schema='pyroles'
    )
    op.create_table('t_rbac_role_permissions',
    sa.Column('role_id', sa.Integer(), nullable=False),
    sa.Column('permission_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['permission_id'], ['pyroles.t_rbac_permissions.id'], ),
    sa.ForeignKeyConstraint(['role_id'], ['pyroles.t_rbac_roles.id'], ),
    sa.PrimaryKeyConstraint('role_id', 'permission_id'),
    schema='pyroles'
    )
    op.create_table('t_rbac_user_roles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.Column('group_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['group_id'], ['pyroles.t_rbac_groups.id'], ),
    sa.ForeignKeyConstraint(['role_id'], ['pyroles.t_rbac_roles.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['pyroles.t_rbac_users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    schema='pyroles'
    )
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('t_rbac_user_roles', schema='pyroles')
    op.drop_table('t_rbac_role_permissions', schema='pyroles')
    op.drop_table('t_rbac_user_usergroups', schema='pyroles')
    op.drop_table('t_rbac_ad_groups', schema='pyroles')
    op.drop_table('t_rbac_usergroup_roles', schema='pyroles')
    op.drop_table('t_rbac_users', schema='pyroles')
    op.drop_table('t_rbac_permissions', schema='pyroles')
    op.drop_table('t_rbac_roles', schema='pyroles')
    op.drop_table('t_rbac_groups', schema='pyroles')
    op.drop_table('t_rbac_usergroups', schema='pyroles')
    op.drop_table('t_rbac_ref_types', schema='pyroles')
    op.drop_table('t_group_ancestors', schema='pyroles')
    ### end Alembic commands ###
