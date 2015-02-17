import unittest
import sys
sys.path.append('..')

import logging

logging.basicConfig()

from pyroles.pyroles import PyRoles
from pyroles import conf_pyroles
from pyroles.model import RBACRefType,RBACPermission,RBACGroup,RBACRole,RBACUserRole,RBACUserGroup,RBACUserGroupRole,RBACUser,RBACADGroup
from nose.plugins.attrib import attr

class PyrolesTest(unittest.TestCase):

    def setUp(self):
        self.pr = PyRoles()
        self.pr.connect(conf_pyroles.dbUrl)

        group = self.pr._session.query(RBACGroup).filter_by(name='Base Test Group').first() # pylint: disable=W0212
        if group is None:
            group = RBACGroup(name='Base Test Group')
            self.pr.add(group)

        usergroup = self.pr._session.query(RBACUserGroup).filter_by(name='Base Test UserGroup').first() # pylint: disable=W0212
        if usergroup is None:
            usergroup = RBACUserGroup(name="Base Test UserGroup")
            self.pr.add(usergroup)

        user = self.pr._session.query(RBACUser).filter_by(name='ndaapp').first() # pylint: disable=W0212
        if user is None:
            user = RBACUser(name='ndaapp',password='ndaapp',corpid='ndaapp',api_key='ndaapp',group_id=1)
            self.pr.add(user)

        role = self.pr._session.query(RBACRole).filter_by(name="Test Role").first() # pylint: disable=W0212
        if role is None:
            role = RBACRole(name="Test Role")
            self.pr.add(role)


    def tearDown(self):
        self.pr.close()

    @attr(scope=["local"])
    @attr("models")
    def test_rbac_reftype(self):
        reftype = RBACRefType("Test RefType Name")
        expected_string = "<RBACRefType('{0}','Test RefType Name')>".format(reftype.id)
        assert str(reftype) == expected_string, "Expected new reftype to stringify to {0}, but was {1}".format(expected_string,str(reftype))

    @attr(scope=["local"])
    @attr("models")
    def test_rbac_user(self):
        group = self.pr.groups[0]
        user = RBACUser(name='Test User',password='Test User',corpid='Test User',api_key='Test User',group_id=group.id)
        self.pr.add(user)
        expected_string = "<RBACUser(id:'{0}',corpid:'Test User',name:'Test User',group:'{1}')>".format(user.id,group.name)
        assert str(user) == expected_string, "Expected new user to stringify to {0}, but was {1}".format(expected_string,str(user))
        self.pr.delete(user)

    @attr(scope=["local"])
    @attr("models")
    def test_rbac_usergroup(self):
        usergroup = RBACUserGroup("Test UserGroup Name")
        self.pr.add(usergroup)
        expected_string = "<RBACUserGroup('{0}','Test UserGroup Name')>".format(usergroup.id)
        assert str(usergroup) == expected_string, "Expected new usergroup to stringify to {0}, but was {1}".format(expected_string,str(usergroup))
        self.pr.delete(usergroup)

    @attr(scope=["local"])
    @attr("models")
    def test_rbac_usergroup_role(self):
        group = self.pr.groups[0]
        usergroup = self.pr.usergroups[0]
        role = self.pr.roles[0]
        usergrouprole = RBACUserGroupRole(group=group,usergroup=usergroup,role=role)
        self.pr.add(usergrouprole)
        expected_string = "<RBACUserGroupRoles(id:'{0}',usergroup:'{1}',role:'{2}',group:'{3}')>".format(usergrouprole.id,usergroup.name,role.name,group.name)
        assert str(usergrouprole) == expected_string, "Expected new usergrouprole to stringify to {0}, but was {1}".format(expected_string,str(usergrouprole))
        self.pr.delete(usergrouprole)

    @attr(scope=["local"])
    @attr("models")
    def test_rbac_user_role(self):
        group = self.pr.groups[0]
        user = self.pr.users[0]
        role = self.pr.roles[0]
        userrole = RBACUserRole(group=group,user=user,role=role)
        self.pr.add(userrole)
        expected_string = "<RBACUserRoles(id:'{0}',user:'{1}',role:'{2}',group:'{3}')>".format(userrole.id,user.name,role.name,group.name)
        assert str(userrole) == expected_string, "Expected new userrole to stringify to {0}, but was {1}".format(expected_string,str(userrole))
        self.pr.delete(userrole)

    @attr(scope=["local"])
    @attr("models")
    def test_rbac_adgroup(self):
        group = self.pr.groups[0]
        usergroup = self.pr.usergroups[0]
        adgroup = RBACADGroup(ad_group_name='Test ADGroup',rbac_group_id=group.id,rbac_usergroup_id=usergroup.id)
        self.pr.add(adgroup)
        expected_string = "<RBACADGroup(id:'{0}',ad_group_name:'Test ADGroup',rbac_group_id:'{1}',rbac_usergroup_id:'{2}')>".format(adgroup.id,group.id,usergroup.id)
        assert str(adgroup) == expected_string, "Expected new adgroup to stringify to {0}, but was {1}".format(expected_string,str(adgroup))
        self.pr.delete(adgroup)

    @attr(scope=["local"])
    @attr("models")
    def test_rbac_group(self):
        parent_group = self.pr.groups[0]
        group = RBACGroup(name='Test Group',parent=parent_group,max_vms=10)
        self.pr.add(group)
        expected_string = "<RBACGroup(id:'{0}',name:'{1}\\Test Group',parent:'{2}')>".format(group.id,parent_group.name,parent_group.id)
        assert str(group) == expected_string, "Expected new group to stringify to {0}, but was {1}".format(expected_string,str(group))
        assert group.max_vms == 10, "Expected max vms for group to be 10, but was: {1}".format(group.max_vms)
        self.pr.delete(group)

    @attr(scope=["local"])
    @attr("models")
    def test_rbac_group_roles_for_users_and_usergroups(self):
        parent_group = self.pr.groups[0]
        group = self.pr._session.query(RBACGroup).filter_by(name='Test Group roles_for_users_and_usergroups',parent=parent_group,max_vms=10).first() # pylint: disable=W0212
        if group is None:
            group = RBACGroup(name='Test Group roles_for_users_and_usergroups',parent=parent_group,max_vms=10)
            self.pr.add(group)

        child_group = self.pr._session.query(RBACGroup).filter_by(name='Test Group roles_for_users_and_usergroups Child',parent=group).first() # pylint: disable=W0212
        if child_group is None:
            child_group = RBACGroup(name='Test Group roles_for_users_and_usergroups Child',parent=group)
            self.pr.add(child_group)

        usergroup = self.pr._session.query(RBACUserGroup).filter_by(name="Test UserGroup Name").first() # pylint: disable=W0212
        if usergroup is None:
            usergroup = RBACUserGroup("Test UserGroup Name")
            self.pr.add(usergroup)

        user = self.pr._session.query(RBACUser).filter_by(name='Test User roles_for_users_and_usergroups',password='Test User',corpid='Test User roles_for_users_and_usergroups',api_key='Test User',group_id=group.id).first() # pylint: disable=W0212
        if user is None:
            user = RBACUser(name='Test User roles_for_users_and_usergroups',password='Test User',corpid='Test User roles_for_users_and_usergroups',api_key='Test User',group_id=group.id)
            self.pr.add(user)

        user_role = self.pr._session.query(RBACRole).filter_by(name="Test Role for user for roles_for_users_and_usergroups").first() # pylint: disable=W0212
        if user_role is None:
            user_role = RBACRole("Test Role for user for roles_for_users_and_usergroups")
            self.pr.add(user_role)

        usergroup_role = self.pr._session.query(RBACRole).filter_by(name="Test Role for usergroup for roles_for_users_and_usergroups").first() # pylint: disable=W0212
        if usergroup_role is None:
            usergroup_role = RBACRole("Test Role for usergroup for roles_for_users_and_usergroups")
            self.pr.add(usergroup_role)

        userrole_assignment = self.pr._session.query(RBACUserRole).filter_by(group_id=group.id,user_id=user.id,role_id=user_role.id).first() # pylint: disable=W0212
        if userrole_assignment is None:
            userrole_assignment = RBACUserRole(group=group,user=user,role=user_role)
            self.pr.add(userrole_assignment)

        usergrouprole_assignment = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup_id=usergroup.id,group_id=child_group.id,role_id=usergroup_role.id).first() # pylint: disable=W0212
        if usergrouprole_assignment is None:
            usergrouprole_assignment = RBACUserGroupRole(usergroup=usergroup,role=usergroup_role,group=child_group)
            self.pr.add(usergrouprole_assignment)

        user_role2 = self.pr._session.query(RBACRole).filter_by(name="Test Role 2 for user for roles_for_users_and_usergroups").first() # pylint: disable=W0212
        if user_role2 is None:
            user_role2 = RBACRole("Test Role 2 for user for roles_for_users_and_usergroups")
            self.pr.add(user_role2)

        userrole_assignment2 = self.pr._session.query(RBACUserRole).filter_by(group_id=child_group.id,user_id=user.id,role_id=user_role2.id).first() # pylint: disable=W0212
        if userrole_assignment2 is None:
            userrole_assignment2 = RBACUserRole(group=child_group,user=user,role=user_role2)
            self.pr.add(userrole_assignment2)

        userrole_assignment3 = self.pr._session.query(RBACUserRole).filter_by(group_id=child_group.id,user_id=user.id,role_id=user_role2.id).first() # pylint: disable=W0212
        if userrole_assignment3 is None:
            userrole_assignment3 = RBACUserRole(group=child_group,user=user,role=user_role2)
            self.pr.add(userrole_assignment3)

        userrole_assignment4 = RBACUserRole(group=parent_group,user=user,role=user_role)
        self.pr.add(userrole_assignment4)

        userrole_assignment5 = RBACUserRole(group=parent_group,user=user,role=user_role2)
        self.pr.add(userrole_assignment5)

        usergrouprole_assignment2 = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup_id=usergroup.id,group_id=group.id,role_id=usergroup_role.id).first() # pylint: disable=W0212
        if usergrouprole_assignment2 is None:
            usergrouprole_assignment2 = RBACUserGroupRole(usergroup=usergroup,role=usergroup_role,group=group)
            self.pr.add(usergrouprole_assignment2)
        
        usergrouprole_assignment3 = RBACUserGroupRole(usergroup=usergroup,role=usergroup_role,group=child_group)
        self.pr.add(usergrouprole_assignment3)

        usergroup_role2 = self.pr._session.query(RBACRole).filter_by(name="Test Role 2 for usergroup for roles_for_users_and_usergroups").first() # pylint: disable=W0212
        if usergroup_role2 is None:
            usergroup_role2 = RBACRole("Test Role 2 for usergroup for roles_for_users_and_usergroups")
            self.pr.add(usergroup_role2)

        usergrouprole_assignment4 = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup_id=usergroup.id,group_id=parent_group.id,role_id=usergroup_role2.id).first() # pylint: disable=W0212
        if usergrouprole_assignment4 is None:
            usergrouprole_assignment4 = RBACUserGroupRole(usergroup=usergroup,role=usergroup_role2,group=parent_group)
            self.pr.add(usergrouprole_assignment4)
        
        usergrouprole_assignment5 = RBACUserGroupRole(usergroup=usergroup,role=usergroup_role2,group=child_group)
        self.pr.add(usergrouprole_assignment5)

        usergrouprole_assignment6 = RBACUserGroupRole(usergroup=usergroup,role=usergroup_role2,group=group)
        self.pr.add(usergrouprole_assignment6)

        users,usergroups = child_group.roles_for_users_and_usergroups()
        assert user in users, "Expected user {0} to be in users hash returned by roles_for_users_and_usergroups, but was not: {1}".format(user,users)
        returned_user_role_hash = None
        for user_role_hash in users[user]:
            if user_role_hash['role'] == user_role:
                returned_user_role_hash = user_role_hash
        assert returned_user_role_hash is not None, "Expected user {0} to have role {1} in users hash returned by roles_for_users_and_usergroups, but did not: {2}".format(user,user_role,users[user])
        assert returned_user_role_hash['inherited'] == True, "Expected user {0} to have inherited role {1} in users hash returned by roles_for_users_and_usergroups, but did not: {2}".format(user,user_role,returned_user_role_hash)


        assert usergroup in usergroups, "Expected usergroup {0} to be in usergroups hash returned by roles_for_users_and_usergroups, but was not: {1}".format(usergroup,usergroups)
        returned_usergroup_role_hash = None
        returned_usergroup_role2_hash = None
        for usergroup_role_hash in usergroups[usergroup]:
            if usergroup_role_hash['role'] == usergroup_role:
                returned_usergroup_role_hash = usergroup_role_hash
            if usergroup_role_hash['role'] == usergroup_role2:
                returned_usergroup_role2_hash = usergroup_role_hash

        assert returned_usergroup_role_hash is not None, "Expected usergroup {0} to have role {1} in usergroups hash returned by roles_for_users_and_usergroups, but did not: {2}".format(usergroup,usergroup_role,usergroups[user])
        assert returned_usergroup_role_hash['inherited'] == False, "Expected usergroup {0} to have non-inherited role {1} in usergroups hash returned by roles_for_users_and_usergroups, but did was inherited: {2}".format(usergroup,usergroup_role,returned_usergroup_role_hash)

        assert returned_usergroup_role2_hash is not None, "Expected usergroup {0} to have role {1} in usergroups hash returned by roles_for_users_and_usergroups, but did not: {2}".format(usergroup,usergroup_role2,usergroups[user])
        assert returned_usergroup_role2_hash['inherited'] == False, "Expected usergroup {0} to have non-inherited role {1} in usergroups hash returned by roles_for_users_and_usergroups, but did was inherited: {2}".format(usergroup,usergroup_role2,returned_usergroup_role2_hash)


        self.pr.delete(usergrouprole_assignment5)
        self.pr.delete(usergrouprole_assignment4)
        self.pr.delete(usergrouprole_assignment3)
        self.pr.delete(usergrouprole_assignment2)
        self.pr.delete(userrole_assignment5)
        self.pr.delete(userrole_assignment4)
        self.pr.delete(userrole_assignment3)
        self.pr.delete(userrole_assignment2)
        self.pr.delete(usergrouprole_assignment)
        self.pr.delete(userrole_assignment)
        self.pr.delete(usergroup_role2)
        self.pr.delete(usergroup_role)
        self.pr.delete(user_role2)
        self.pr.delete(user_role)
        self.pr.delete(user)
        self.pr.delete(usergroup)
        self.pr.delete(child_group)
        self.pr.delete(group)


    @attr(scope=["local"])
    @attr("models")
    def test_rbac_group_permissions_for_user(self):
        parent_group = self.pr.groups[0]
        group = self.pr._session.query(RBACGroup).filter_by(name='Test Group permissions_for_user',parent=parent_group,max_vms=10).first() # pylint: disable=W0212
        if group is None:
            group = RBACGroup(name='Test Group permissions_for_user',parent=parent_group,max_vms=10)
            self.pr.add(group)

        child_group = self.pr._session.query(RBACGroup).filter_by(name='Test Group permissions_for_user Child',parent=group).first() # pylint: disable=W0212
        if child_group is None:
            child_group = RBACGroup(name='Test Group permissions_for_user Child',parent=group)
            self.pr.add(child_group)

        usergroup = self.pr._session.query(RBACUserGroup).filter_by(name="Test UserGroup for permissions_for_user").first() # pylint: disable=W0212
        if usergroup is None:
            usergroup = RBACUserGroup("Test UserGroup for permissions_for_user")
            self.pr.add(usergroup)

        user = self.pr._session.query(RBACUser).filter_by(name='Test User roles_for_users_and_usergroups',password='Test User',corpid='Test User roles_for_users_and_usergroups',api_key='Test User',group_id=group.id).first() # pylint: disable=W0212
        if user is None:
            user = RBACUser(name='Test User roles_for_users_and_usergroups',password='Test User',corpid='Test User roles_for_users_and_usergroups',api_key='Test User',group_id=group.id)
            self.pr.add(user)

        self.pr.set_user_usergroups(user,[usergroup.name])

        ref_type = self.pr._session.query(RBACRefType).filter_by(name="Test Type").first() # pylint: disable=W0212
        if ref_type is None:
            ref_type = RBACRefType(name="Test Type")
            self.pr.add(ref_type)

        user_permission = self.pr._session.query(RBACPermission).filter_by(name="Test User Permission").first() # pylint: disable=W0212
        if user_permission is None:
            user_permission = RBACPermission(name="Test User Permission",reftype=ref_type)
            self.pr.add(user_permission)

        usergroup_permission = self.pr._session.query(RBACPermission).filter_by(name="Test UserGroup Permission").first() # pylint: disable=W0212
        if usergroup_permission is None:
            usergroup_permission = RBACPermission(name="Test UserGroup Permission",reftype=ref_type)
            self.pr.add(usergroup_permission)

        # extra_permission ensures we hit the same permission more than once
        extra_permission = self.pr._session.query(RBACPermission).filter_by(name="Test Extra Permission").first() # pylint: disable=W0212
        if extra_permission is None:
            extra_permission = RBACPermission(name="Test Extra Permission",reftype=ref_type)
            self.pr.add(extra_permission)

        user_role = self.pr._session.query(RBACRole).filter_by(name="Test Role for user for permissions_for_user").first() # pylint: disable=W0212
        if user_role is None:
            user_role = RBACRole("Test Role for user for permissions_for_user")
            self.pr.add(user_role)
            user_role.permissions.append(user_permission)
            user_role.permissions.append(extra_permission)
            self.pr._session.commit() # pylint: disable=W0212

        # Also used to ensure we hit the same permission more than once
        user_role2 = self.pr._session.query(RBACRole).filter_by(name="Test Role 2 for user for permissions_for_user").first() # pylint: disable=W0212
        if user_role2 is None:
            user_role2 = RBACRole("Test Role 2 for user for permissions_for_user")
            self.pr.add(user_role2)
            user_role2.permissions.append(user_permission)
            user_role2.permissions.append(extra_permission)
            self.pr._session.commit() # pylint: disable=W0212

        usergroup_role = self.pr._session.query(RBACRole).filter_by(name="Test Role for usergroup for permissions_for_user").first() # pylint: disable=W0212
        if usergroup_role is None:
            usergroup_role = RBACRole("Test Role for usergroup for permissions_for_user")
            self.pr.add(usergroup_role)
            usergroup_role.permissions.append(usergroup_permission)
            usergroup_role.permissions.append(extra_permission)
            self.pr._session.commit() # pylint: disable=W0212

        userrole_assignment = self.pr._session.query(RBACUserRole).filter_by(group_id=group.id,user_id=user.id,role_id=user_role.id).first() # pylint: disable=W0212
        if userrole_assignment is None:
            userrole_assignment = RBACUserRole(group=group,user=user,role=user_role)
            self.pr.add(userrole_assignment)

        userrole_assignment2 = self.pr._session.query(RBACUserRole).filter_by(group_id=group.id,user_id=user.id,role_id=user_role2.id).first() # pylint: disable=W0212
        if userrole_assignment2 is None:
            userrole_assignment2 = RBACUserRole(group=group,user=user,role=user_role2)
            self.pr.add(userrole_assignment2)

        usergrouprole_assignment = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup_id=usergroup.id,group_id=child_group.id,role_id=usergroup_role.id).first() # pylint: disable=W0212
        if usergrouprole_assignment is None:
            usergrouprole_assignment = RBACUserGroupRole(usergroup=usergroup,role=usergroup_role,group=child_group)
            self.pr.add(usergrouprole_assignment)

        permissions = child_group.permissions_for_user(user)

        assert user_permission in permissions, "Expected to have permission {0} in permissions returned by permissions_for_user, but did not: {1}".format(user_permission,permissions)
        assert usergroup_permission in permissions, "Expected to have permission {0} in permissions returned by permissions_for_user, but did not: {1}".format(usergroup_permission,permissions)

        self.pr.set_user_usergroups(user,[])

        self.pr.delete(usergrouprole_assignment)
        self.pr.delete(userrole_assignment)
        self.pr.delete(userrole_assignment2)
        self.pr.delete(usergroup_role)
        self.pr.delete(user_role2)
        self.pr.delete(user_role)
        self.pr.delete(extra_permission)
        self.pr.delete(usergroup_permission)
        self.pr.delete(user_permission)
        self.pr.delete(user)
        self.pr.delete(usergroup)
        self.pr.delete(child_group)
        self.pr.delete(group)

    @attr(scope=["local"])
    @attr("models")
    def test_rbac_group_roles_for_user(self):
        parent_group = self.pr.groups[0]
        group = self.pr._session.query(RBACGroup).filter_by(name='Test Group permissions_for_user',parent=parent_group,max_vms=10).first() # pylint: disable=W0212
        if group is None:
            group = RBACGroup(name='Test Group permissions_for_user',parent=parent_group,max_vms=10)
            self.pr.add(group)

        child_group = self.pr._session.query(RBACGroup).filter_by(name='Test Group permissions_for_user Child',parent=group).first() # pylint: disable=W0212
        if child_group is None:
            child_group = RBACGroup(name='Test Group permissions_for_user Child',parent=group)
            self.pr.add(child_group)

        usergroup = self.pr._session.query(RBACUserGroup).filter_by(name="Test UserGroup for permissions_for_user").first() # pylint: disable=W0212
        if usergroup is None:
            usergroup = RBACUserGroup("Test UserGroup for permissions_for_user")
            self.pr.add(usergroup)

        user = self.pr._session.query(RBACUser).filter_by(name='Test User roles_for_users_and_usergroups',password='Test User',corpid='Test User roles_for_users_and_usergroups',api_key='Test User',group_id=group.id).first() # pylint: disable=W0212
        if user is None:
            user = RBACUser(name='Test User roles_for_users_and_usergroups',password='Test User',corpid='Test User roles_for_users_and_usergroups',api_key='Test User',group_id=group.id)
            self.pr.add(user)

        self.pr.set_user_usergroups(user,[usergroup.name])

        ref_type = self.pr._session.query(RBACRefType).filter_by(name="Test Type").first() # pylint: disable=W0212
        if ref_type is None:
            ref_type = RBACRefType(name="Test Type")
            self.pr.add(ref_type)

        user_permission = self.pr._session.query(RBACPermission).filter_by(name="Test User Permission").first() # pylint: disable=W0212
        if user_permission is None:
            user_permission = RBACPermission(name="Test User Permission",reftype=ref_type)
            self.pr.add(user_permission)

        usergroup_permission = self.pr._session.query(RBACPermission).filter_by(name="Test UserGroup Permission").first() # pylint: disable=W0212
        if usergroup_permission is None:
            usergroup_permission = RBACPermission(name="Test UserGroup Permission",reftype=ref_type)
            self.pr.add(usergroup_permission)

        user_role = self.pr._session.query(RBACRole).filter_by(name="Test Role for user for permissions_for_user").first() # pylint: disable=W0212
        if user_role is None:
            user_role = RBACRole("Test Role for user for permissions_for_user")
            self.pr.add(user_role)
            user_role.permissions.append(user_permission)
            self.pr._session.commit() # pylint: disable=W0212

        usergroup_role = self.pr._session.query(RBACRole).filter_by(name="Test Role for usergroup for permissions_for_user").first() # pylint: disable=W0212
        if usergroup_role is None:
            usergroup_role = RBACRole("Test Role for usergroup for permissions_for_user")
            self.pr.add(usergroup_role)
            usergroup_role.permissions.append(usergroup_permission)
            self.pr._session.commit() # pylint: disable=W0212

        user_role2 = self.pr._session.query(RBACRole).filter_by(name="Test Role 2 for user for permissions_for_user").first() # pylint: disable=W0212
        if user_role2 is None:
            user_role2 = RBACRole("Test Role 2 for user for permissions_for_user")
            self.pr.add(user_role2)
            user_role2.permissions.append(user_permission)
            self.pr._session.commit() # pylint: disable=W0212

        usergroup_role2 = self.pr._session.query(RBACRole).filter_by(name="Test Role 2 for usergroup for permissions_for_user").first() # pylint: disable=W0212
        if usergroup_role2 is None:
            usergroup_role2 = RBACRole("Test Role 2 for usergroup for permissions_for_user")
            self.pr.add(usergroup_role2)
            usergroup_role2.permissions.append(usergroup_permission)
            self.pr._session.commit() # pylint: disable=W0212

        userrole_assignment = self.pr._session.query(RBACUserRole).filter_by(group_id=group.id,user_id=user.id,role_id=user_role.id).first() # pylint: disable=W0212
        if userrole_assignment is None:
            userrole_assignment = RBACUserRole(group=group,user=user,role=user_role)
            self.pr.add(userrole_assignment)

        usergrouprole_assignment = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup_id=usergroup.id,group_id=child_group.id,role_id=usergroup_role.id).first() # pylint: disable=W0212
        if usergrouprole_assignment is None:
            usergrouprole_assignment = RBACUserGroupRole(usergroup=usergroup,role=usergroup_role,group=child_group)
            self.pr.add(usergrouprole_assignment)

        userrole_assignment2 = self.pr._session.query(RBACUserRole).filter_by(group_id=child_group.id,user_id=user.id,role_id=user_role2.id).first() # pylint: disable=W0212
        if userrole_assignment2 is None:
            userrole_assignment2 = RBACUserRole(group=group,user=user,role=user_role)
            self.pr.add(userrole_assignment2)

        usergrouprole_assignment2 = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup_id=usergroup.id,group_id=group.id,role_id=usergroup_role2.id).first() # pylint: disable=W0212
        if usergrouprole_assignment2 is None:
            usergrouprole_assignment2 = RBACUserGroupRole(usergroup=usergroup,role=usergroup_role,group=child_group)
            self.pr.add(usergrouprole_assignment2)

        roles = child_group.roles_for_user(user)

        assert user_role in roles, "Expected to have role {0} in roles returned by roles_for_user, but did not: {1}".format(user_role,roles)
        assert usergroup_role in roles, "Expected to have role {0} in roles returned by roles_for_user, but did not: {1}".format(usergroup_role,roles)

        self.pr.set_user_usergroups(user,[])

        self.pr.delete(usergrouprole_assignment2)
        self.pr.delete(userrole_assignment2)
        self.pr.delete(usergrouprole_assignment)
        self.pr.delete(userrole_assignment)
        self.pr.delete(usergroup_role2)
        self.pr.delete(user_role2)
        self.pr.delete(usergroup_role)
        self.pr.delete(user_role)
        self.pr.delete(usergroup_permission)
        self.pr.delete(user_permission)
        self.pr.delete(user)
        self.pr.delete(usergroup)
        self.pr.delete(child_group)
        self.pr.delete(group)
