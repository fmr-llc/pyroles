import unittest
import sys
sys.path.append('..')

import logging

logging.basicConfig()

from pyroles.pyroles import PyRoles
from pyroles import conf_pyroles
from pyroles.model import RBACRefType,RBACPermission,RBACGroup,RBACRole,RBACUserRole,RBACUserGroup,RBACUserGroupRole,GroupAncestor,RBACUser
from nose.plugins.attrib import attr

class PyrolesTest(unittest.TestCase):
    fixtures = ["test_data.json"]
    def setUp(self):
        self.pr = PyRoles()
        logging.debug("conf_pyroles.dbUrl is {0}".format(conf_pyroles.dbUrl))
        self.pr.connect(conf_pyroles.dbUrl)


        self.all_group = self.pr._session.query(RBACGroup).filter_by(name="All").first() # pylint: disable=W0212
        if self.all_group is None:
            self.all_group = RBACGroup(name="All")
            self.pr.add(self.all_group)

        self.u1 = self.pr._session.query(RBACUser).filter_by(name='ndaapp').first() # pylint: disable=W0212
        if self.u1 is None:
            self.u1 = RBACUser(name='ndaapp',password='ndaapp',corpid='ndaapp',api_key='ndaapp',group_id=1)
            self.pr.add(self.u1)


        self.u2 = self.pr._session.query(RBACUser).filter_by(name='deactivated_test_user').first() # pylint: disable=W0212
        if self.u2 is None:
            self.u2 = RBACUser(name='deactivated_test_user',password='deactivated_test_user',corpid='deactivated_test_user',api_key='deactivated_test_user',group_id=1)
            self.pr.add(self.u2)

        self.u2.active=False

        ref_type = self.pr._session.query(RBACRefType).filter_by(name="Test Type").first() # pylint: disable=W0212
        if ref_type is None:
            ref_type = RBACRefType(name="Test Type")
            self.pr.add(ref_type)

        self.permission = self.pr._session.query(RBACPermission).filter_by(name="Test Permission").first() # pylint: disable=W0212
        if self.permission is None:
            self.permission = RBACPermission(name="Test Permission",reftype=ref_type)
            self.pr.add(self.permission)

        self.permission2 = self.pr._session.query(RBACPermission).filter_by(name="Test Permission 2").first() # pylint: disable=W0212
        if self.permission2 is None:
            self.permission2 = RBACPermission(name="Test Permission 2",reftype=ref_type)
            self.pr.add(self.permission2)

        self.permission3 = self.pr._session.query(RBACPermission).filter_by(name="Test Permission 3").first() # pylint: disable=W0212
        if self.permission3 is None:
            self.permission3 = RBACPermission(name="Test Permission 3",reftype=ref_type)
            self.pr.add(self.permission3)


        self.group = self.pr._session.query(RBACGroup).filter_by(name="Test Group").first() # pylint: disable=W0212
        if self.group is None:
            self.group = RBACGroup(name="Test Group")
            self.pr.add(self.group)

        self.child_group = self.pr._session.query(RBACGroup).filter_by(name="Test Group Child").first() # pylint: disable=W0212
        if self.child_group is None:
            self.child_group = RBACGroup(name="Test Group Child",parent=self.group)
            self.pr.add(self.child_group)

        ancestry_entry = self.pr._session.query(GroupAncestor).filter_by(group_id=self.child_group.id,ancestor_id=self.group.id).first() # pylint: disable=W0212
        if ancestry_entry is None:
            ancestry_entry = GroupAncestor(group_id=self.child_group.id,ancestor_id=self.group.id)
            self.pr.add(ancestry_entry)

        self.role = self.pr._session.query(RBACRole).filter_by(name="Test Role").first() # pylint: disable=W0212
        if self.role is None:
            self.role = RBACRole(name="Test Role")
            self.pr.add(self.role)
            self.role.permissions.append(self.permission)
            self.pr._session.commit() # pylint: disable=W0212
        else:
#            if self.permission not in self.role.permissions:
            if self.permission not in self.role.permissions:
                self.role.permissions.append(self.permission)
                self.pr._session.commit() # pylint: disable=W0212
            
        self.role2 = self.pr._session.query(RBACRole).filter_by(name="Test Role 2").first() # pylint: disable=W0212
        if self.role2 is None:
            self.role2 = RBACRole(name="Test Role 2")
            self.pr.add(self.role2)
            self.role2.permissions.append(self.permission2)
            self.pr._session.commit() # pylint: disable=W0212
        else:
            if self.permission2 not in self.role.permissions:
                self.role2.permissions.append(self.permission2)
                self.pr._session.commit() # pylint: disable=W0212

        self.role3 = self.pr._session.query(RBACRole).filter_by(name="Test Role 3").first() # pylint: disable=W0212
        if self.role3 is None:
            self.role3 = RBACRole(name="Test Role 3")
            self.pr.add(self.role3)
            self.role3.permissions.append(self.permission3)
            self.pr._session.commit() # pylint: disable=W0212
        else:
            if self.permission3 not in self.role.permissions:
                self.role3.permissions.append(self.permission3)
                self.pr._session.commit() # pylint: disable=W0212

        self.user_role = self.pr._session.query(RBACUserRole).filter_by(user=self.u1,role=self.role,group=self.group).first() # pylint: disable=W0212
        if self.user_role is None:
            self.user_role = RBACUserRole(user=self.u1,role=self.role,group=self.group)
            self.pr.add(self.user_role)

        self.user_role2 = self.pr._session.query(RBACUserRole).filter_by(user=self.u1,role=self.role2,group=self.group).first() # pylint: disable=W0212
        if self.user_role2 is None:
            self.user_role2 = RBACUserRole(user=self.u1,role=self.role2,group=self.group)
            self.pr.add(self.user_role2)

        deactivated_user_role = self.pr._session.query(RBACUserRole).filter_by(user=self.u2,role=self.role,group=self.group).first() # pylint: disable=W0212
        if deactivated_user_role is None:
            deactivated_user_role = RBACUserRole(user=self.u2,role=self.role,group=self.group)
            self.pr.add(deactivated_user_role)

    def tearDown(self):
#        self.pr._session.query(RBACUser).filter_by(name='ndaapp').delete() # pylint: disable=W0212
        if self.pr.connected:
            for usergroup in self.u1.usergroups:
                self.u1.usergroups.remove(usergroup)

            deactivated_user_role_query = self.pr._session.query(RBACUserRole).filter_by(user=self.u2,role=self.role,group=self.group) # pylint: disable=W0212
            deactivated_user_role_query.delete()
            self.pr._session.commit() # pylint: disable=W0212
            self.pr.close()

    @attr(scope=["local"])
    @attr("groups")
    def test_user_has_permission_from_userrole(self):
        groups_and_perms = self.pr.evaluate_groups_and_perms_for_user(self.u1)
        assert groups_and_perms is not None
        assert len(groups_and_perms) == len(self.pr.groups)
        assert self.permission in groups_and_perms[self.group], "Expected to have {0} in user perms for group {1}, perms were: {2}".format(self.permission.name,self.group.id,groups_and_perms[self.group])

    @attr(scope=["local"])
    @attr("pyroles")
    def test_user_has_permission_from_usergroup_role(self):

        usergroup_query = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup for evaluate_groups_and_perms_for_user") # pylint: disable=W0212
        usergroup = usergroup_query.first()
        if usergroup is None:
            usergroup = RBACUserGroup(name="Test RBACUsergroup for evaluate_groups_and_perms_for_user")
            self.pr.add(usergroup)

        usergroup_role_query = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup=usergroup,role=self.role3,group=self.group)# pylint: disable=W0212
        usergroup_role = usergroup_role_query.first() 
        if usergroup_role is None:
            usergroup_role = RBACUserGroupRole(usergroup=usergroup,role=self.role3,group=self.group)
            self.pr.add(usergroup_role)

        self.pr.set_user_usergroups(self.u1,[usergroup.name])
        groups_and_perms = self.pr.evaluate_groups_and_perms_for_user(self.u1)
        assert groups_and_perms is not None
        assert len(groups_and_perms) == len(self.pr.groups)
        assert self.permission3 in groups_and_perms[self.group], "Expected to have {0} in user perms for group {1}, perms were: {2}".format(self.permission.name,self.group.id,groups_and_perms[self.group])

        self.pr.set_user_usergroups(self.u1,[])
        usergroup_role_query.delete()
        usergroup_query.delete()

    @attr(scope=["local"])
    @attr("pyroles")
    def test_evaluate_groups_and_roles_for_user(self):
        usergroup_query = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup for evaluate_groups_and_perms_for_user") # pylint: disable=W0212
        usergroup = usergroup_query.first()
        if usergroup is None:
            usergroup = RBACUserGroup(name="Test RBACUsergroup for evaluate_groups_and_perms_for_user")
            self.pr.add(usergroup)

        usergroup_role_query = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup=usergroup,role=self.role3,group=self.group)# pylint: disable=W0212
        usergroup_role = usergroup_role_query.first() 
        if usergroup_role is None:
            usergroup_role = RBACUserGroupRole(usergroup=usergroup,role=self.role3,group=self.group)
            self.pr.add(usergroup_role)

        self.pr.set_user_usergroups(self.u1,[usergroup.name])
        groups_and_perms = self.pr.evaluate_groups_and_roles_for_user(self.u1)
        assert groups_and_perms is not None
        assert len(groups_and_perms) == len(self.pr.groups)
        assert self.role3 in groups_and_perms[self.group], "Expected to have {0} in user perms for group {1}, perms were: {2}".format(self.permission3.name,self.group.id,groups_and_perms[self.group])
        assert self.role in groups_and_perms[self.group], "Expected to have {0} in user perms for group {1}, perms were: {2}".format(self.permission.name,self.group.id,groups_and_perms[self.group])

        self.pr.set_user_usergroups(self.u1,[])
        usergroup_role_query.delete()
        usergroup_query.delete()

    @attr(scope=["local"])
    @attr("pyroles")
    def test_evaluate_groups_with_permission_for_user(self):
        groups = self.pr.evaluate_groups_with_permission_for_user(self.u1,self.permission)
        assert groups is not None
        assert len(groups) == 2, "Expected return value from evaluate_groups_with_permission_for_user to be {0}, was {1}, list was {2}".format(2,len(groups),groups)
        assert self.group in groups, "Expected to have {0} in groups with permission {1} for user {2}, groups were: {3}".format(self.group,self.permission.name,self.u1,groups)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_add_role(self):
        role = self.pr.add_role("Added test role",[{self.permission.name:"Test Type"} ])
        assert role is not None
        assert self.permission in role.permissions, "Expected to have {0} in user perms for added role, perms were: {1}".format(self.permission.name,role.permissions)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_add_role_no_permission_list(self):
        role = self.pr.add_role("Added test role")
        assert role is not None
        assert len(role.permissions) == 0, "Expected to have no perms for added role if no perms were provided, perms were: {0}".format(role.permissions)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_add_role_not_connected(self):
        self.pr.close()
        try: 
            role = self.pr.add_role("Added test role")
            self.fail("Expected to get an exception when calling add_role() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling add_role() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_add_role_nonexistent_permission_name(self):
        roles = self.pr._session.query(RBACRole).filter_by(name="Added test role").all() # pylint: disable=W0212
        for role in roles:
            for permission in role.permissions:
                role.permissions.remove(permission)
            
        self.pr._session.commit()# pylint: disable=W0212
        self.pr._session.query(RBACRole).filter_by(name="Added test role").delete() # pylint: disable=W0212
        self.pr._session.query(RBACPermission).filter_by(name="Nonexistent Permission").delete() # pylint: disable=W0212

        role = self.pr.add_role("Added test role",[{'Nonexistent Permission':"Test Type"} ])
        permission_query = self.pr._session.query(RBACPermission).filter_by(name="Nonexistent Permission") # pylint: disable=W0212
        permission = permission_query.first() # pylint: disable=W0212
        assert role is not None
        assert permission in role.permissions, "Expected to have {0} in user perms for added role, perms were: {1}".format(permission.name,role.permissions)
        role.permissions.remove(permission)
        permission_query.delete()

    @attr(scope=["local"])
    @attr("pyroles")
    def test_evaluate_access_for(self):
        usergroup_query = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup for evaluate_groups_and_perms_for_user") # pylint: disable=W0212
        usergroup = usergroup_query.first()
        if usergroup is None:
            usergroup = RBACUserGroup(name="Test RBACUsergroup for evaluate_groups_and_perms_for_user")
            self.pr.add(usergroup)

        usergroup_role_query = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup=usergroup,role=self.role3,group=self.group)# pylint: disable=W0212
        usergroup_role = usergroup_role_query.first() 
        if usergroup_role is None:
            usergroup_role = RBACUserGroupRole(usergroup=usergroup,role=self.role3,group=self.group)
            self.pr.add(usergroup_role)

        usergroup_query2 = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup 2 for evaluate_groups_and_perms_for_user") # pylint: disable=W0212
        usergroup2 = usergroup_query2.first()
        if usergroup2 is None:
            usergroup2 = RBACUserGroup(name="Test RBACUsergroup 2 for evaluate_groups_and_perms_for_user")
            self.pr.add(usergroup2)

        usergroup_role_query2 = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup=usergroup2,role=self.role3,group=self.child_group)# pylint: disable=W0212
        usergroup_role2 = usergroup_role_query2.first() 
        if usergroup_role2 is None:
            usergroup_role2 = RBACUserGroupRole(usergroup=usergroup2,role=self.role3,group=self.child_group)
            self.pr.add(usergroup_role2)

        self.pr.set_user_usergroups(self.u1,[usergroup.name])
        accesslist = self.pr.evaluate_access_for(self.u1,self.child_group)
        assert accesslist is not None
        assert accesslist.has("Test Type",self.permission.name) == True, "Expected accesslist.has('Test Type',{0}) to be true, but was not.".format(self.permission.name)
        assert accesslist.has("Test Type",self.permission3.name) == True, "Expected accesslist.has('Test Type',{0}) to be true, but was not.".format(self.permission.name)

        self.pr.set_user_usergroups(self.u1,[])
        usergroup_role_query2.delete()
        usergroup_query2.delete()
        usergroup_role_query.delete()
        usergroup_query.delete()

    @attr(scope=["local"])
    @attr("pyroles")
    def test_evaluate_roles_for(self):
        usergroup_query = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup for evaluate_groups_and_perms_for_user") # pylint: disable=W0212
        usergroup = usergroup_query.first()
        if usergroup is None:
            usergroup = RBACUserGroup(name="Test RBACUsergroup for evaluate_groups_and_perms_for_user")
            self.pr.add(usergroup)

        usergroup_role_query = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup=usergroup,role=self.role3,group=self.group)# pylint: disable=W0212
        usergroup_role = usergroup_role_query.first() 
        if usergroup_role is None:
            usergroup_role = RBACUserGroupRole(usergroup=usergroup,role=self.role3,group=self.group)
            self.pr.add(usergroup_role)

        usergroup_query2 = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup 2 for evaluate_groups_and_perms_for_user") # pylint: disable=W0212
        usergroup2 = usergroup_query2.first()
        if usergroup2 is None:
            usergroup2 = RBACUserGroup(name="Test RBACUsergroup 2 for evaluate_groups_and_perms_for_user")
            self.pr.add(usergroup2)

        usergroup_role_query2 = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup=usergroup,role=self.role3,group=self.child_group)# pylint: disable=W0212
        usergroup_role2 = usergroup_role_query2.first() 
        if usergroup_role2 is None:
            usergroup_role2 = RBACUserGroupRole(usergroup=usergroup,role=self.role3,group=self.child_group)
            self.pr.add(usergroup_role2)

        usergroup_query3 = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup 3 for evaluate_groups_and_perms_for_user") # pylint: disable=W0212
        usergroup3 = usergroup_query3.first()
        if usergroup3 is None:
            usergroup3 = RBACUserGroup(name="Test RBACUsergroup 3 for evaluate_groups_and_perms_for_user")
            self.pr.add(usergroup3)

        usergroup_role_query3 = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup=usergroup,role=self.role3,group=self.all_group)# pylint: disable=W0212
        usergroup_role3 = usergroup_role_query3.first() 
        if usergroup_role3 is None:
            usergroup_role3 = RBACUserGroupRole(usergroup=usergroup,role=self.role3,group=self.all_group)
            self.pr.add(usergroup_role3)

        user_role_query = self.pr._session.query(RBACUserRole).filter_by(user=self.u1,role=self.role2,group=self.child_group)# pylint: disable=W0212
        user_role = user_role_query.first()
        if user_role is None:
            user_role = RBACUserRole(user=self.u1,role=self.role2,group=self.child_group)
            self.pr.add(user_role)

        self.pr.set_user_usergroups(self.u1,[usergroup.name])
        role_list = self.pr.evaluate_roles_for(self.u1,self.child_group)
        assert role_list is not None
        assert self.role3 in role_list, "Expected role_list to contain {0}, but did not. List was: {1}".format(self.role3,role_list)
        assert self.role in role_list, "Expected role_list to contain {0}, but did not. List was: {1}".format(self.role,role_list)

        self.pr.set_user_usergroups(self.u1,[])
        self.pr._session.query(RBACUserRole).filter_by(id=user_role.id)# pylint: disable=W0212

        usergroup_role_query3.delete()
        usergroup_query3.delete()
        usergroup_role_query2.delete()
        usergroup_query2.delete()
        usergroup_role_query.delete()
        usergroup_query.delete()

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_users(self):
        userlist = self.pr.users
        assert userlist is not None
        assert self.u1 in userlist, "Expected pr.users() to return a list of users including {0}, but list was: {1}".format(self.u1,userlist)
        assert self.u2 not in userlist, "Expected pr.users() to return a list of users NOT including {0}, but list was: {1}".format(self.u2,userlist)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_accesslist_has(self):
        accesslist = self.pr.evaluate_access_for(self.u1,self.group)
        assert accesslist.has("Test Type",self.permission.name) == True, "Expected accesslist.has('Test Type',{0}) to be true, but was not.".format(self.permission.name)
        assert accesslist.has("Test Type","Bogus Permission Name") == False, "Expected accesslist.has('Test Type','Bogus Permission Name') to be False, but was not."

    @attr(scope=["local"])
    @attr("pyroles")
    def test_accesslist_groups_with_permission(self):
        accesslist = self.pr.evaluate_access_for(self.u1,self.group)
        groups_with_permission = accesslist.groups_with_permission("Test Type",self.permission.name)
        assert self.group in groups_with_permission, "Expected accesslist.groups_with_permission('Test Type',{0}) to return a list of groups including {1}, but list was: {2}".format(self.permission.name,self.group,groups_with_permission)
        assert self.child_group in groups_with_permission, "Expected accesslist.groups_with_permission('Test Type',{0}) to return a list of groups including {1}, but list was: {2}".format(self.permission.name,self.child_group,groups_with_permission)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_accesslist_permission(self):
        usergroup_query = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup for accesslist_permissions") # pylint: disable=W0212
        usergroup = usergroup_query.first()
        if usergroup is None:
            usergroup = RBACUserGroup(name="Test RBACUsergroup for accesslist_permissions")
            self.pr.add(usergroup)

        usergroup_role_query = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup=usergroup,role=self.role,group=self.group)# pylint: disable=W0212
        usergroup_role = usergroup_role_query.first() 
        if usergroup_role is None:
            usergroup_role = RBACUserGroupRole(usergroup=usergroup,role=self.role,group=self.group)
            self.pr.add(usergroup_role)

        self.pr.set_user_usergroups(self.u1,[usergroup.name])
        accesslist = self.pr.evaluate_access_for(self.u1,self.group)
        assert self.permission in accesslist.permissions, "Expected accesslist.permissions() to return a list of permissions including {0}, but list was: {1}".format(self.permission,accesslist.permissions)
        assert len(accesslist.permissions) == 2, "Expected accesslist.permissions() to return a list containing only two permissions, but list was: {0}".format(accesslist.permissions)
        self.pr.set_user_usergroups(self.u1,[])

    @attr(scope=["local"])
    @attr("pyroles")
    def test_set_user_usergroups_empty_usergroups(self):
        self.pr.set_user_usergroups(self.u1,['Test RBACUsergroup'])

        usergroup = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup").first() # pylint: disable=W0212

        assert usergroup in self.u1.usergroups, "Expected to have {0} in usergroups for {1} after calling set_user_usergroups with 'Test RBACUsergroup' in the list, usergroups were: {2}".format(usergroup,self.u1,self.u1.usergroups) # pylint: disable=E1103
        self.pr.set_user_usergroups(self.u1,[])

    @attr(scope=["local"])
    @attr("pyroles")
    def test_set_user_usergroups_new_usergroup(self):
        self.pr._session.query(RBACUserGroup).filter_by(name="Test New RBACUsergroup").delete() # pylint: disable=W0212
        self.pr.set_user_usergroups(self.u1,['Test New RBACUsergroup'])

        usergroup = self.pr._session.query(RBACUserGroup).filter_by(name="Test New RBACUsergroup").first() # pylint: disable=W0212

        assert usergroup in self.u1.usergroups, "Expected to have {0} in usergroups for {1} after calling set_user_usergroups with 'Test RBACUsergroup' in the list, usergroups were: {2}".format(usergroup,self.u1,self.u1.usergroups) # pylint: disable=E1103
        self.pr.set_user_usergroups(self.u1,[])

    @attr(scope=["local"])
    @attr("pyroles")
    def test_set_user_usergroups_add_usergroup(self):
        self.pr.set_user_usergroups(self.u1,['Test RBACUsergroup for add_usergroup'])

        usergroup_query = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup for add_usergroup") # pylint: disable=W0212
        usergroup = usergroup_query.first()
        if usergroup is None:
            usergroup = RBACUserGroup(name="Test RBACUsergroup for add_usergroup")
            self.pr.add(usergroup)

        usergroup2_query = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup 2 for add_usergroup") # pylint: disable=W0212
        usergroup2 = usergroup2_query.first()
        if usergroup2 is None:
            usergroup2 = RBACUserGroup(name="Test RBACUsergroup 2 for add_usergroup")
            self.pr.add(usergroup2)

        assert usergroup in self.u1.usergroups, "Expected to have {0} in usergroups for {1} after calling set_user_usergroups with 'Test RBACUsergroup for add_usergroup' in the list, usergroups were: {2}".format(usergroup,self.u1,self.u1.usergroups) # pylint: disable=E1103
        self.pr.set_user_usergroups(self.u1,['Test RBACUsergroup for add_usergroup','Test RBACUsergroup 2 for add_usergroup' ])
        assert usergroup in self.u1.usergroups, "Expected to have {0} in usergroups for {1} after calling set_user_usergroups with 'Test RBACUsergroup for add_usergroup' and 'Test RBACUsergroup 2 for add_usergroup' in the list, usergroups were: {2}".format(usergroup,self.u1,self.u1.usergroups) # pylint: disable=E1103
        assert usergroup2 in self.u1.usergroups, "Expected to have {0} in usergroups for {1} after calling set_user_usergroups with 'Test RBACUsergroup for add_usergroup' and 'Test RBACUsergroup 2 for add_usergroup' in the list, usergroups were: {2}".format(usergroup2,self.u1,self.u1.usergroups) # pylint: disable=E1103

        self.pr.set_user_usergroups(self.u1,[])
        self.pr._session.commit()  # pylint: disable=W0212
        usergroup_query.delete()
        usergroup2_query.delete()

    @attr(scope=["local"])
    @attr("pyroles")
    def test_set_user_usergroups_add_and_remove_usergroup(self):
        usergroup_query = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup for add_and_remove_usergroup") # pylint: disable=W0212
        usergroup = usergroup_query.first()
        if usergroup is None:
            usergroup = RBACUserGroup(name="Test RBACUsergroup for add_and_remove_usergroup")
            self.pr.add(usergroup)

        usergroup2_query = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup 2 for add_and_remove_usergroup") # pylint: disable=W0212
        usergroup2 = usergroup2_query.first()
        if usergroup2 is None:
            usergroup2 = RBACUserGroup(name="Test RBACUsergroup 2 for add_and_remove_usergroup")
            self.pr.add(usergroup2)

        self.pr.set_user_usergroups(self.u1,['Test RBACUsergroup for add_and_remove_usergroup'])
        assert usergroup in self.u1.usergroups, "Expected to have {0} in usergroups for {1} after calling set_user_usergroups with 'Test RBACUsergroup' in the list, usergroups were: {2}".format(usergroup,self.u1,self.u1.usergroups) # pylint: disable=E1103
        self.pr.set_user_usergroups(self.u1,['Test RBACUsergroup 2 for add_and_remove_usergroup' ])

        assert len(self.u1.usergroups) == 1, "Expected to have one entry in usergroups for {0} after calling set_user_usergroups with 'Test RBACUsergroup 2' when 'Test RBACUsergroup' was previously in the list, usergroups were: {1}".format(self.u1,self.u1.usergroups) # pylint: disable=E1103
        assert usergroup2 in self.u1.usergroups, "Expected to have {0} in usergroups for {1} after calling set_user_usergroups with 'Test RBACUsergroup 2' when 'Test RBACUsergroup' was previously in the list, usergroups were: {2}".format(usergroup2,self.u1,self.u1.usergroups) # pylint: disable=E1103
        self.pr.set_user_usergroups(self.u1,[])

        usergroup_query.delete()
        usergroup2_query.delete()

    @attr(scope=["local"])
    @attr("pyroles")
    def test_set_user_usergroups_clear_usergroups(self):
        self.pr.set_user_usergroups(self.u1,['Test RBACUsergroup for clear_usergroups'])
        usergroup = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup for clear_usergroups").first() # pylint: disable=W0212
        assert usergroup in self.u1.usergroups, "Expected to have {0} in usergroups for {1} after calling set_user_usergroups with 'Test RBACUsergroup for clear_usergroups' in the list, usergroups were: {2}".format(usergroup,self.u1,self.u1.usergroups) # pylint: disable=E1103
        self.pr.set_user_usergroups(self.u1,[])
        assert len(self.u1.usergroups) == 0, "Expected to have one entry in usergroups for {0} after calling set_user_usergroups with an empty list when 'Test RBACUsergroup for clear_usergroups' was previously in the list, usergroups were: {1}".format(self.u1,self.u1.usergroups) # pylint: disable=E1103

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_usergroups(self):
        self.pr.set_user_usergroups(self.u1,['Test RBACUsergroup'])
        usergroup = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup").first() # pylint: disable=W0212
        usergrouplist = self.pr.usergroups
        assert usergrouplist is not None
        assert usergroup in usergrouplist, "Expected pr.usergroups() to return a list of usergroups including {0}, but list was: {1}".format(usergroup,usergrouplist)
        self.pr.set_user_usergroups(self.u1,[])

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_user_roles(self):
        user_role_list = self.pr.user_roles
        assert user_role_list is not None
        assert self.user_role in user_role_list, "Expected pr.user_roles() to return a list of user roles including {0}, but list was: {1}".format(self.user_role,user_role_list)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_objects_to_ids(self):
        user_list = self.pr.users
        assert user_list is not None
        id_list = self.pr.objects_to_ids(user_list)
        assert self.u1.id in id_list, "Expected pr.objects_to_ids(user_list) to return a list of user ids including {0}, but list was: {1}".format(self.u1.id,id_list)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_role_by_name(self):
        role = self.pr.get_role_by_name("Test Role")
        assert role is not None
        assert role.id == self.role.id, "Expected pr.get_role_by_name('Test Role') to return role id {0}, but returned: {1}".format(self.role.id,role.id)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_role_by_name_nonexistent_role(self):
        self.pr._session.query(RBACRole).filter_by(name="Nonexistent Role").delete() # pylint: disable=W0212
        role = self.pr.get_role_by_name("Nonexistent Role")
        assert role is None, "Expected pr.get_role_by_name('Nonexistent Role') to return None, but returned: {0}".format(role.id)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_user_by_id(self):
        user = self.pr.get_user_by_id(self.u1.id)
        assert user is not None
        assert user.id == self.u1.id, "Expected pr.get_user_by_id({0}) to return user with id {0}, but returned: {1}".format(self.u1.id,user.id)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_user_by_id_nonexistent_user(self):
        user = self.pr.get_user_by_id(999999)
        assert user is None, "Expected pr.get_user_by_id(999999) to return None, but did not"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_group_by_id(self):
        group = self.pr.get_group_by_id(self.group.id)
        assert group is not None
        assert group.id == self.group.id, "Expected pr.get_group_by_id({0}) to return group with id {0}, but returned: {1}".format(self.group.id,group.id)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_group_by_id_nonexistent_group(self):
        group = self.pr.get_group_by_id(999999)
        assert group is None, "Expected pr.get_group_by_id(999999) to return None, but did not"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_user_by_name(self):
        user = self.pr.get_user_by_name(self.u1.name)
        assert user is not None
        assert user.name == self.u1.name, "Expected pr.get_user_by_name({0}) to return user with id {0}, but returned: {1}".format(self.u1.name,user.name)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_user_by_name_nonexistent_user(self):
        user = self.pr.get_user_by_name('Bogus Name')
        assert user is None, "Expected pr.get_user_by_name(999999) to return None, but did not"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_group_by_name(self):
        group = self.pr.get_group_by_name(self.group.name)
        assert group is not None
        assert group.name == self.group.name, "Expected pr.get_group_by_name({0}) to return group with id {0}, but returned: {1}".format(self.group.name,group.name)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_group_by_name_nonexistent_group(self):
        group = self.pr.get_group_by_name('Bogus Name')
        assert group is None, "Expected pr.get_group_by_name(999999) to return None, but did not"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_permission(self):
        permission = self.pr.get_permission(self.permission.name,self.permission.reftype.name)
        assert permission is not None
        assert permission.id == self.permission.id, "Expected pr.get_permission_by_id({0},{1}) to return permission with id {2}, but returned: {3}".format(self.permission.name,self.permission.reftype.name,self.permission.id,permission.id)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_get_permission_nonexistent_permission(self):
        permission = self.pr.get_permission("Bogus Permission",self.permission.reftype.name)
        assert permission is None, "Expected pr.get_permission_by_id({0},{1}) to return None, but returned: {2}".format(self.permission.name,self.permission.reftype.name,permission.id)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_pyroles_usergroup_roles(self):

        usergroup_query = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup for usergroup_roles") # pylint: disable=W0212
        usergroup = usergroup_query.first()
        if usergroup is None:
            usergroup = RBACUserGroup(name="Test RBACUsergroup for usergroup_roles")
            self.pr.add(usergroup)

        usergroup_role_query = self.pr._session.query(RBACUserGroupRole).filter_by(usergroup=usergroup,role=self.role,group=self.group)# pylint: disable=W0212
        usergroup_role = usergroup_role_query.first() 
        if usergroup_role is None:
            usergroup_role = RBACUserGroupRole(usergroup=usergroup,role=self.role,group=self.group)
            self.pr.add(usergroup_role)

        usergroup_role_list = self.pr.usergroup_roles
        assert usergroup_role_list is not None
        assert usergroup_role in usergroup_role_list, "Expected pr.usergroup_roles() to return a list of usergroup roles including {0}, but list was: {1}".format(usergroup_role,usergroup_role_list)

        usergroup_role_query.delete()
        usergroup_query.delete()

    @attr(scope=["local"])
    @attr("pyroles")
    def test_assign_role_user_system_context(self):
        user_role = self.pr.assign_role(self.u1,self.role,self.child_group)
        assert user_role is not None
        assert user_role.role == self.role, "Expected user role returned by assign_role() to have role {0}, but had: {1}".format(self.role,user_role.role)
        assert user_role.user == self.u1, "Expected user role returned by assign_role() to have user {0}, but had: {1}".format(self.u1,user_role.user)
        assert user_role.group == self.child_group, "Expected user role returned by assign_role() to have group {0}, but had: {1}".format(self.child_group,user_role.group)
        user_role_query = self.pr._session.query(RBACUserRole).filter_by(id=user_role.id) # pylint: disable=W0212
        user_role_query.delete()

    @attr(scope=["local"])
    @attr("pyroles")
    def test_assign_role_user_user_context(self):
        self.pr.set_user(self.u1)
        user_role = self.pr.assign_role(self.u2,self.role,self.child_group)
        assert user_role is not None
        assert user_role.role == self.role, "Expected user role returned by assign_role() to have role {0}, but had: {1}".format(self.role,user_role.role)
        assert user_role.user == self.u2, "Expected user role returned by assign_role() to have user {0}, but had: {1}".format(self.u2,user_role.user)
        assert user_role.group == self.child_group, "Expected user role returned by assign_role() to have group {0}, but had: {1}".format(self.child_group,user_role.group)
        user_role_query = self.pr._session.query(RBACUserRole).filter_by(id=user_role.id) # pylint: disable=W0212
        user_role_query.delete()
        self.pr.set_user(None)

    @attr(scope=["local"])
    @attr("pyroles")
    def test_assign_role_user_user_context_no_perms(self):
        user_query = self.pr._session.query(RBACUser).filter_by(name="no_perms_user") # pylint: disable=W0212
        self.u3 = user_query.first()
        if self.u3 is None:
            self.u3 = RBACUser(name="no_perms_user",password="no_perms_user",corpid="no_perms_user",group_id=1)
            self.pr.add(self.u3)

        self.pr.set_user(self.u3)
        try:
            user_role = self.pr.assign_role(self.u2,self.role,self.child_group)
            self.pr.set_user(None)
            user_query.delete()
            self.fail("Expected assign_role() to throw an exception if the user had no permissions!")
        except Exception as e:
            self.pr.set_user(None)
            expected_error = "Insufficient Rights to Assign Role"
            assert str(e) == expected_error, "Expected error message to be {0}, was {1}".format(expected_error,str(e))
            user_query.delete()

    @attr(scope=["local"])
    @attr("pyroles")
    def test_assign_role_usergroup(self):
        usergroup_query = self.pr._session.query(RBACUserGroup).filter_by(name="Test RBACUsergroup for assign_role") # pylint: disable=W0212
        usergroup = usergroup_query.first()
        if usergroup is None:
            usergroup = RBACUserGroup(name="Test RBACUsergroup for assign_role")
            self.pr.add(usergroup)

        usergroup_role = self.pr.assign_role(usergroup,self.role,self.child_group)
        assert usergroup_role is not None
        assert usergroup_role.role == self.role, "Expected user role returned by assign_role() to have role {0}, but had: {1}".format(self.role,usergroup_role.role)
        assert usergroup_role.usergroup == usergroup, "Expected user role returned by assign_role() to have user {0}, but had: {1}".format(usergroup,usergroup_role.usergroup) # pylint: disable=E1103
        assert usergroup_role.group == self.child_group, "Expected user role returned by assign_role() to have group {0}, but had: {1}".format(self.child_group,usergroup_role.group)

        self.pr._session.query(RBACUserGroupRole).filter_by(id=usergroup_role.id).delete() # pylint: disable=W0212

    @attr(scope=["local"])
    @attr("pyroles")
    def test_delete_group(self):
        group_query = self.pr._session.query(RBACGroup).filter_by(name="Test Group for deletion") # pylint: disable=W0212
        group_for_deletion = group_query.first()
        if group_for_deletion is None:
            group_for_deletion = RBACGroup(name="Test Group for deletion")
            self.pr.add(group_for_deletion)

        child_group_query = self.pr._session.query(RBACGroup).filter_by(name="Test Group Child for deletion") # pylint: disable=W0212
        child_group_for_deletion = child_group_query.first()
        if child_group_for_deletion is None:
            child_group_for_deletion = RBACGroup(name="Test Group Child for deletion",parent=group_for_deletion)
            self.pr.add(child_group_for_deletion)

        self.pr.delete(group_for_deletion)

        self.pr._session.expire_all() # pylint: disable=W0212
        group_after_deletion = group_query.first()
        child_group_after_deletion = child_group_query.first()

        assert group_after_deletion is None, "Expected not to have a group with the name 'Test Group for deletion' after deleting it, but did!"
        assert child_group_after_deletion is None, "Expected not to have a group with the name 'Test Group Child for deletion' after deleting its parent, but did!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_add_not_connected(self):
        self.pr.close()
        try: 
            self.pr.add("foo")
            self.fail("Expected to get an exception when calling add() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling add() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_assign_role_not_connected(self):
        self.pr.close()
        try: 
            self.pr.assign_role("foo","bar","baz")
            self.fail("Expected to get an exception when calling assign_role() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling assign_role() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_delete_not_connected(self):
        self.pr.close()
        try: 
            self.pr.delete("foo")
            self.fail("Expected to get an exception when calling delete() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling delete() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_evaluate_groups_and_roles_for_user_not_connected(self):
        self.pr.close()
        try: 
            self.pr.evaluate_groups_and_roles_for_user("foo")
            self.fail("Expected to get an exception when calling evaluate_groups_and_roles_for_user() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling evaluate_groups_and_roles_for_user() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_evaluate_access_for_not_connected(self):
        self.pr.close()
        try: 
            self.pr.evaluate_access_for("foo","bar")
            self.fail("Expected to get an exception when calling evaluate_access_for() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling evaluate_access_for() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_evaluate_roles_for_not_connected(self):
        self.pr.close()
        try: 
            self.pr.evaluate_roles_for("foo","bar")
            self.fail("Expected to get an exception when calling evaluate_roles_for() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling evaluate_roles_for() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_evaluate_groups_and_perms_for_user_not_connected(self):
        self.pr.close()
        try: 
            self.pr.evaluate_groups_and_perms_for_user("foo")
            self.fail("Expected to get an exception when calling evaluate_groups_and_perms_for_user() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling evaluate_groups_and_perms_for_user() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_get_user_by_id_not_connected(self):
        self.pr.close()
        try: 
            self.pr.get_user_by_id(1)
            self.fail("Expected to get an exception when calling get_user_by_id() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling get_user_by_id() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_get_group_by_id_not_connected(self):
        self.pr.close()
        try: 
            self.pr.get_group_by_id(1)
            self.fail("Expected to get an exception when calling get_group_by_id() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling get_group_by_id() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_get_user_by_name_not_connected(self):
        self.pr.close()
        try: 
            self.pr.get_user_by_name(1)
            self.fail("Expected to get an exception when calling get_user_by_name() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling get_user_by_name() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_get_group_by_name_not_connected(self):
        self.pr.close()
        try: 
            self.pr.get_group_by_name(1)
            self.fail("Expected to get an exception when calling get_group_by_name() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling get_group_by_name() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_set_user_not_connected(self):
        self.pr.close()
        try: 
            self.pr.set_user(1)
            self.fail("Expected to get an exception when calling set_user() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling set_user() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_set_user_usergroups_not_connected(self):
        self.pr.close()
        try: 
            self.pr.set_user_usergroups(1)
            self.fail("Expected to get an exception when calling set_user_usergroups() if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when calling set_user_usergroups() if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_permissions_not_connected(self):
        self.pr.close()
        try: 
            perms = self.pr.permissions
            self.fail("Expected to get an exception when accessing permissions if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when accessing permissions if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_roles_not_connected(self):
        self.pr.close()
        try: 
            perms = self.pr.roles
            self.fail("Expected to get an exception when accessing roles if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when accessing roles if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_groups_not_connected(self):
        self.pr.close()
        try: 
            perms = self.pr.groups
            self.fail("Expected to get an exception when accessing groups if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when accessing groups if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_reftypes_not_connected(self):
        self.pr.close()
        try: 
            perms = self.pr.reftypes
            self.fail("Expected to get an exception when accessing reftypes if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when accessing reftypes if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_usergroups_not_connected(self):
        self.pr.close()
        try: 
            perms = self.pr.usergroups
            self.fail("Expected to get an exception when accessing usergroups if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when accessing usergroups if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_usergroup_roles_not_connected(self):
        self.pr.close()
        try: 
            perms = self.pr.usergroup_roles
            self.fail("Expected to get an exception when accessing usergroup_roles if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when accessing usergroup_roles if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_user_roles_not_connected(self):
        self.pr.close()
        try: 
            perms = self.pr.user_roles
            self.fail("Expected to get an exception when accessing user_roles if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when accessing user_roles if we were not connected, but did not!"

    @attr(scope=["local"])
    @attr("pyroles")
    def test_users_not_connected(self):
        self.pr.close()
        try: 
            perms = self.pr.users
            self.fail("Expected to get an exception when accessing users if we were not connected, but did not!")
        except Exception as e:
            assert e.message == "Not Connected", "Expected to get an exception when accessing users if we were not connected, but did not!"
