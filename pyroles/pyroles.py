from sqlalchemy import create_engine, and_
from sqlalchemy.orm import sessionmaker
from model import RBACRefType,RBACRole, RBACPermission,RBACGroup,RBACUser,RBACUserGroup,RBACUserRole,RBACUserGroupRole,GroupAncestor
from accesslist import AccessList
import logging


class PyRoles(object):
    
    def __init__(self,dbUrl=None):
        self._dbUrl = None
        self._engine = None
        self._session = None        
        self.connected = False
        self._user_for_evaluations = None
        
        if dbUrl is not None:
            self.connect(dbUrl)
        
    def add(self,object_to_add):
        """Add an object to the session and commit it to the database"""
        if self.connected == False:
            raise Exception("Not Connected")
        self._session.add(object_to_add)        
        self._session.commit()
        return object_to_add   
        
    def add_role(self,role_name,permission_list=None):
        """Add a new role with permissions"""

        if self.connected == False:
            logging.debug("add_role called when not connected!")
            raise Exception("Not Connected")
        
        if permission_list == None:
            permission_list = []

        logging.debug("Adding role '"+role_name+"'")
        role = RBACRole(role_name)
        self._session.add(role)
        
        
        for permAndType in permission_list:
            permission_name = permAndType.keys()[0]
            reftype_name = permAndType[permission_name]
            reftype = filter(lambda r: r.name==reftype_name,self.reftypes)[0]
            
            logging.debug("Adding permission '"+permission_name+"':"+reftype_name+" to role '"+role_name+"'")
            
            existing_permissions = filter(lambda p: p.name==permission_name and p.reftype.name==reftype_name,self._permissions())
            if len(existing_permissions) > 0:
                permission = existing_permissions[0]
            else:
                permission = RBACPermission(permission_name,reftype)
                    
            role.permissions.append(permission)
        
        self._session.commit()
        return role
        
    def assign_role(self,user_or_usergroup,role,group):
        """Assign a role to a user or usergroup"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        if type(user_or_usergroup) is RBACUser:
            logging.debug("Assigning user '"+user_or_usergroup.name+"' to role '"+str(role)+"' for group '"+group.name+"'")
        
            if self._user_for_evaluations is not None:
                #First we must ensure the user has the same role in order to delegate it:
                roles = self.evaluate_roles_for(self._user_for_evaluations,group)
                if role not in roles:
                    raise Exception("Insufficient Rights to Assign Role")
        
            return self.add(RBACUserRole(user_or_usergroup,role,group))
        else:
            logging.debug("Assigning usergroup '"+user_or_usergroup.name+"' to role '"+str(role)+"' for group '"+group.name+"'")
            
            return self.add(RBACUserGroupRole(user_or_usergroup,role,group))
    
    def connect_to_existing_session(self,session):
        """Connect to an existing session, rather than creating a new session"""

        if self.connected == True:
            raise Exception("Already Connected")
        self._dbUrl = None
        self._session = session
        self._engine = None
        self.connected = True    
            
    def connect(self,dbUrl):
        """Connect to the database and create a new session"""
        self._dbUrl = dbUrl
        self.connected = False
        
        self._engine = create_engine(dbUrl)
        
        Session = sessionmaker(autoflush=True,autocommit=False,expire_on_commit=True)
        self._session = Session(bind=self._engine)
                         
        self.connected = True
        
    def close(self):
        """Close the database connection and session"""
        if self.connected:
            if self._engine is not None:
                self._engine.dispose()
                
            self._session.close()                        
            self.connected = False    
    


    def delete(self,object_to_delete):
        """Delete an object from the database; if the object is an RBACGroup, delete its children as well"""

        if self.connected == False:
            raise Exception("Not Connected")
        
        logging.debug("Deleting object "+str(object_to_delete))
        
        if type(object_to_delete) is RBACGroup:
            logging.debug("Object is {0}, deleting children".format(type(object_to_delete)))
            
            #Examine the children
            for child in object_to_delete.children:
                logging.debug("Deleting Child of {0}: {1}".format(object_to_delete,child))
                self.delete(child)
                    
        self._session.delete(object_to_delete)        
        self._session.commit()
        return object_to_delete
    
    def __get_groups(self):
        groups = {}
        for group in self._groups():
            groups[group] = []
        return groups
    
    def __apply_permissions_or_roles_downwards(self,groups,parent_group):
        """Apply permissions or roles for a group to all its children. Takes a dict keyed on group, and updates that dict."""

        children = self._session.query(GroupAncestor).filter(GroupAncestor.ancestor_id==parent_group.id).all()        
        child_group_ids = [child.group_id for child in children]
        for group in groups:
            if group.id in child_group_ids:
                for perm in groups[parent_group]:
                    if perm not in groups[group]:
                        groups[group].append(perm) #Copy list of permissions down

    def evaluate_groups_and_perms_for_user(self,user):
        """Get the permissions for the specified user for all groups. Returns a dictionary where the KEY is the RBACGroup and the value is an array of RBACPermissions"""

        if self.connected == False:
            raise Exception("Not Connected")
        
        groups_and_perms = self.__get_groups()        
        for usergroup in user.usergroups:
            for r_a in usergroup.role_assignments:
                logging.debug("Adding group {0} permissions".format(r_a.group))
                groups_and_perms[r_a.group] = r_a.group.permissions_for_user(user)
                self.__apply_permissions_or_roles_downwards(groups_and_perms,r_a.group)            

        for r_a in user.role_assignments:
            logging.debug("Adding group {0} permissions".format(r_a.group))
            groups_and_perms[r_a.group] = r_a.group.permissions_for_user(user)        
            self.__apply_permissions_or_roles_downwards(groups_and_perms,r_a.group)
            
        return groups_and_perms
        
    def evaluate_groups_and_roles_for_user(self,user):
        """Get the roles for the specified user for all groups. Returns a dictionary where the KEY is the RBACGroup and the value is an array of RBACRoles"""
        
        if self.connected == False:
            raise Exception("Not Connected")
        
        groups_and_roles = self.__get_groups()
        for r_a in user.role_assignments:
            groups_and_roles[r_a.group] = r_a.group.roles_for_user(user)
            self.__apply_permissions_or_roles_downwards(groups_and_roles,r_a.group)
        
        for usergroup in user.usergroups:
            for r_a in usergroup.role_assignments:
                groups_and_roles[r_a.group] = r_a.group.roles_for_user(user)
                self.__apply_permissions_or_roles_downwards(groups_and_roles,r_a.group)
                
        return groups_and_roles
        
    def evaluate_groups_with_permission_for_user(self,user,perm):
        """Get the groups for which a user has a specific permission. Returns a list of groups."""
        groups_and_perms = self.evaluate_groups_and_perms_for_user(user)
        groups = filter(lambda g: perm in groups_and_perms[g],groups_and_perms)
        return groups
    
    def evaluate_access_for(self,user,group):
        """Get an AccessList for the specified user and group"""
        if self.connected == False:
            raise Exception("Not Connected")

        perms = []
        target_group = group
        while target_group is not None:
            #First evaluate user's direct assignments:
            for role_assignment in user.role_assignments:
                logging.debug("Checking to see if role_assignment.group {0} matches target_group {1}".format(role_assignment.group,target_group))
                if role_assignment.group == target_group:
                    for permission in role_assignment.role.permissions:
                        logging.debug("evaluate: Found permission '"+str(permission)+"' for group '"+group.full_path+"'")
                        perms.append([permission,target_group])
            #Second, evaluate user's usergroup assignments:
            for usergroup in user.usergroups:
                for role_assignment in usergroup.role_assignments:
                    logging.debug("Checking to see if role_assignment.group {0} matches target_group {1}".format(role_assignment.group,target_group))
                    if role_assignment.group == target_group:
                        for permission in role_assignment.role.permissions:
                            logging.debug("evaluate: Found permission '"+str(permission)+"' for group '"+group.full_path+"' via usergroup '"+usergroup.name+"'")
                            perms.append([permission,target_group])
            
            #Now move up in the tree and repeat
            target_group = target_group.parent
        
        return AccessList(self,user,perms)
    
    def evaluate_roles_for(self,user,group):
        """Get a list of roles for the specified user and group"""
        if self.connected == False:
            raise Exception("Not Connected")

        logging.debug("evaluate_roles_for: Evaluating hierarchical roles for '"+user.name+"' for '"+group.full_path+"'")
        roles = []
        target_group = group
        while target_group is not None:
            logging.debug("evaluate: Evaluating hierarchical roles for '"+user.name+"' for '"+group.full_path+"', currently checking group {0}".format(target_group))
            for role_assignment in user.role_assignments:
                if role_assignment.group == target_group:
                    logging.debug("Checking to see if role {0} is in roles ({1}) (target group is {2})".format(role_assignment.role,roles,target_group))
                    if role_assignment.role not in roles:
                        roles.append(role_assignment.role)
            
            for usergroup in user.usergroups:
                for role_assignment in usergroup.role_assignments:
                    if role_assignment.group == target_group:
                        logging.debug("Checking to see if role {0} is in roles ({1}) (target group is {2})".format(role_assignment.role,roles,target_group))
                        if role_assignment.role not in roles:
                            roles.append(role_assignment.role)        
            
            target_group = target_group.parent
        
        return roles

    def get_user_by_id(self,user_id):
        """Get a user by id"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        rbac_user = self._session.query(RBACUser).filter(and_(RBACUser.id==user_id, RBACUser.active==True)).first()
        return rbac_user

    def get_group_by_id(self,group_id):
        """Get a user by id"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        rbac_group = self._session.query(RBACGroup).filter(RBACGroup.id==group_id).first()
        return rbac_group
            
    def get_user_by_name(self,user_name):
        """Get a user by name"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        rbac_user = self._session.query(RBACUser).filter(and_(RBACUser.name==user_name, RBACUser.active==True)).first()
        return rbac_user

    def get_group_by_name(self,group_name):
        """Get a group by name"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        rbac_group = self._session.query(RBACGroup).filter(RBACGroup.name==group_name).first()
        return rbac_group
            
    def get_permission(self,permission_name,permission_type):
        "Get an RBACPermission object with a given name and reftype"
        results = filter(lambda p: p.name==permission_name and p.reftype.name==permission_type,self._permissions())
        if len(results) == 0:
            return None
        return results[0]
    
    def get_role_by_name(self,role_name):
        """Get a role by name"""
        results = filter(lambda r: r.name==role_name,self._roles())
        if len(results) == 0:
            return None
        return results[0]    

    def _groups(self):
        """Return a list of all groups"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        groups = self._session.query(RBACGroup).filter(RBACGroup.deleted==False).all()
        return groups
    
    groups = property(_groups,None,None,None)  
    
    def objects_to_ids(self,list_of_objects):
        """Given a list of objects, return a corresponding list of the object ids"""
        ids = []
        for obj in list_of_objects:
            ids.append(obj.id)
        return ids   

    def _permissions(self):
        """Return a list of all permissions"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        permissions = self._session.query(RBACPermission).all()
        return permissions  
    
    permissions = property(_permissions,None,None,None)
    
    def _reftypes(self):
        """Return a list of all reftypes"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        reftypes = self._session.query(RBACRefType).all()
        return reftypes
    
    reftypes = property(_reftypes,None,None,None)    
                                    
    def _roles(self):
        """Return a list of all roles"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        roles = self._session.query(RBACRole).all()
        return roles
    
    roles = property(_roles,None,None,None)
    
    def set_user(self,user):
        """Set the user used for various evaluations"""
        if self.connected == False:
            raise Exception("Not Connected")
        self._user_for_evaluations = user
        
    def set_user_usergroups(self,user,usergroup_name_list=None):
        """Set the usergroups a user is associated with. Takes a list
        of usergroup names (not usergroup objects!), and associates
        the user with that list of usergroups only, overwriting the
        previous associations and removing any usergroups not in the
        list from the usergroups the user is associated with."""

        if usergroup_name_list is None:
            usergroup_name_list = []

        if self.connected == False:
            raise Exception("Not Connected")
        
        logging.debug("Usergroups for {0} are: {1}".format(user,user.usergroups))
        usergroups_to_remove = []
        usergroups_to_remove.extend(user.usergroups)
        for usergroup in usergroups_to_remove:
            logging.debug("Removing {0} from usergroups for {1}, current usergroup contents are: {2}".format(usergroup,user,user.usergroups))
            user.usergroups.remove(usergroup)
        
        logging.debug("Done clearing usergroups for {0}, current usergroup_contents are: {1}".format(user,user.usergroups))

        for usergroup_name in usergroup_name_list:
            existing_entries = filter(lambda ug: ug.name==usergroup_name,self._usergroups())
            if len(existing_entries) == 0:
                existing_entries = [RBACUserGroup(usergroup_name)]
                self._session.add(existing_entries[0])
            
            user.usergroups.append(existing_entries[0])
        
        self._session.commit()
    
    def _usergroups(self):
        """Return a list of all usergroups"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        return self._session.query(RBACUserGroup).all()
    
    usergroups = property(_usergroups,None,None,None)
    
    def _usergroup_roles(self):
        """Return a list of all usergroup role associations"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        return self._session.query(RBACUserGroupRole).all()
    
    usergroup_roles = property(_usergroup_roles,None,None,None)        
    
    def _user_roles(self):
        """Return a list of all user role associations"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        return self._session.query(RBACUserRole).all()
    
    user_roles = property(_user_roles,None,None,None)
    
    def _users(self):
        """Return a list of all users"""
        if self.connected == False:
            raise Exception("Not Connected")
        
        users = self._session.query(RBACUser).filter_by(active=True).all()
        return users
    
    users = property(_users,None,None,None)
