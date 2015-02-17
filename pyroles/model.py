from sqlalchemy import Table,Column,Integer,String,ForeignKey, DateTime,Boolean

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship,backref
from datetime import datetime

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/..')
import logging

from . import conf_pyroles

Base = declarative_base()

rbac_user_usergroups = Table('t_rbac_user_usergroups', Base.metadata,
    Column('user_id',Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_users.id'),primary_key=True),
    Column('usergroup_id',Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_usergroups.id'),primary_key=True),
    schema=conf_pyroles.schema_name
    ) 

rbac_role_permissions = Table('t_rbac_role_permissions', Base.metadata,
    Column('role_id',Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_roles.id'),primary_key=True),
    Column('permission_id',Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_permissions.id'),primary_key=True),
    schema=conf_pyroles.schema_name
    ) 

class RBACRefType(Base):
    __tablename__ = "t_rbac_ref_types"
    __table_args__ = {'schema':conf_pyroles.schema_name}
    
    id = Column(Integer, primary_key=True)
    name = Column(String,nullable=False)
    
    def __init__(self,name):
        self.name = name
        super(RBACRefType,self).__init__()

    def __repr__(self):
        return "<RBACRefType('%s','%s')>" % (self.id,self.name)   
    
    
        
class RBACUser(Base):
    __tablename__ = "t_rbac_users"
    __table_args__ = {'schema':conf_pyroles.schema_name}
    
    id = Column(Integer, primary_key=True)
    name = Column(String,nullable=False)
    corpid = Column(String,nullable=False)
    password = Column(String,nullable=False)
    api_key = Column(String,nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    last_accessed_at = Column(DateTime)
    disclaimer_accepted = Column(DateTime)    
                    
    group_id = Column(Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_groups.id'))
    group = relationship("RBACGroup",backref='users',order_by=id)
    active = Column(Boolean,nullable=False, default=True)
    
    def __init__(self,name,corpid,password,group_id,api_key=None):
        self.name = name
        self.corpid = corpid
        self.password = password
        self.group_id = group_id
        self.api_key = "?" if api_key == None else api_key
        super(RBACUser,self).__init__()
        
    def __repr__(self):
        return "<RBACUser(id:'%s',corpid:'%s',name:'%s',group:'%s')>" % (self.id,self.corpid,self.name,self.group.name)
    
    
class RBACUserGroup(Base):
    __tablename__ = "t_rbac_usergroups"
    __table_args__ = {'schema':conf_pyroles.schema_name}
    
    id = Column(Integer, primary_key=True)
    name = Column(String,nullable=False)
    
    users = relationship("RBACUser",secondary=rbac_user_usergroups,backref="usergroups")
 
    def __init__(self,name):
        self.name = name
        super(RBACUserGroup,self).__init__()
        
    def __repr__(self):
        return "<RBACUserGroup('%s','%s')>" % (self.id,self.name)         

    
class RBACRole(Base):
    __tablename__ = "t_rbac_roles"
    __table_args__ = {'schema':conf_pyroles.schema_name}
    
    id = Column(Integer, primary_key=True)
    name = Column(String,nullable=False)
    description = Column(String,nullable=True)
    
    permissions = relationship("RBACPermission",secondary=rbac_role_permissions,backref="roles")
 
    def __init__(self,name):
        self.name = name
        super(RBACRole,self).__init__()
        
    def __repr__(self):
        return "<RBACRole('%s','%s')>" % (self.id,self.name)     
        
    
class RBACGroup(Base):
    __tablename__ = "t_rbac_groups"
    __table_args__ = {'schema':conf_pyroles.schema_name}
    
    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_groups.id'))
    name = Column(String,nullable=False)
    deleted = Column(Boolean,default=False)
    max_vms = Column(Integer)

    children = relationship("RBACGroup",backref=backref('parent',remote_side=id))
        
    
    def __init__(self,name,parent=None,max_vms=None):
        if parent is not None:
            self.parent_id=parent.id
        if max_vms is not None:
            self.max_vms=max_vms               
        self.name = name
        super(RBACGroup,self).__init__()
        
    def __repr__(self):
        return "<RBACGroup(id:'%s',name:'%s',parent:'%s')>" % (self.id,self.full_path,self.parent_id)
    
    def _get_full_path(self):
        """Returns a string representation of the full path of this group, starting with the root of the tree. E.G.: All Groups\\Parent Group\\Child Group"""
        if self.parent is None: # pylint: disable=E1101
            return self.name
        
        return self.parent.full_path+"\\"+self.name# pylint: disable=E1101

    full_path = property(_get_full_path,None,None,"Full Path for Group")
    
    def permissions_for_user(self,user):
        """Returns a list of all the permissions a user has on this group"""
        # TODO: This needs to be re-written in a non-recursive fashion using the GroupAncestors table
        permissions = []
        if self.parent is not None:# pylint: disable=E1101
            #Perms flow downards from above so we must evaluate above us
            permissions = self.parent.permissions_for_user(user) # pylint: disable=E1101 
                    
        for user_role_assignment in self.user_role_assignments: # pylint: disable=E1101 
            if user_role_assignment.user == user:
                for permission in user_role_assignment.role.permissions:
                    if permission not in permissions:
                        permissions.append(permission)
        
        for usergroup_role_assignment in self.usergroup_role_assignments: # pylint: disable=E1101 
            if usergroup_role_assignment.usergroup in user.usergroups:
                for permission in usergroup_role_assignment.role.permissions:
                    if permission not in permissions:
                        permissions.append(permission)
        return permissions
    
    def roles_for_user(self,user):
        """Returns a list of all the roles a user has on this group"""
        # TODO: This needs to be re-written in a non-recursive fashion using the GroupAncestors table
        roles = []
        if self.parent is not None: # pylint: disable=E1101 
            #Roles flow downards from above so we must evaluate above us
            roles = self.parent.roles_for_user(user) # pylint: disable=E1101 
                    
        for user_role_assignment in self.user_role_assignments: # pylint: disable=E1101 
            if user_role_assignment.user == user:
                if user_role_assignment.role not in roles:
                    roles.append(user_role_assignment.role)
        
        for usergroup_role_assignment in self.usergroup_role_assignments: # pylint: disable=E1101 
            if usergroup_role_assignment.usergroup in user.usergroups:
                if usergroup_role_assignment.role not in roles:
                    roles.append(usergroup_role_assignment.role)
        return roles    

    def roles_for_users_and_usergroups(self,recursing=False):
        """Returns two lists of roles for this group, a list of roles
        for all users, and a list of roles for all usergroups. The
        items in the lists are dictionaries; the 'role' key contains
        the role object, and the 'inherited' key is a boolean denoting
        whether the role was inherited or assigned directly on the
        group."""
        # TODO: This needs to be re-written in a non-recursive fashion using the GroupAncestors table
        users={}
        usergroups={}
        seen_user_role={}
        seen_usergroup_role={}

        logging.debug("Getting roles for users and usergroups on group {0}, recursing is {1}".format(self,recursing))

        if self.parent: # pylint: disable=E1101 
            #Roles flow downwards
            users,usergroups,seen_user_role,seen_usergroup_role = self.parent.roles_for_users_and_usergroups(True) # pylint: disable=E1101
        
        for user_role_assignment in self.user_role_assignments: # pylint: disable=E1101 
            if user_role_assignment.user not in users:
                users[user_role_assignment.user] = []

            if user_role_assignment.user not in seen_user_role:
                seen_user_role[user_role_assignment.user] = {}
            
            if user_role_assignment.role not in seen_user_role[user_role_assignment.user]:
                users[user_role_assignment.user].append({"inherited":recursing,"role":user_role_assignment.role})
                seen_user_role[user_role_assignment.user][user_role_assignment.role] = True
            elif recursing == False:
                for role_hash in users[user_role_assignment.user]:
                    if role_hash["role"] == user_role_assignment.role:
                        users[user_role_assignment.user].remove(role_hash)
                        users[user_role_assignment.user].append({"inherited":recursing,"role":user_role_assignment.role})
        
        for usergroup_role_assignment in self.usergroup_role_assignments: # pylint: disable=E1101 
            if usergroup_role_assignment.usergroup not in usergroups:
                usergroups[usergroup_role_assignment.usergroup] = []

            if usergroup_role_assignment.usergroup not in seen_usergroup_role:
                seen_usergroup_role[usergroup_role_assignment.usergroup] = {}
            
            if usergroup_role_assignment.role not in seen_usergroup_role[usergroup_role_assignment.usergroup]:
                usergroups[usergroup_role_assignment.usergroup].append({"inherited":recursing,"role":usergroup_role_assignment.role})
                seen_usergroup_role[usergroup_role_assignment.usergroup][usergroup_role_assignment.role] = True
            elif recursing == False:
                for role_hash in usergroups[usergroup_role_assignment.usergroup]:
                    if role_hash["role"] == usergroup_role_assignment.role:
                        usergroups[usergroup_role_assignment.usergroup].remove(role_hash)
                        usergroups[usergroup_role_assignment.usergroup].append({"inherited":recursing,"role":usergroup_role_assignment.role})
        
        if recursing:
            return users,usergroups,seen_user_role,seen_usergroup_role
        else:
            return users,usergroups    
        

class RBACPermission(Base):
    __tablename__ = "t_rbac_permissions"
    __table_args__ = {'schema':conf_pyroles.schema_name}
    
    id = Column(Integer, primary_key=True)
    name = Column(String,nullable=False)
       
    reftype_id = Column(Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_ref_types.id'))
    reftype = relationship(RBACRefType,backref='permissions',order_by=id)
   
    def __init__(self,name,reftype):
        self.name = name
        self.reftype_id = reftype.id
        super(RBACPermission,self).__init__()
        
    def __repr__(self):
        return "<RBACPermission(id:'%s',name:'%s',type:'%s')>" % (self.id,self.name,self.reftype.name)    

    
    
class RBACUserRole(Base):
    __tablename__ = "t_rbac_user_roles"
    __table_args__ = {'schema':conf_pyroles.schema_name}
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_users.id'))
    role_id = Column(Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_roles.id'))
    group_id = Column(Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_groups.id'))
    
    #users = relationship("RBACUser",secondary=rbac_user_roles,backref="roles")
    user = relationship(RBACUser,backref='role_assignments')
    role = relationship(RBACRole,backref='user_role_assignments')
    group = relationship(RBACGroup,backref='user_role_assignments')

            
    def __init__(self,user,role,group):
        self.user_id = user.id
        self.role_id = role.id
        self.group_id = group.id
        super(RBACUserRole,self).__init__()
        
    def __repr__(self):
        return "<RBACUserRoles(id:'%s',user:'%s',role:'%s',group:'%s')>" % (self.id,self.user.name,self.role.name,self.group.name)
    
class RBACUserGroupRole(Base):
    __tablename__ = "t_rbac_usergroup_roles"
    __table_args__ = {'schema':conf_pyroles.schema_name}
    
    id = Column(Integer, primary_key=True)
    usergroup_id = Column(Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_usergroups.id'))
    role_id = Column(Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_roles.id'))
    group_id = Column(Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_groups.id'))
    
    usergroup = relationship(RBACUserGroup,backref='role_assignments')
    role = relationship(RBACRole,backref='usergroup_role_assignments')
    group = relationship(RBACGroup,backref='usergroup_role_assignments')

            
    def __init__(self,usergroup,role,group):
        self.usergroup_id = usergroup.id
        self.role_id = role.id
        self.group_id = group.id
        super(RBACUserGroupRole,self).__init__()
        
    def __repr__(self):
        return "<RBACUserGroupRoles(id:'%s',usergroup:'%s',role:'%s',group:'%s')>" % (self.id,self.usergroup.name,self.role.name,self.group.name)
    
class RBACADGroup(Base):
    
    __tablename__ = "t_rbac_ad_groups"
    __table_args__ = {'schema':conf_pyroles.schema_name}
    
    id = Column(Integer, primary_key=True)
    ad_group_name = Column(String,nullable=False)
    rbac_usergroup_id = Column(Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_usergroups.id'))
    rbac_group_id = Column(Integer,ForeignKey(conf_pyroles.schema_name + '.t_rbac_groups.id'))
    
    def __repr__(self):
        return "<RBACADGroup(id:'%s',ad_group_name:'%s',rbac_group_id:'%s',rbac_usergroup_id:'%s')>" % (self.id,self.ad_group_name,self.rbac_group_id,self.rbac_usergroup_id)    


class GroupAncestor(Base):
    
    __tablename__ = "t_group_ancestors"
    __table_args__ = {'schema':conf_pyroles.schema_name}

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer)
    ancestor_id = Column(Integer)
