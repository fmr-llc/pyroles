# PyRoles RBAC Model

PyRoles is a python based heirarchical role-based model with inheritance.

## The basic models are:
 
1) Groups, which are a collection of resources for purposes of
determining permissions, and which have a name and a parent. (In
hindsight, we should have called this something else, and called
UserGroups Groups instead, as UserGroups are analogous to unix
groups).
 
2) Reftypes, which determine what kind of object a permission applies
to (e.g., a reftype of "VM" means it applies to VMs, while "Group"
would mean that the permission applies to groups).
 
3) RBAC Permissions, which consist of a reftype and a permission which
is one of "View","Create","Modify","Delete", or "Full Control".
 
4) Roles, which have a set of permissions applied to them, e.g. the
"VM Admin" role has the VM "Full Control" permission applied; a
hypothetical "VM Creator" role which can only create VMs but not
change them afterwards would have the "View" and "Create" VM
permissions applied.
 
5) Users, which have specific roles on specific groups via a UserRole
object which has a user, a role, and the group it applies to. Note
that users do not have permissions directly; they get their
permissions from their roles.
 
6) There are also UserGroups, which are collections of users; a
usergroup can have a role on a group via a UserGroupRole object which
is identical to a UserRole other than having a reference to a
UserGroup rather than a User.
 
7) GroupAncestry, which has a group and an ancestor, and which enables
faster lookups for children or parents of a group (more below).
 
To see if a user has a given permission on a group, there are
helper functions which allow you to get a list of permissions for a
user in a specific group and ask if a user has a specific permission
for that group.
 
Similarly, to find all groups that a user has a specific permission in, there
is a helper function which will return a list of all groups which have
that permission; this is useful when e.g. a user calls the vms index
method in our API, which returns a list of all VMs the user can see no
matter what group that VM is in.
 
One issue with the heirarchical model is that it could be slow,
especially when finding all groups a user has permissions in. To avoid
this, the GroupAncestry table was created. Each group has multiple
entries in it, one entry for each ancestor -- e.g., if group A is the
parent of Group B, and Group B is the parent of Group C, then there
would be two entries in the group ancestry table for group C:
 
Group     Ancestor
Group C   Group A
Group C   Group B
 
This means that finding all the children of group A can be done with a
single call (find all entries in the group ancestry table where
ancestor is group A), rather than having to walk the tree
recursively. Similarly, finding all the ancestors of Group C is a
single call (find all entries in the group ancestry table where
group is Group C), rather than having to walk the tree up to the root;
this is very useful when finding out what permissions a user has on
Group C.
 
One major difference from the way things are done with Keystone is
that we do *not* store permissions in the auth token a user gets back
when authenticating; instead, permissions are evaluated when the user
actually makes a call to the API. This means that we didn't have to
require users to authenticate against a specific group while still
scaling well. I can't find it now, but I think I saw something on the
keystone mailing list indicating you were considering moving to a
similar model?
 
(I should also note that all the relations between models are done via
the object's ID, rather than e.g. the name, which means that if the
name of a group is changed nothing has to be done in terms of
permissions.)

# Contributing

1. Fork the repository on Github
2. Write your change
3. Write tests for your change (if applicable)
4. Run the tests, ensuring they all pass
5. Submit a Pull Request

# License

(c) 2014 Fidelity Investments
Licensed under the Apache License, Version 2.0
