
class AccessList():
    def __init__(self,pyroles,user,access_list):
        self._pyroles = pyroles
        self._user = user
        self.access_list = access_list
        
    def has(self,reftype_name,permission_name):
        
        for access_item in self.access_list:
            perm = access_item[0]
            if perm.name == permission_name and perm.reftype.name == reftype_name:
                return True
        return False
    
    def groups_with_permission(self,reftype_name,permission_name):
        groups = []
        for access_item in self.access_list:
            perm = access_item[0]
            group = access_item[1]
            if perm.name == permission_name and perm.reftype.name == reftype_name:
                groups.append(group)
                
        
        #Now that we've built the basic group tree we must proceed DOWNWARD for each group since permissions travel down
        list_changed = True
        while list_changed == True:
            list_changed = False
            for group in groups:
                for child in group.children:
                    if child not in groups:
                        groups.append(child)
                        list_changed = True 
        
        return groups
    
    def _permissions(self):
        perms = []
        for access_item in self.access_list:
            perm = access_item[0]
            if perm not in perms:
                perms.append(perm)
        return perms
        
    permissions = property(_permissions,None,None,None)