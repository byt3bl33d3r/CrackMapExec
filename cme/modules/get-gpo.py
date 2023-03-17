from ldap3 import Server, Connection, SUBTREE

class CMEModule:

    name = 'get-gpo'
    description = 'Retrieves all Group Policy Objects (GPOs) in Active Directory or properties of a specific GPO.'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        GPO             Details information about this GPO 
        """

        self.gpo = None
        if module_options and 'GPO' in module_options:
            self.gpo = module_options['GPO']

    def on_login(self, context, connection):
        """
        """
        server = Server(connection.host)
        conn = Connection(server, user=connection.username, password=connection.password)
        conn.bind()

        base_dn = 'DC=' + ',DC='.join(connection.domain.split('.'))
        search_scope = SUBTREE
        
        if self.gpo:
            context.log.success(f"Searching for GPO '{self.gpo}'")
            search_filter = f'(&(objectCategory=groupPolicyContainer)(displayname={self.gpo}))'
            attributes = ['usncreated', 'displayName', 'gPCMachineExtensionNames', 'whenChanged', 'objectClass', 'gPCFunctionalityVersion', 'showInAdvancedViewOnly', 'usnchanged', 'name', 'flags', 'cn', 'gPCFileSysPath', 'distinguishedName', 'whenCreated', 'versionNumber', 'instanceType', 'objectGUID', 'objectCategory']

        else :        
            context.log.highlight(f"Searching for all GPOs")
            search_filter = '(objectCategory=groupPolicyContainer)'
            attributes = ['name', 'displayName', 'gPCFileSysPath', 'gPCUserExtensionNames', 'gPCMachineExtensionNames']


        conn.search(base_dn, search_filter, search_scope=search_scope, attributes=attributes)

        if not conn.entries:
            if self.gpo:
                context.log.error(f"No GPO found with the name '{self.gpo}'")
            else:
                context.log.error('No GPOs found.')
            return

        for entry in conn.entries:
            if self.gpo:
                context.log.highlight(f'Properties:')
                for attribute in attributes:
                    if attribute in entry:
                        context.log.highlight(f'{attribute}: {entry[attribute].value}')    
            else:
                context.log.success(f'Found GPO: {entry.name.value}')
                context.log.highlight(f'Display Name: {entry.displayName.value}')
                context.log.highlight(f'SysVol Path: {entry.gPCFileSysPath.value}')

                if 'gPCUserExtensionNames' in entry:
                    user_extensions = entry.gPCUserExtensionNames.values
                    if user_extensions:
                        context.log.highlight('User Extensions: {}'.format(', '.join(user_extensions)))

                if 'gPCMachineExtensionNames' in entry:
                    machine_extensions = entry.gPCMachineExtensionNames.values
                    if machine_extensions:
                        context.log.highlight('Machine Extensions: {}'.format(', '.join(machine_extensions)))

        conn.unbind()
