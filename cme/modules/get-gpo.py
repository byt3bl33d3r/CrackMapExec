from ldap3 import Server, Connection
from datetime import datetime
import uuid

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

        base_dn = 'DC=' + ',DC='.join(connection.domain.split('.'))
        
        if self.gpo:
            context.log.success(f"Searching for GPO '{self.gpo}'")
            search_filter = f'(&(objectCategory=groupPolicyContainer)(displayname={self.gpo}))'
            attributes = ['usncreated', 'displayName', 'gPCMachineExtensionNames', 'whenChanged', 'objectClass', 'gPCFunctionalityVersion', 'showInAdvancedViewOnly', 'usnchanged', 'name', 'flags', 'cn', 'gPCFileSysPath', 'distinguishedName', 'whenCreated', 'versionNumber', 'instanceType', 'objectCategory']

        else :        
            context.log.success(f"Searching for all GPOs")
            search_filter = '(objectCategory=groupPolicyContainer)'
            attributes = ['name', 'displayName', 'gPCFileSysPath']

        results = connection.search(search_filter, attributes, 10000)
        results = [r for r in results if isinstance(r, ldapasn1_impacket.SearchResultEntry)]
            
        if results :
            for gpo in results:
                gpo_values = {str(attr['type']).lower(): str(attr['vals'][0]) for attr in gpo['attributes']}
                context.log.success("GPO Found: " +gpo_values['displayname'])
                for attribute, value in gpo_values.items():
                    context.log.highlight(f"{attribute}: {value}")
        else :
            if self.gpo:
                context.log.error(f"No GPO found with the name '{self.gpo}'")
            else:
                context.log.error('No GPOs found.')
            return