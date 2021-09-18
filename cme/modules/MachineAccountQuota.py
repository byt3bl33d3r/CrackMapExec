from impacket.ldap import ldapasn1 as ldapasn1_impacket


class CMEModule:
    '''
      Module by Shutdown and Podalirius

      Initial module:
        https://github.com/ShutdownRepo/CrackMapExec-MachineAccountQuota

      Authors:
        Shutdown: @_nwodtuhs
        Podalirius: @podalirius_
    '''

    def options(self, context, module_options):
        pass

    name = 'MAQ'
    description = 'Retrieves the MachineAccountQuota domain-level attribute'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False

    def on_login(self, context, connection):
        result = []
        context.log.info('Getting the MachineAccountQuota')
        searchFilter = '(objectClass=*)'
        attributes = ['ms-DS-MachineAccountQuota']
        result = connection.search(searchFilter, attributes, 1)
        for item in result:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            context.log.highlight("MachineAccountQuota: %d" % item['attributes'][0]['vals'][0])
