from impacket.ldap import ldap

class CMEModule:
    '''
    Checks whether LDAP signing is required.

    Module by Tobias Neitzel (@qtc_de)
    '''
    name = 'ldap-signing'
    description = 'Check whether LDAP signing is required'
    supported_protocols = ['ldap']
    opsec_safe= True
    multiple_hosts = True 

    def options(self, context, module_options):
        '''
        No options available.
        '''
        pass

    def on_login(self, context, connection):
        '''
        Perform a second logon attempt without LDAP signing.
        '''
        domain = connection.domain
        username = connection.username
        password = connection.password
        ldap_host = connection.conn.getRemoteHost()

        try:
            connection = ldap.LDAPConnection('ldap://{}'.format(ldap_host))
            connection.login(username, password, domain, '', '')
            context.log.highlight('LDAP signing is NOT enforced on {}'.format(ldap_host)) 

        except ldap.LDAPSessionError as e:

            error_msg = str(e)

            if 'strongerAuthRequired' in error_msg:
                context.log.info('LDAP signing is enforced on {}'.format(ldap_host)) 

            else:
                context.log.error("Unexpected LDAP error: '{}'".format(error_msg))

        except Exception as e:
            context.log.error("Unexpected LDAP error: '{}'".format(str(e)))
