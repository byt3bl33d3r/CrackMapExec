from ldap3 import Server, Connection, NTLM, ALL

class CMEModule:
    '''
        Sanity check of current user groups and privileges 
        Module by spyr0 (@spyr0-sec)
    '''
    name = 'whoami'
    description = 'Get privileges of provided user'
    supported_protocols = ['ldap']
    opsec_safe = True #Does the module touch disk?
    multiple_hosts = True # Does it make sense to run this module on multiple hosts at a time?

    def options(self, context, module_options):
        '''
            No options required
        '''
        pass

    def on_login(self, context, connection):

        # Grab the variables from the CME connection to fill our variables
        inputUser = connection.domain + '\\' + connection.username
        inputPassword = connection.password
        dcTarget = connection.conn.getRemoteHost()

        try:
            # Connect and bind to the LDAP server
            ldapServer = Server(dcTarget, use_ssl=False, port=389, get_info=ALL)
            ldapConn = Connection(ldapServer, user=inputUser, password=inputPassword, authentication=NTLM, auto_bind=True)

            # https://github.com/pycontribs/python3-ldap/blob/master/python3-ldap/ldap3/protocol/rfc4512.py
            searchBase = ldapServer.info.naming_contexts[0]
            searchFilter = f'(sAMAccountName={connection.username})'

            context.log.debug(f'Using naming context: {searchBase} and {searchFilter} as search filter')

            # Confirm login / get username
            context.log.highlight(f'Username: {ldapConn.extend.standard.who_am_i().replace("u:","")}')

            # Get attributes of provided user
            ldapConn.search(search_base=searchBase,search_filter=searchFilter,attributes=['description','distinguishedName', 'memberOf', 'name', 'pwdLastSet'])      

            for response in ldapConn.response:
                context.log.highlight(f"Distinguished name: {response['attributes']['distinguishedName']}")
                context.log.highlight(f"Human name: {response['attributes']['name']}")
                context.log.highlight(f"Description: {response['attributes']['description'][0]}")
                context.log.highlight(f"Password last set: {response['attributes']['pwdLastSet']}")

                for group in response['attributes']['memberOf']:
                    context.log.highlight(f'Member of: {group}')

                # Only want output from first response
                break
        
        except Exception as e:
            context.log.error(f'UNEXPECTED ERROR: {e}')