from ldap3 import Server, Connection, NTLM, ALL

class CMEModule:
    '''
        Basic enumeration of provided user information and privileges 
        Module by spyr0 (@spyr0-sec)
    '''
    name = 'whoami'
    description = 'Get details of provided user'
    supported_protocols = ['ldap']
    opsec_safe = True #Does the module touch disk?
    multiple_hosts = True # Does it make sense to run this module on multiple hosts at a time?

    def options(self, context, module_options):
        '''
            USER  Enumerate information about a different SamAccountName
        '''
        self.username = None
        if 'USER' in module_options:
                self.username = module_options['USER']

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

            if self.username is None:
                searchFilter = f'(sAMAccountName={connection.username})'
            else:
                searchFilter = f'(sAMAccountName={format(self.username)})'
                
            context.log.debug(f'Using naming context: {searchBase} and {searchFilter} as search filter')

            # Confirm login / get username
            context.log.debug(f'Running LDAP queries as: {ldapConn.extend.standard.who_am_i().replace("u:","")}')

            # Get attributes of provided user
            ldapConn.search(search_base=searchBase,search_filter=searchFilter,
            attributes=['name','sAmAccountName','description','distinguishedName','pwdLastSet','logonCount','lastLogon','userAccountControl','servicePrincipalName','memberOf'])      

            for response in ldapConn.response:
                context.log.highlight(f"Human name: {response['attributes']['name']}")
                context.log.highlight(f"Username: {response['attributes']['sAmAccountName']}")
                context.log.highlight(f"Description: {response['attributes']['description']}")
                context.log.highlight(f"Distinguished name: {response['attributes']['distinguishedName']}")
                context.log.highlight(f"Password last set: {response['attributes']['pwdLastSet']}")
                context.log.highlight(f"Logon count: {response['attributes']['logonCount']}")

                if '1601' in str(response['attributes']['lastLogon']):
                    context.log.highlight(f"Last logon: Never")
                else:
                    context.log.highlight(f"Last logon: {response['attributes']['lastLogon']}")

                if response['attributes']['userAccountControl'] == 512:
                    context.log.highlight(f"Enabled: Yes")
                    context.log.highlight(f"Password Never Expires: No")
                if response['attributes']['userAccountControl'] == 514:
                    context.log.highlight(f"Enabled: No")
                    context.log.highlight(f"Password Never Expires: No")                    
                if response['attributes']['userAccountControl'] == 66048:
                    context.log.highlight(f"Enabled: Yes")
                    context.log.highlight(f"Password Never Expires: Yes")
                if response['attributes']['userAccountControl'] == 66050:
                    context.log.highlight(f"Enabled: No")
                    context.log.highlight(f"Password Never Expires: Yes")

                if len(response['attributes']['servicePrincipalName']) != 0:
                    context.log.highlight(f"Service Account Name(s) found - Potentially Kerberoastable user!")
                    for spn in response['attributes']['servicePrincipalName']:
                        context.log.highlight(f"Service Account Name: {spn}")
                              
                for group in response['attributes']['memberOf']:
                    context.log.highlight(f'Member of: {group}')

                # Only want output from first response
                break
        
        except KeyError:
            context.log.error(f'Username does not exist')

        except Exception as e:
            context.log.error(f'UNEXPECTED ERROR: {repr(e)}')
