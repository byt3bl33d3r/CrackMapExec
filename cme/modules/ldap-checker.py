#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ldap3
import ssl
import asyncio
from msldap.connection import MSLDAPClientConnection
from msldap.commons.factory import LDAPConnectionFactory

class CMEModule:
    '''
    Checks whether LDAP signing and channelbinding are required.

    Module by LuemmelSec (@theluemmel)
    Original work thankfully taken from @zyn3rgy's Ldap Relay Scan project: https://github.com/zyn3rgy/LdapRelayScan
    '''
    name = 'ldap-checker'
    description = 'Checks whether LDAP signing and binding are required and / or enforced'
    supported_protocols = ['ldap']
    opsec_safe= True
    multiple_hosts = True 

    def options(self, context, module_options):
        '''
        No options available.
        '''
        pass

    def on_login(self, context, connection):
        
        #Grab the variables from the CME connection to fill our variables
        
        inputUser = connection.domain + '\\' + connection.username
        inputPassword = connection.password
        dcTarget = connection.conn.getRemoteHost()
        
        #Conduct a bind to LDAPS and determine if channel
        #binding is enforced based on the contents of potential
        #errors returned. This can be determined unauthenticated,
        #because the error indicating channel binding enforcement
        #will be returned regardless of a successful LDAPS bind.
        def run_ldaps_noEPA(inputUser, inputPassword, dcTarget):
            try:
                tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
                ldapServer = ldap3.Server(
                    dcTarget, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
                ldapConn = ldap3.Connection(
                    ldapServer, user=inputUser, password=inputPassword, authentication=ldap3.NTLM)
                if not ldapConn.bind():
                    if "data 80090346" in str(ldapConn.result):
                        return True #channel binding IS enforced
                    elif "data 52e" in str(ldapConn.result):
                        return False #channel binding not enforced
                    else:
                        context.log.error("UNEXPECTED ERROR: " + str(ldapConn.result))
                else:
                    #LDAPS bind successful
                    return False #because channel binding is not enforced
                    exit()
            except Exception as e:
                context.log.error("\n   [!] "+ dcTarget+" -", str(e))
                context.log.error("        * Ensure DNS is resolving properly, and that you can reach LDAPS on this host")

        #Conduct a bind to LDAPS with channel binding supported
        #but intentionally miscalculated. In the case that and
        #LDAPS bind has without channel binding supported has occured,
        #you can determine whether the policy is set to "never" or
        #if it's set to "when supported" based on the potential
        #error recieved from the bind attempt.
        async def run_ldaps_withEPA(inputUser, inputPassword, dcTarget):
            try:
                url = 'ldaps+ntlm-password://'+inputUser + ':' + inputPassword +'@' + dcTarget
                conn_url = LDAPConnectionFactory.from_url(url)
                ldaps_client = conn_url.get_client()
                ldapsClientConn = MSLDAPClientConnection(ldaps_client.target, ldaps_client.creds)
                _, err = await ldapsClientConn.connect()
                if err is not None:
                    context.log.error("ERROR while connecting to " + dcTarget + ": " + err)
                #forcing a miscalculation of the "Channel Bindings" av pair in Type 3 NTLM message
                ldapsClientConn.cb_data = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                _, err = await ldapsClientConn.bind()
                if "data 80090346" in str(err):
                    return True
                elif "data 52e" in str(err):
                    return False
                elif err is not None:
                    context.log.error("ERROR while connecting to " + dcTarget + ": " + err)
                elif err is None:
                    return False
            except Exception as e:
                context.log.error("something went wrong during ldaps_withEPA bind:" + str(e))

        #Domain Controllers do not have a certificate setup for
        #LDAPS on port 636 by default. If this has not been setup,
        #the TLS handshake will hang and you will not be able to 
        #interact with LDAPS. The condition for the certificate
        #existing as it should is either an error regarding 
        #the fact that the certificate is self-signed, or
        #no error at all. Any other "successful" edge cases
        #not yet accounted for.
        def DoesLdapsCompleteHandshake(dcIp):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            ssl_sock = ssl.wrap_socket(s,cert_reqs=ssl.CERT_OPTIONAL,suppress_ragged_eofs=False,do_handshake_on_connect=False)
            ssl_sock.connect((dcIp, 636))
            try:
                ssl_sock.do_handshake()
                ssl_sock.close()
                return True
            except Exception as e:
                if "CERTIFICATE_VERIFY_FAILED" in str(e):
                    ssl_sock.close()
                    return True
                if "handshake operation timed out" in str(e):
                    ssl_sock.close()
                    return False
                else:
                    context.log.error("Unexpected error during LDAPS handshake: " + str(e))
                    ssl_sock.close()
                    return False


        #Conduct and LDAP bind and determine if server signing
        #requirements are enforced based on potential errors
        #during the bind attempt. 
        def run_ldap(inputUser, inputPassword, dcTarget):
            ldapServer = ldap3.Server(
                dcTarget, use_ssl=False, port=389, get_info=ldap3.ALL)
            ldapConn = ldap3.Connection(
                ldapServer, user=inputUser, password=inputPassword, authentication=ldap3.NTLM)
            if not ldapConn.bind():
                if "stronger" in str(ldapConn.result):
                    return True #because LDAP server signing requirements ARE enforced
                elif "data 52e" or "data 532" in str(ldapConn.result):
                    context.log.error("[!!!] invalid credentials - aborting to prevent unnecessary authentication")
                    exit()
                else:
                    context.log.error("UNEXPECTED ERROR: " + str(ldapConn.result))
            else:
                #LDAPS bind successful
                return False #because LDAP server signing requirements are not enforced
                exit()

        #Run trough all our code blocks to determine LDAP signing and channel binding settings.
        try:
            
            ldapIsProtected = run_ldap(inputUser, inputPassword, dcTarget)
            
            if ldapIsProtected == False:
                context.log.highlight("LDAP Signing NOT Enforced!")
            elif ldapIsProtected == True:
                context.log.error("LDAP Signing IS Enforced")
            if DoesLdapsCompleteHandshake(dcTarget) == True:
                ldapsChannelBindingAlwaysCheck = run_ldaps_noEPA(inputUser, inputPassword, dcTarget)
                ldapsChannelBindingWhenSupportedCheck = asyncio.run(run_ldaps_withEPA(inputUser, inputPassword, dcTarget))
                if ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == True:
                    context.log.highlight('Channel Binding is set to \"when supported\" - Success of Attacks depends on client settings')
                elif ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == False:
                    context.log.highlight('Channel Binding is set to \"NEVER\" - Time to PWN!')
                elif ldapsChannelBindingAlwaysCheck == True:
                    context.log.error('Channel Binding is set to \"Required\" - Meeeehhhh :(')
                else:
                    context.log.error("\nSomething went wrong...")
                    exit()          
            else:
                context.log.error(dcTarget + " - cannot complete TLS handshake, cert likely not configured")
        except Exception as e:
            context.log.error("ERROR: " + str(e))