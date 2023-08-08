#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import ssl
import asyncio

from msldap.connection import MSLDAPClientConnection
from msldap.commons.target import MSLDAPTarget

from asyauth.common.constants import asyauthSecret
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential

from asysocks.unicomm.common.target import UniTarget, UniProto

class CMEModule:
    """
    Checks whether LDAP signing and channelbinding are required.

    Module by LuemmelSec (@theluemmel), updated by @zblurx
    Original work thankfully taken from @zyn3rgy's Ldap Relay Scan project: https://github.com/zyn3rgy/LdapRelayScan
    """

    name = "ldap-checker"
    description = "Checks whether LDAP signing and binding are required and / or enforced"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        No options available.
        """
        pass

    def on_login(self, context, connection):
        # Conduct a bind to LDAPS and determine if channel
        # binding is enforced based on the contents of potential
        # errors returned. This can be determined unauthenticated,
        # because the error indicating channel binding enforcement
        # will be returned regardless of a successful LDAPS bind.
        async def run_ldaps_noEPA(target, credential):
            ldapsClientConn = MSLDAPClientConnection(target, credential)
            _, err = await ldapsClientConn.connect()
            if err is not None:
                context.log.fail("ERROR while connecting to " + str(connection.domain) + ": " + str(err))
                exit()
            _, err = await ldapsClientConn.bind()
            if "data 80090346" in str(err):
                return True  # channel binding IS enforced
            elif "data 52e" in str(err):
                return False  # channel binding not enforced
            elif err is None:
                # LDAPS bind successful
                # because channel binding is not enforced
                return False

        # Conduct a bind to LDAPS with channel binding supported
        # but intentionally miscalculated. In the case that and
        # LDAPS bind has without channel binding supported has occured,
        # you can determine whether the policy is set to "never" or
        # if it's set to "when supported" based on the potential
        # error recieved from the bind attempt.
        async def run_ldaps_withEPA(target, credential):
            ldapsClientConn = MSLDAPClientConnection(target, credential)
            _, err = await ldapsClientConn.connect()
            if err is not None:
                context.log.fail("ERROR while connecting to " + str(connection.domain) + ": " + str(err))
                exit()
            # forcing a miscalculation of the "Channel Bindings" av pair in Type 3 NTLM message
            ldapsClientConn.cb_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            _, err = await ldapsClientConn.bind()
            if "data 80090346" in str(err):
                return True
            elif "data 52e" in str(err):
                return False
            elif err is not None:
                context.log.fail("ERROR while connecting to " + str(connection.domain) + ": " + str(err))
            elif err is None:
                return False

        # Domain Controllers do not have a certificate setup for
        # LDAPS on port 636 by default. If this has not been setup,
        # the TLS handshake will hang and you will not be able to
        # interact with LDAPS. The condition for the certificate
        # existing as it should is either an error regarding
        # the fact that the certificate is self-signed, or
        # no error at all. Any other "successful" edge cases
        # not yet accounted for.
        def DoesLdapsCompleteHandshake(dcIp):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            ssl_sock = ssl.wrap_socket(
                s,
                cert_reqs=ssl.CERT_OPTIONAL,
                suppress_ragged_eofs=False,
                do_handshake_on_connect=False,
            )
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
                    context.log.fail("Unexpected error during LDAPS handshake: " + str(e))
                    ssl_sock.close()
                    return False

        # Conduct and LDAP bind and determine if server signing
        # requirements are enforced based on potential errors
        # during the bind attempt.
        async def run_ldap(target, credential):
            ldapsClientConn = MSLDAPClientConnection(target, credential)
            _, err = await ldapsClientConn.connect()
            if err is None:
                _, err = await ldapsClientConn.bind()
                if "stronger" in str(err):
                    return True  # because LDAP server signing requirements ARE enforced
                elif ("data 52e" or "data 532") in str(err):
                    context.log.fail("Not connected... exiting")
                    exit()
                elif err is None:
                    return False
            else:
                context.log.fail(str(err))

        # Run trough all our code blocks to determine LDAP signing and channel binding settings.   
        stype = asyauthSecret.PASS if not connection.nthash else asyauthSecret.NT
        secret = connection.password if not connection.nthash else connection.nthash
        if not connection.kerberos:
            credential = NTLMCredential(
                secret=secret,
                username=connection.username,
                domain=connection.domain,
                stype=stype,
            )
        else:
            kerberos_target = UniTarget(
                connection.hostname + '.' + connection.domain,
                88,
                UniProto.CLIENT_TCP,
                proxies=None,
                dns=None,
                dc_ip=connection.domain,
                domain=connection.domain
            )
            credential = KerberosCredential(
                target=kerberos_target,
                secret=secret,
                username=connection.username,
                domain=connection.domain,
                stype=stype,
            )

        target = MSLDAPTarget(connection.host, hostname=connection.hostname, domain=connection.domain, dc_ip=connection.domain)
        ldapIsProtected = asyncio.run(run_ldap(target, credential))

        if ldapIsProtected == False:
            context.log.highlight("LDAP Signing NOT Enforced!")
        elif ldapIsProtected == True:
            context.log.fail("LDAP Signing IS Enforced")
        else:
            context.log.fail("Connection fail, exiting now")
            exit()

        if DoesLdapsCompleteHandshake(connection.host) == True:
            target = MSLDAPTarget(connection.host, 636, UniProto.CLIENT_SSL_TCP, hostname=connection.hostname, domain=connection.domain, dc_ip=connection.domain)
            ldapsChannelBindingAlwaysCheck = asyncio.run(run_ldaps_noEPA(target, credential))
            target = MSLDAPTarget(connection.host, hostname=connection.hostname, domain=connection.domain, dc_ip=connection.domain)
            ldapsChannelBindingWhenSupportedCheck = asyncio.run(run_ldaps_withEPA(target, credential))
            if ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == True:
                context.log.highlight('LDAPS Channel Binding is set to "When Supported"')
            elif ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == False:
                context.log.highlight('LDAPS Channel Binding is set to "NEVER"')
            elif ldapsChannelBindingAlwaysCheck == True:
                context.log.fail('LDAPS Channel Binding is set to "Required"')
            else:
                context.log.fail("\nSomething went wrong...")
                exit()
        else:
            context.log.fail(connection.domain + " - cannot complete TLS handshake, cert likely not configured")
