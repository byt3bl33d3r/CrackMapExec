#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldap as ldap_impacket
from impacket.krb5.kerberosv5 import KerberosError
from cme.logger import CMEAdapter


ldap_error_status = {
    "1": "STATUS_NOT_SUPPORTED",
    "533": "STATUS_ACCOUNT_DISABLED",
    "701": "STATUS_ACCOUNT_EXPIRED",
    "531": "STATUS_ACCOUNT_RESTRICTION",
    "530": "STATUS_INVALID_LOGON_HOURS",
    "532": "STATUS_PASSWORD_EXPIRED",
    "773": "STATUS_PASSWORD_MUST_CHANGE",
    "775": "USER_ACCOUNT_LOCKED",
    "50": "LDAP_INSUFFICIENT_ACCESS",
    "KDC_ERR_CLIENT_REVOKED": "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_PREAUTH_FAILED": "KDC_ERR_PREAUTH_FAILED"
}


class LDAPConnect:

    def __init__(self, host, port, hostname):
        self.logger = None
        self.proto_logger(host, port, hostname)

    def proto_logger(self, host, port, hostname):
        self.logger = CMEAdapter(
            extra={
                "protocol": "LDAP",
                "host": host,
                "port": port,
                "hostname": hostname
            }
        )

    def kerberos_login(self, domain, username, password='', ntlm_hash='', aesKey='', kdcHost='', useCache=False):
        lmhash = ""
        nthash = ""

        if kdcHost is None:
            kdcHost = domain

        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash and ntlm_hash.find(":") != -1:
            lmhash, nthash = ntlm_hash.split(":")
        elif ntlm_hash:
            nthash = ntlm_hash

        # Create the baseDN
        baseDN = ''
        domainParts = domain.split('.')
        for i in domainParts:
            baseDN += f"dc={i},"
        # Remove last ','
        baseDN = baseDN[:-1]

        try:
            ldapConnection = ldap_impacket.LDAPConnection(f"ldap://{kdcHost}", baseDN)
            ldapConnection.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, kdcHost=kdcHost, useCache=False)
            # Connect to LDAP
            out = f"{domain}{username}:{password if password else ntlm_hash}"
            self.logger.extra["protocol"] = "LDAP"
            self.logger.extra["port"] = "389"
            return ldapConnection
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    ldapConnection = ldap_impacket.LDAPConnection(f"ldaps://{kdcHost}", baseDN)
                    ldapConnection.login(username, password, domain, lmhash, nthash, aesKey, kdcHost=kdcHost, useCache=False)
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    # self.logger.success(out)
                    return ldapConnection
                except ldap_impacket.LDAPSessionError as e:
                    errorCode = str(e).split()[-2][:-1]
                    self.logger.error(
                        f"{domain}\\{username}:{password if password else ntlm_hash} {ldap_error_status[errorCode] if errorCode in ldap_error_status else ''}",
                        color="magenta" if errorCode in ldap_error_status else "red"
                    )
            else:
                errorCode = str(e).split()[-2][:-1]
                self.logger.error(
                    f"{domain}\\{username}:{password if password else ntlm_hash} {ldap_error_status[errorCode] if errorCode in ldap_error_status else ''}",
                    color="magenta" if errorCode in ldap_error_status else "red"
                )
            return False

        except OSError as e:
            self.logger.debug(
                f"{domain}\\{username}:{password if password else ntlm_hash} {'Error connecting to the domain, please add option --kdcHost with the FQDN of the domain controller'}"
            )
            return False
        except KerberosError as e:
            self.logger.error(
                f"{domain}\\{username}:{password if password else ntlm_hash} {str(e)}",
                color="red"
            )
            return False

    def plaintext_login(self, domain, username, password, ntlm_hash):
        lmhash = ""
        nthash = ""

        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash and ntlm_hash.find(":") != -1:
            lmhash, nthash = ntlm_hash.split(":")
        elif ntlm_hash:
            nthash = ntlm_hash

        # Create the baseDN
        baseDN = ''
        domainParts = domain.split(".")
        for i in domainParts:
            baseDN += f"dc={i},"
        # Remove last ','
        baseDN = baseDN[:-1]

        try:
            ldapConnection = ldap_impacket.LDAPConnection(f"ldap://{domain}", baseDN, domain)
            ldapConnection.login(username, password, domain, lmhash, nthash)

            # Connect to LDAP
            out = u"{domain}\\{username}:{password if password else ntlm_hash}"
            self.logger.extra["protocol"] = "LDAP"
            self.logger.extra["port"] = "389"
            # self.logger.success(out)

            return ldapConnection

        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    ldapConnection = ldap_impacket.LDAPConnection(f"ldaps://{domain}", baseDN, domain)
                    ldapConnection.login(username, password, domain, lmhash, nthash)
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    # self.logger.success(out)
                    return ldapConnection
                except ldap_impacket.LDAPSessionError as e:
                    errorCode = str(e).split()[-2][:-1]
                    self.logger.error(
                        f"{domain}\\{username}:{password if password else ntlm_hash} {ldap_error_status[errorCode] if errorCode in ldap_error_status else ''}",
                        color="magenta" if errorCode in ldap_error_status else "red"
                    )
            else:
                errorCode = str(e).split()[-2][:-1]
                self.logger.error(
                    f"{domain}\\{username}:{password if password else ntlm_hash} {ldap_error_status[errorCode] if errorCode in ldap_error_status else ''}",
                    color="magenta" if errorCode in ldap_error_status else "red"
                )
            return False

        except OSError as e:
            self.logger.debug(
                f"{domain}\\{username}:{password if password else ntlm_hash} {'Error connecting to the domain, please add option --kdcHost with the FQDN of the domain controller'}"
            )
            return False

