#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import os
from io import StringIO

from cme.config import process_secret
from cme.protocols.mssql.mssqlexec import MSSQLEXEC
from cme.connection import *
from cme.helpers.logger import highlight
from cme.helpers.bloodhound import add_user_bh
from cme.helpers.powershell import create_ps_command
from impacket import tds
from impacket.krb5.ccache import CCache
from impacket.smbconnection import SMBConnection, SessionError
from impacket.tds import (
    SQLErrorException,
    TDS_LOGINACK_TOKEN,
    TDS_ERROR_TOKEN,
    TDS_ENVCHANGE_TOKEN,
    TDS_INFO_TOKEN,
    TDS_ENVCHANGE_VARCHAR,
    TDS_ENVCHANGE_DATABASE,
    TDS_ENVCHANGE_LANGUAGE,
    TDS_ENVCHANGE_CHARSET,
    TDS_ENVCHANGE_PACKETSIZE,
)


class mssql(connection):
    def __init__(self, args, db, host):
        self.mssql_instances = None
        self.domain = None
        self.server_os = None
        self.hash = None
        self.os_arch = None
        self.nthash = ""

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        mssql_parser = parser.add_parser("mssql", help="own stuff using MSSQL", parents=[std_parser, module_parser])
        dgroup = mssql_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, help="domain name")
        dgroup.add_argument(
            "--local-auth",
            action="store_true",
            help="authenticate locally to each target",
        )
        mssql_parser.add_argument(
            "-H",
            "--hash",
            metavar="HASH",
            dest="hash",
            nargs="+",
            default=[],
            help="NTLM hash(es) or file(s) containing NTLM hashes",
        )
        mssql_parser.add_argument(
            "--port",
            default=1433,
            type=int,
            metavar="PORT",
            help="MSSQL port (default: 1433)",
        )
        mssql_parser.add_argument(
            "-q",
            "--query",
            dest="mssql_query",
            metavar="QUERY",
            type=str,
            help="execute the specified query against the MSSQL DB",
        )
        mssql_parser.add_argument(
            "--no-bruteforce",
            action="store_true",
            help="No spray when using file for username and password (user1 => password1, user2 => password2",
        )
        mssql_parser.add_argument(
            "--continue-on-success",
            action="store_true",
            help="continues authentication attempts even after successes",
        )

        cgroup = mssql_parser.add_argument_group("Command Execution", "options for executing commands")
        cgroup.add_argument(
            "--force-ps32",
            action="store_true",
            help="force the PowerShell command to run in a 32-bit process",
        )
        cgroup.add_argument("--no-output", action="store_true", help="do not retrieve command output")
        xgroup = cgroup.add_mutually_exclusive_group()
        xgroup.add_argument(
            "-x",
            metavar="COMMAND",
            dest="execute",
            help="execute the specified command",
        )
        xgroup.add_argument(
            "-X",
            metavar="PS_COMMAND",
            dest="ps_execute",
            help="execute the specified PowerShell command",
        )

        psgroup = mssql_parser.add_argument_group("Powershell Obfuscation", "Options for PowerShell script obfuscation")
        psgroup.add_argument("--obfs", action="store_true", help="Obfuscate PowerShell scripts")
        psgroup.add_argument(
            "--clear-obfscripts",
            action="store_true",
            help="Clear all cached obfuscated PowerShell scripts",
        )

        tgroup = mssql_parser.add_argument_group("Files", "Options for put and get remote files")
        tgroup.add_argument(
            "--put-file",
            nargs=2,
            metavar="FILE",
            help="Put a local file into remote target, ex: whoami.txt C:\\Windows\\Temp\\whoami.txt",
        )
        tgroup.add_argument(
            "--get-file",
            nargs=2,
            metavar="FILE",
            help="Get a remote file, ex: C:\\Windows\\Temp\\whoami.txt whoami.txt",
        )

        return parser

    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            self.enum_host_info()
            self.print_host_info()
            self.login()
            if hasattr(self.args, "module") and self.args.module:
                self.call_modules()
            else:
                self.call_cmd_args()

    def proto_logger(self):
        self.logger = CMEAdapter(
            extra={
                "protocol": "MSSQL",
                "host": self.host,
                "port": self.args.port,
                "hostname": "None",
            }
        )

    def enum_host_info(self):
        # this try pass breaks module http server, more info https://github.com/byt3bl33d3r/CrackMapExec/issues/363
        try:
            # Probably a better way of doing this, grab our IP from the socket
            self.local_ip = str(self.conn.socket).split()[2].split("=")[1].split(":")[0]
        except:
            pass

        if self.args.domain:
            self.domain = self.args.domain
        else:
            try:
                smb_conn = SMBConnection(self.host, self.host, None)
                try:
                    smb_conn.login("", "")
                except SessionError as e:
                    if "STATUS_ACCESS_DENIED" in e.getErrorString():
                        pass

                self.domain = smb_conn.getServerDNSDomainName()
                self.hostname = smb_conn.getServerName()
                self.server_os = smb_conn.getServerOS()
                self.logger.extra["hostname"] = self.hostname

                try:
                    smb_conn.logoff()
                except:
                    pass

                if self.args.domain:
                    self.domain = self.args.domain

                if self.args.local_auth:
                    self.domain = self.hostname
            except Exception as e:
                self.logger.fail(f"Error retrieving host domain: {e} specify one manually with the '-d' flag")

        self.mssql_instances = self.conn.getInstances(0)
        self.db.add_host(
            self.host,
            self.hostname,
            self.domain,
            self.server_os,
            len(self.mssql_instances),
        )

        try:
            self.conn.disconnect()
        except:
            pass

    def print_host_info(self):
        self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.domain})")
        # if len(self.mssql_instances) > 0:
        #     self.logger.display("MSSQL DB Instances: {}".format(len(self.mssql_instances)))
        #     for i, instance in enumerate(self.mssql_instances):
        #         self.logger.debug("Instance {}".format(i))
        #         for key in instance.keys():
        #             self.logger.debug(key + ":" + instance[key])

    def create_conn_obj(self):
        try:
            self.conn = tds.MSSQL(self.host, self.args.port)
            self.conn.connect()
        except socket.error:
            return False

        return True

    def check_if_admin(self):
        try:
            results = self.conn.sql_query("SELECT IS_SRVROLEMEMBER('sysadmin')")
            is_admin = int(results[0][""])
        except Exception as e:
            self.logger.fail(f"Error querying for sysadmin role: {e}")
            return False

        if is_admin:
            self.admin_privs = True
            self.logger.debug(f"User is admin")
        else:
            return False
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
        try:
            self.conn.disconnect()
        except:
            pass
        self.create_conn_obj()
        logging.getLogger("impacket").disabled = True

        nthash = ""
        hashes = None
        if ntlm_hash != "":
            if ntlm_hash.find(":") != -1:
                hashes = ntlm_hash
                nthash = ntlm_hash.split(":")[1]
            else:
                # only nt hash
                hashes = f":{ntlm_hash}"
                nthash = ntlm_hash

        if not all("" == s for s in [self.nthash, password, aesKey]):
            kerb_pass = next(s for s in [self.nthash, password, aesKey] if s)
        else:
            kerb_pass = ""
        try:
            res = self.conn.kerberosLogin(
                None,
                username,
                password,
                domain,
                hashes,
                aesKey,
                kdcHost=kdcHost,
                useCache=useCache,
            )
            if res is not True:
                self.conn.printReplies()
                return False

            self.password = password
            if username == "" and useCache:
                ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
                principal = ccache.principal.toPrincipal()
                self.username = principal.components[0]
                username = principal.components[0]
            else:
                self.username = username
            self.domain = domain
            self.check_if_admin()

            out = "{}{}{} {}".format(
                f"{domain}\\" if not self.args.local_auth else "",
                username,
                # Show what was used between cleartext, nthash, aesKey and ccache
                " from ccache" if useCache else ":%s" % (kerb_pass if not self.config.get("CME", "audit_mode") else self.config.get("CME", "audit_mode") * 8),
                highlight(f'({self.config.get("CME", "pwn3d_label")})' if self.admin_privs else ""),
            )
            self.logger.success(out)
            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True
        except Exception as e:
            self.logger.fail(
                "{}\\{}{} {}".format(
                    f"{domain}\\" if not self.args.local_auth else "",
                    username,
                    " from ccache" if useCache else f":{kerb_pass if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode') * 8}",
                    e,
                )
            )
            return False

    def plaintext_login(self, domain, username, password):
        try:
            self.conn.disconnect()
        except:
            pass
        self.create_conn_obj()

        try:
            # this is to prevent a decoding issue in impacket/ntlm.py:617 where it attempts to decode the domain
            if not domain:
                domain = ""
            res = self.conn.login(None, username, password, domain, None, not self.args.local_auth)
            if res is not True:
                self.conn.printReplies()
                return False

            self.password = password
            self.username = username
            self.domain = domain
            self.check_if_admin()
            self.db.add_credential("plaintext", domain, username, password)

            if self.admin_privs:
                self.db.add_admin_user("plaintext", domain, username, password, self.host)

            out = "{}{}:{} {}".format(
                f"{domain}\\" if not self.args.local_auth else "",
                username,
                process_secret(password),
                highlight(f'({self.config.get("CME", "pwn3d_label")})' if self.admin_privs else ""),
            )
            self.logger.success(out)
            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True
        except BrokenPipeError as e:
            self.logger.fail(f"Broken Pipe Error while attempting to login")
        except Exception as e:
            self.logger.fail(f"{domain}\\{username}:{process_secret(password)}")
            self.logger.exception(e)
            return False

    def hash_login(self, domain, username, ntlm_hash):
        lmhash = ""
        nthash = ""

        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(":") != -1:
            lmhash, nthash = ntlm_hash.split(":")
        else:
            nthash = ntlm_hash

        try:
            self.conn.disconnect()
        except:
            pass
        self.create_conn_obj()

        try:
            res = self.conn.login(
                None,
                username,
                "",
                domain,
                ":" + nthash if not lmhash else ntlm_hash,
                not self.args.local_auth,
            )
            if res is not True:
                self.conn.printReplies()
                return False

            self.hash = ntlm_hash
            self.username = username
            self.domain = domain
            self.check_if_admin()
            self.db.add_credential("hash", domain, username, ntlm_hash)

            if self.admin_privs:
                self.db.add_admin_user("hash", domain, username, ntlm_hash, self.host)

            out = "{}\\{} {} {}".format(
                domain,
                username,
                process_secret(ntlm_hash),
                highlight(f'({self.config.get("CME", "pwn3d_label")})' if self.admin_privs else ""),
            )
            self.logger.success(out)
            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True
        except BrokenPipeError as e:
            self.logger.fail(f"Broken Pipe Error while attempting to login")
        except Exception as e:
            self.logger.fail(f"{domain}\\{username}:{process_secret(ntlm_hash)} {e}")
            return False

    def mssql_query(self):
        result = self.conn.sql_query(self.args.mssql_query)
        self.logger.debug(f"SQL Query Result: {result}")
        for line in StringIO(self.conn._MSSQL__rowsPrinter.getMessage()).readlines():
            if line.strip() != "":
                self.logger.highlight(line.strip())
        return self.conn._MSSQL__rowsPrinter.getMessage()

    @requires_admin
    def execute(self, payload=None, print_output=False):
        if not payload and self.args.execute:
            payload = self.args.execute

        self.logger.info(f"Command to execute:\n{payload}")
        try:
            exec_method = MSSQLEXEC(self.conn)
            raw_output = exec_method.execute(payload, print_output)
            self.logger.info("Executed command via mssqlexec")
            self.logger.debug(f"Raw output: {raw_output}")
        except Exception as e:
            self.logger.exception(e)
            return None

        if hasattr(self, "server"):
            self.server.track_host(self.host)

        if self.args.execute or self.args.ps_execute:
            self.logger.success("Executed command via mssqlexec")
            if self.args.no_output:
                self.logger.debug(f"Output set to disabled")
            else:
                for line in raw_output:
                    self.logger.highlight(line)

        return raw_output

    @requires_admin
    def ps_execute(
        self,
        payload=None,
        get_output=False,
        methods=None,
        force_ps32=False,
        dont_obfs=True,
    ):
        if not payload and self.args.ps_execute:
            payload = self.args.ps_execute
            if not self.args.no_output:
                get_output = True

        # We're disabling PS obfuscation by default as it breaks the MSSQLEXEC execution method
        ps_command = create_ps_command(payload, force_ps32=force_ps32, dont_obfs=dont_obfs)
        return self.execute(ps_command, get_output)

    @requires_admin
    def put_file(self):
        self.logger.display(f"Copy {self.args.put_file[0]} to {self.args.put_file[1]}")
        with open(self.args.put_file[0], "rb") as f:
            try:
                data = f.read()
                self.logger.display(f"Size is {len(data)} bytes")
                exec_method = MSSQLEXEC(self.conn)
                exec_method.put_file(data, self.args.put_file[1])
                if exec_method.file_exists(self.args.put_file[1]):
                    self.logger.success("File has been uploaded on the remote machine")
                else:
                    self.logger.fail("File does not exist on the remote system... error during upload")
            except Exception as e:
                self.logger.fail(f"Error during upload : {e}")

    @requires_admin
    def get_file(self):
        self.logger.display(f"Copy {self.args.get_file[0]} to {self.args.get_file[1]}")
        try:
            exec_method = MSSQLEXEC(self.conn)
            exec_method.get_file(self.args.get_file[0], self.args.get_file[1])
            self.logger.success(f"File {self.args.get_file[0]} was transferred to {self.args.get_file[1]}")
        except Exception as e:
            self.logger.fail(f"Error reading file {self.args.get_file[0]}: {e}")

    # We hook these functions in the tds library to use CME's logger instead of printing the output to stdout
    # The whole tds library in impacket needs a good overhaul to preserve my sanity
    def printRepliesCME(self):
        for keys in self.replies.keys():
            for i, key in enumerate(self.replies[keys]):
                if key["TokenType"] == TDS_ERROR_TOKEN:
                    error = f"ERROR({key['ServerName'].decode('utf-16le')}): Line {key['LineNumber']:d}: {key['MsgText'].decode('utf-16le')}"
                    self.lastError = SQLErrorException(f"ERROR: Line {key['LineNumber']:d}: {key['MsgText'].decode('utf-16le')}")
                    self._MSSQL__rowsPrinter.error(error)

                elif key["TokenType"] == TDS_INFO_TOKEN:
                    self._MSSQL__rowsPrinter.info(f"INFO({key['ServerName'].decode('utf-16le')}): Line {key['LineNumber']:d}: {key['MsgText'].decode('utf-16le')}")

                elif key["TokenType"] == TDS_LOGINACK_TOKEN:
                    self._MSSQL__rowsPrinter.info(f"ACK: Result: {key['Interface']} - {key['ProgName'].decode('utf-16le')} ({key['MajorVer']:d}{key['MinorVer']:d} {key['BuildNumHi']:d}{key['BuildNumLow']:d}) ")

                elif key["TokenType"] == TDS_ENVCHANGE_TOKEN:
                    if key["Type"] in (
                        TDS_ENVCHANGE_DATABASE,
                        TDS_ENVCHANGE_LANGUAGE,
                        TDS_ENVCHANGE_CHARSET,
                        TDS_ENVCHANGE_PACKETSIZE,
                    ):
                        record = TDS_ENVCHANGE_VARCHAR(key["Data"])
                        if record["OldValue"] == "":
                            record["OldValue"] = "None".encode("utf-16le")
                        elif record["NewValue"] == "":
                            record["NewValue"] = "None".encode("utf-16le")
                        if key["Type"] == TDS_ENVCHANGE_DATABASE:
                            _type = "DATABASE"
                        elif key["Type"] == TDS_ENVCHANGE_LANGUAGE:
                            _type = "LANGUAGE"
                        elif key["Type"] == TDS_ENVCHANGE_CHARSET:
                            _type = "CHARSET"
                        elif key["Type"] == TDS_ENVCHANGE_PACKETSIZE:
                            _type = "PACKETSIZE"
                        else:
                            _type = f"{key['Type']:d}"
                        self._MSSQL__rowsPrinter.info(f"ENVCHANGE({_type}): Old Value: {record['OldValue'].decode('utf-16le')}, New Value: {record['NewValue'].decode('utf-16le')}")

    tds.MSSQL.printReplies = printRepliesCME
