import socket
import logging
from cme.logger import CMEAdapter
from io import StringIO
from cme.protocols.mssql.mssqlexec import MSSQLEXEC
from cme.connection import *
from cme.helpers.logger import highlight
from cme.helpers.bloodhound import add_user_bh
from cme.helpers.powershell import create_ps_command
from impacket import tds
import configparser
from impacket.smbconnection import SMBConnection, SessionError
from impacket.tds import SQLErrorException, TDS_LOGINACK_TOKEN, TDS_ERROR_TOKEN, TDS_ENVCHANGE_TOKEN, TDS_INFO_TOKEN, \
    TDS_ENVCHANGE_VARCHAR, TDS_ENVCHANGE_DATABASE, TDS_ENVCHANGE_LANGUAGE, TDS_ENVCHANGE_CHARSET, TDS_ENVCHANGE_PACKETSIZE


class mssql(connection):
    def __init__(self, args, db, host):
        self.mssql_instances = None
        self.domain = None
        self.server_os = None
        self.hash = None
        self.os_arch = None

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        mssql_parser = parser.add_parser('mssql', help="own stuff using MSSQL", parents=[std_parser, module_parser])
        dgroup = mssql_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, help="domain name")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')
        mssql_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        mssql_parser.add_argument("--port", default=1433, type=int, metavar='PORT', help='MSSQL port (default: 1433)')
        mssql_parser.add_argument("-q", "--query", dest='mssql_query', metavar='QUERY', type=str, help='execute the specified query against the MSSQL DB')
        mssql_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        mssql_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")

        cgroup = mssql_parser.add_argument_group("Command Execution", "options for executing commands")
        cgroup.add_argument('--force-ps32', action='store_true', help='force the PowerShell command to run in a 32-bit process')
        cgroup.add_argument('--no-output', action='store_true', help='do not retrieve command output')
        xgroup = cgroup.add_mutually_exclusive_group()
        xgroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")
        xgroup.add_argument("-X", metavar="PS_COMMAND", dest='ps_execute', help='execute the specified PowerShell command')

        psgroup = mssql_parser.add_argument_group('Powershell Obfuscation', "Options for PowerShell script obfuscation")
        psgroup.add_argument('--obfs', action='store_true', help='Obfuscate PowerShell scripts')
        psgroup.add_argument('--clear-obfscripts', action='store_true', help='Clear all cached obfuscated PowerShell scripts')

        return parser

    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            self.enum_host_info()
            self.print_host_info()
            self.login()
            if hasattr(self.args, 'module') and self.args.module:
                self.call_modules()
            else:
                self.call_cmd_args()

    def proto_logger(self):
        self.logger = CMEAdapter(extra={
                                        'protocol': 'MSSQL',
                                        'host': self.host,
                                        'port': self.args.port,
                                        'hostname': 'None'
                                        })

    def enum_host_info(self):
        # this try pass breaks module http server, more info https://github.com/byt3bl33d3r/CrackMapExec/issues/363
        try:
            # Probably a better way of doing this, grab our IP from the socket
            self.local_ip = str(self.conn.socket).split()[2].split('=')[1].split(':')[0]
        except:
            pass

        if self.args.domain:
            self.domain = self.args.domain
        else:
            try:
                smb_conn = SMBConnection(self.host, self.host, None)
                try:
                    smb_conn.login('', '')
                except SessionError as e:
                    if "STATUS_ACCESS_DENIED" in e.getErrorString():
                        pass

                self.domain = smb_conn.getServerDNSDomainName()
                self.hostname = smb_conn.getServerName()
                self.server_os = smb_conn.getServerOS()
                self.logger.extra['hostname'] = self.hostname

                try:
                    smb_conn.logoff()
                except:
                    pass

                if self.args.domain:
                    self.domain = self.args.domain

                if self.args.local_auth:
                    self.domain = self.hostname

            except Exception as e:
                self.logger.error("Error retrieving host domain: {} specify one manually with the '-d' flag".format(e))

        self.mssql_instances = self.conn.getInstances(0)
        self.db.add_computer(self.host, self.hostname, self.domain, self.server_os, len(self.mssql_instances))

        try:
            self.conn.disconnect()
        except:
            pass

    def print_host_info(self):
        self.logger.info(u"{} (name:{}) (domain:{})".format(self.server_os,
                                                            self.hostname,
                                                            self.domain))
        # if len(self.mssql_instances) > 0:
        #     self.logger.info("MSSQL DB Instances: {}".format(len(self.mssql_instances)))
        #     for i, instance in enumerate(self.mssql_instances):
        #         self.logger.debug("Instance {}".format(i))
        #         for key in instance.keys():
        #             self.logger.debug(key + ":" + instance[key])

    def create_conn_obj(self):
        try:
            self.conn = tds.MSSQL(self.host, self.args.port, rowsPrinter=self.logger)
            self.conn.connect()
        except socket.error:
            return False

        return True

    def check_if_admin(self, auth):
        try:
            self.conn.sql_query("SELECT IS_SRVROLEMEMBER('sysadmin')")
            self.conn.printRows()
            query_output = self.conn._MSSQL__rowsPrinter.getMessage()
            query_output = query_output.strip("\n-")

            if int(query_output):
                self.admin_privs = True
            else:
                return False
        except Exception as e:
            self.logger.error('Error calling check_if_admin(): {}'.format(e))
            return False

        return True

    def plaintext_login(self, domain, username, password):
        try:
            self.conn.disconnect()
        except:
            pass
        self.create_conn_obj()

        try:
            res = self.conn.login(None, username, password, domain, None, not self.args.local_auth)
            if res is not True:
                self.conn.printReplies()
                return False

            self.password = password
            self.username = username
            self.domain = domain
            self.check_if_admin(self.args.local_auth)
            self.db.add_credential('plaintext', domain, username, password)

            if self.admin_privs:
                self.db.add_admin_user('plaintext', domain, username, password, self.host)

            out = u'{}{}:{} {}'.format('{}\\'.format(domain) if not self.args.local_auth else '',
                                    username,
                                    password,
                                    highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))
            self.logger.success(out)
            add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True
        except Exception as e:
            self.logger.error(u'{}\\{}:{} {}'.format(domain,
                                                        username,
                                                        password,
                                                        e))
            return False

    def hash_login(self, domain, username, ntlm_hash):
        lmhash = ''
        nthash = ''

        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash

        try:
            self.conn.disconnect()
        except:
            pass
        self.create_conn_obj()

        try:
            res = self.conn.login(None, username, '', domain, ':' + nthash if not lmhash else ntlm_hash, True)
            if res is not True:
                self.conn.printReplies()
                return False

            self.hash = ntlm_hash
            self.username = username
            self.domain = domain
            self.check_if_admin()
            self.db.add_credential('hash', domain, username, ntlm_hash)

            if self.admin_privs:
                self.db.add_admin_user('hash', domain, username, ntlm_hash, self.host)

            out = u'{}\\{} {} {}'.format(domain,
                                        username,
                                        ntlm_hash,
                                        highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))
            self.logger.success(out)
            add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True
        except Exception as e:
            self.logger.error(u'{}\\{}:{} {}'.format(domain,
                                                        username,
                                                        ntlm_hash,
                                                        e))
            return False

    def mssql_query(self):
        self.conn.sql_query(self.args.mssql_query)
        self.conn.printRows()
        for line in StringIO(self.conn._MSSQL__rowsPrinter.getMessage()).readlines():
            if line.strip() != '':
                self.logger.highlight(line.strip())
        return self.conn._MSSQL__rowsPrinter.getMessage()

    @requires_admin
    def execute(self, payload=None, get_output=False, methods=None):
        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output: get_output = True

        logging.debug('Command to execute:\n{}'.format(payload))
        exec_method = MSSQLEXEC(self.conn)
        raw_output = exec_method.execute(payload, get_output)
        logging.debug('Executed command via mssqlexec')

        if hasattr(self, 'server'): self.server.track_host(self.host)

        output = u'{}'.format(raw_output)

        if self.args.execute or self.args.ps_execute:
            #self.logger.success('Executed command {}'.format('via {}'.format(self.args.exec_method) if self.args.exec_method else ''))
            self.logger.success('Executed command via mssqlexec')
            buf = StringIO(output).readlines()
            for line in buf:
                if line.strip() != '':
                    self.logger.highlight(line.strip())

        return output

    @requires_admin
    def ps_execute(self, payload=None, get_output=False, methods=None, force_ps32=False, dont_obfs=True):
        if not payload and self.args.ps_execute:
            payload = self.args.ps_execute
            if not self.args.no_output: get_output = True

        # We're disabling PS obfuscation by default as it breaks the MSSQLEXEC execution method (probably an escaping issue)
        ps_command = create_ps_command(payload, force_ps32=force_ps32, dont_obfs=dont_obfs)
        return self.execute(ps_command, get_output)

# We hook these functions in the tds library to use CME's logger instead of printing the output to stdout
# The whole tds library in impacket needs a good overhaul to preserve my sanity


def printRepliesCME(self):
    for keys in self.replies.keys():
        for i, key in enumerate(self.replies[keys]):
            if key['TokenType'] == TDS_ERROR_TOKEN:
                error =  "ERROR(%s): Line %d: %s" % (key['ServerName'].decode('utf-16le'), key['LineNumber'], key['MsgText'].decode('utf-16le'))
                self.lastError = SQLErrorException("ERROR: Line %d: %s" % (key['LineNumber'], key['MsgText'].decode('utf-16le')))
                self._MSSQL__rowsPrinter.error(error)

            elif key['TokenType'] == TDS_INFO_TOKEN:
                self._MSSQL__rowsPrinter.info("INFO(%s): Line %d: %s" % (key['ServerName'].decode('utf-16le'), key['LineNumber'], key['MsgText'].decode('utf-16le')))

            elif key['TokenType'] == TDS_LOGINACK_TOKEN:
                self._MSSQL__rowsPrinter.info("ACK: Result: %s - %s (%d%d %d%d) " % (key['Interface'], key['ProgName'].decode('utf-16le'), key['MajorVer'], key['MinorVer'], key['BuildNumHi'], key['BuildNumLow']))

            elif key['TokenType'] == TDS_ENVCHANGE_TOKEN:
                if key['Type'] in (TDS_ENVCHANGE_DATABASE, TDS_ENVCHANGE_LANGUAGE, TDS_ENVCHANGE_CHARSET, TDS_ENVCHANGE_PACKETSIZE):
                    record = TDS_ENVCHANGE_VARCHAR(key['Data'])
                    if record['OldValue'] == '':
                        record['OldValue'] = 'None'.encode('utf-16le')
                    elif record['NewValue'] == '':
                        record['NewValue'] = 'None'.encode('utf-16le')
                    if key['Type'] == TDS_ENVCHANGE_DATABASE:
                        _type = 'DATABASE'
                    elif key['Type'] == TDS_ENVCHANGE_LANGUAGE:
                        _type = 'LANGUAGE'
                    elif key['Type'] == TDS_ENVCHANGE_CHARSET:
                        _type = 'CHARSET'
                    elif key['Type'] == TDS_ENVCHANGE_PACKETSIZE:
                        _type = 'PACKETSIZE'
                    else:
                        _type = "%d" % key['Type']
                    self._MSSQL__rowsPrinter.info("ENVCHANGE(%s): Old Value: %s, New Value: %s" % (_type,record['OldValue'].decode('utf-16le'), record['NewValue'].decode('utf-16le')))

tds.MSSQL.printReplies = printRepliesCME
