import winrm as pywinrm
import requests
import logging
from StringIO import StringIO
# from winrm.exceptions import InvalidCredentialsError
from impacket.smbconnection import SMBConnection, SessionError
from cme.connection import *
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
from ConfigParser import ConfigParser

# The following disables the InsecureRequests warning and the 'Starting new HTTPS connection' log message
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class winrm(connection):

    def __init__(self, args, db, host):
        self.domain = None

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        winrm_parser = parser.add_parser('winrm', help="own stuff using WINRM", parents=[std_parser, module_parser])
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
        self.logger = CMEAdapter(extra={'protocol': 'WINRM',
                                        'host': self.host,
                                        'port': 'NONE',
                                        'hostname': 'NONE'})

    def enum_host_info(self):
        try:
            smb_conn = SMBConnection(self.host, self.host, None)
            try:
                smb_conn.login('', '')
            except SessionError as e:
                if "STATUS_ACCESS_DENIED" in e.message:
                    pass

            self.domain = smb_conn.getServerDomain()
            self.hostname = smb_conn.getServerName()

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
        self.logger.info(self.endpoint)

    def create_conn_obj(self):
        endpoints = [
            'https://{}:5986/wsman'.format(self.host),
            'http://{}:5985/wsman'.format(self.host)
        ]

        for url in endpoints:
            try:
                requests.get(url, verify=False, timeout=10)
                self.endpoint = url
                if self.endpoint.startswith('https://'):
                    self.port = 5986
                else:
                    self.port = 5985

                self.logger.extra['port'] = self.port

                return True
            except Exception as e:
                if 'Max retries exceeded with url' not in str(e):
                    logging.debug('Error in WinRM create_conn_obj:' + str(e))

        return False

    def plaintext_login(self, domain, username, password):
        try:
            self.conn = pywinrm.Session(self.host,
                                        auth=('{}\\{}'.format(domain, username), password),
                                        transport='ntlm',
                                        server_cert_validation='ignore')

            # TO DO: right now we're just running the hostname command to make the winrm library auth to the server
            # we could just authenticate without running a command :) (probably)
            self.conn.run_cmd('hostname')
            self.admin_privs = True
            self.logger.success(u'{}\\{}:{} {}'.format(self.domain.decode('utf-8'),
                                                       username.decode('utf-8'),
                                                       password.decode('utf-8'),
                                                       highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')))

            return True

        except Exception as e:
            self.logger.error(u'{}\\{}:{} "{}"'.format(self.domain.decode('utf-8'),
                                                       username.decode('utf-8'),
                                                       password.decode('utf-8'),
                                                       e))

            return False

    def parse_output(self, response_obj):
        if response_obj.status_code == 0:
            buf = StringIO(response_obj.std_out).readlines()
            for line in buf:
                self.logger.highlight(line.decode('utf-8').strip())

            return response_obj.std_out

        else:
            buf = StringIO(response_obj.std_err).readlines()
            for line in buf:
                self.logger.highlight(line.decode('utf-8').strip())

            return response_obj.std_err

    def execute(self, payload=None, get_output=False):
        r = self.conn.run_cmd(self.args.execute)
        self.logger.success('Executed command')
        self.parse_output(r)

    def ps_execute(self, payload=None, get_output=False):
        r = self.conn.run_ps(self.args.ps_execute)
        self.logger.success('Executed command')
        self.parse_output(r)
