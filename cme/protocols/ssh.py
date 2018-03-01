import paramiko
import socket
from cme.connection import *
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError, SSHException
from ConfigParser import ConfigParser


class ssh(connection):

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        ssh_parser = parser.add_parser('ssh', help="own stuff using SSH", parents=[std_parser, module_parser])
        #ssh_parser.add_argument("--key-file", type=str, help="Authenticate using the specified private key")
        ssh_parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")

        cgroup = ssh_parser.add_argument_group("Command Execution", "Options for executing commands")
        cgroup.add_argument('--no-output', action='store_true', help='do not retrieve command output')
        cgroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")

        return parser

    def proto_logger(self):
        self.logger = CMEAdapter(extra={'protocol': 'SSH',
                                        'host': self.host,
                                        'port': self.args.port,
                                        'hostname': self.hostname})

    def print_host_info(self):
        self.logger.info(self.remote_version)

    def enum_host_info(self):
        self.remote_version = self.conn._transport.remote_version

    def create_conn_obj(self):
        self.conn = paramiko.SSHClient()
        self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.conn.connect(self.host, port=self.args.port)
        except AuthenticationException:
            return True
        except SSHException:
            return True
        except NoValidConnectionsError:
            return False
        except socket.error:
            return False

    def check_if_admin(self):
        stdin, stdout, stderr = self.conn.exec_command('id')
        if stdout.read().find('uid=0(root)') != -1:
            self.admin_privs = True

    def plaintext_login(self, username, password):
        try:
            self.conn.connect(self.host, port=self.args.port, username=username, password=password)
            self.check_if_admin()

            self.logger.success(u'{}:{} {}'.format(username.decode('utf-8'),
                                                   password.decode('utf-8'),
                                                   highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')))

            return True
        except Exception as e:
            self.logger.error(u'{}:{} {}'.format(username.decode('utf-8'),
                                                 password.decode('utf-8'),
                                                 e))

            return False

    def execute(self, payload=None, get_output=False):
        stdin, stdout, stderr = self.conn.exec_command(self.args.execute)
        self.logger.success('Executed command')
        for line in stdout:
            self.logger.highlight(line.decode('utf-8').strip())

        return stdout
