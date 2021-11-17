import paramiko
import socket
from cme.connection import *
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError, SSHException
import configparser


class ssh(connection):

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        ssh_parser = parser.add_parser('ssh', help="own stuff using SSH", parents=[std_parser, module_parser])
        ssh_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        ssh_parser.add_argument("--key-file", type=str, help="Authenticate using the specified private key. Treats the password parameter as the key's passphrase.")
        ssh_parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
        ssh_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")

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
        return True

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

    def client_close(self):
        self.conn.close()

    def check_if_admin(self):
        stdin, stdout, stderr = self.conn.exec_command('id')
        if stdout.read().decode('utf-8').find('uid=0(root)') != -1:
            self.admin_privs = True

    def plaintext_login(self, username, password):
        try:
            if self.args.key_file:
                passwd = password
                password = u'{} (keyfile: {})'.format(passwd, self.args.key_file)
                self.conn.connect(self.host, port=self.args.port, username=username, passphrase=passwd, key_filename=self.args.key_file, look_for_keys=False, allow_agent=False)
            else:
                self.conn.connect(self.host, port=self.args.port, username=username, password=password, look_for_keys=False, allow_agent=False)

            self.check_if_admin()
            self.logger.success(u'{}:{} {}'.format(username,
                                                   password,
                                                   highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')))
            if not self.args.continue_on_success:
                return True
        except Exception as e:
            self.logger.error(u'{}:{} {}'.format(username,
                                                 password,
                                                 e))
            self.client_close()
            return False

    def execute(self, payload=None, get_output=False):
        try:
            stdin, stdout, stderr = self.conn.exec_command(self.args.execute)
        except AttributeError:
            return ''
        self.logger.success('Executed command')
        for line in stdout:
            self.logger.highlight(line.strip())

        return stdout
