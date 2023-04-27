#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging

import paramiko

from cme.config import process_secret
from cme.connection import *
from cme.logger import CMEAdapter
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError, SSHException


class ssh(connection):
    def __init__(self, args, db, host):
        super().__init__(args, db, host)
        self.remote_version = None
        self.server_os = None


    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        ssh_parser = parser.add_parser(
            "ssh",
            help="own stuff using SSH",
            parents=[std_parser, module_parser]
        )
        ssh_parser.add_argument(
            "--no-bruteforce",
            action='store_true',
            help="No spray when using file for username and password (user1 => password1, user2 => password2"
        )
        ssh_parser.add_argument(
            "--key-file",
            type=str,
            help="Authenticate using the specified private key. Treats the password parameter as the key's passphrase."
        )
        ssh_parser.add_argument(
            "--port",
            type=int,
            default=22,
            help="SSH port (default: 22)"
        )
        ssh_parser.add_argument(
            "--continue-on-success",
            action="store_true",
            help="continues authentication attempts even after successes"
        )

        cgroup = ssh_parser.add_argument_group(
            "Command Execution",
            "Options for executing commands"
        )
        cgroup.add_argument(
            "--no-output",
            action="store_true",
            help="do not retrieve command output"
        )
        cgroup.add_argument(
            "-x",
            metavar="COMMAND",
            dest="execute",
            help="execute the specified command"
        )
        cgroup.add_argument(
            "--remote-enum",
            action="store_true",
            help="executes remote commands for enumeration"
        )

        return parser

    def proto_logger(self):
        self.logger = CMEAdapter(
            extra={
                "protocol": "SSH",
                "host": self.host,
                "port": self.args.port,
                "hostname": self.hostname
            }
        )
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    def print_host_info(self):
        self.logger.display(self.remote_version)
        return True

    def enum_host_info(self):
        self.remote_version = self.conn._transport.remote_version
        self.logger.debug(f"Remote version: {self.remote_version}")
        self.server_os = ""
        if self.args.remote_enum:
            stdin, stdout, stderr = self.conn.exec_command("uname -r")
            self.server_os = stdout.read().decode("utf-8")
            self.logger.debug(f"OS retrieved: {self.server_os}")
        self.db.add_host(self.host, self.args.port, self.remote_version, os=self.server_os)

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
        # we could add in another method to check by piping in the password to sudo
        # but that might be too much of an opsec concern - maybe add in a flag to do more checks?
        stdin, stdout, stderr = self.conn.exec_command("id")
        if stdout.read().decode("utf-8").find("uid=0(root)") != -1:
            self.logger.info(f"Determined user is root via `id` command")
            self.admin_privs = True
            return True
        stdin, stdout, stderr = self.conn.exec_command("sudo -ln | grep 'NOPASSWD: ALL'")
        if stdout.read().decode("utf-8").find("NOPASSWD: ALL")!= -1:
            self.logger.info(f"Determined user is root via `sudo -ln` command")
            self.admin_privs = True
            return True

    def plaintext_login(self, username, password):
        try:
            if self.args.key_file:
                self.logger.debug(f"Logging in with keyfile: {self.args.key_file}")
                with open(self.args.key_file, "r") as f:
                    key_data = f.read()

                self.conn.connect(
                    self.host,
                    port=self.args.port,
                    username=username,
                    passphrase=password,
                    key_filename=self.args.key_file,
                    look_for_keys=False,
                    allow_agent=False
                )
                cred_id = self.db.add_credential("key", username, password, key=key_data)
            else:
                self.logger.debug(f"Logging in with password")
                self.conn.connect(
                    self.host,
                    port=self.args.port,
                    username=username,
                    password=password,
                    look_for_keys=False,
                    allow_agent=False
                )
                cred_id = self.db.add_credential("plaintext", username, password)

            shell_access = False
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(cred_id, host_id)

            if self.check_if_admin():
                shell_access = True
                self.logger.debug(f"User {username} logged in successfully and is root!")
                if self.args.key_file:
                    self.db.add_admin_user("key", username, password, host_id=host_id, cred_id=cred_id)
                else:
                    self.db.add_admin_user("plaintext", username, password, host_id=host_id, cred_id=cred_id)
            else:
                stdin, stdout, stderr = self.conn.exec_command("id")
                output = stdout.read().decode("utf-8")
                if not output:
                    self.logger.debug(f"User cannot get a shell")
                    shell_access = False
                else:
                    shell_access = True

            if self.args.key_file:
                password = f"{password} (keyfile: {self.args.key_file})"

            display_shell_access = f" - shell access!" if shell_access else ""

            self.logger.success(
                f"{username}:{process_secret(password)} {self.mark_pwned()}{highlight(display_shell_access)}"
            )

            if not self.args.continue_on_success:
                return True
        except (AuthenticationException, NoValidConnectionsError, ConnectionResetError) as e:
            self.logger.fail(
                f"{username}:{process_secret(password)} {e}"
            )
            self.client_close()
            return False
        except Exception as e:
            self.logger.exception(e)
            self.client_close()
            return False

    def execute(self, payload=None, output=False):
        try:
            command = payload if payload is not None else self.args.execute
            stdin, stdout, stderr = self.conn.exec_command(command)
        except AttributeError:
            return ""
        if output:
            self.logger.success("Executed command")
            for line in stdout:
                self.logger.highlight(line.strip())
            return stdout
