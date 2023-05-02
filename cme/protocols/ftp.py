#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from cme.config import process_secret
from cme.connection import *
from cme.logger import CMEAdapter
from ftplib import FTP, error_reply, error_temp, error_perm, error_proto


class ftp(connection):

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        ftp_parser = parser.add_parser('ftp', help="own stuff using FTP", parents=[std_parser, module_parser])
        ftp_parser.add_argument("--port", type=int, default=21, help="FTP port (default: 21)")

        # TODO: Create more options for the protocol
        # cgroup = ftp_parser.add_argument_group("FTP Access", "Options for enumerating your access")
        # cgroup.add_argument('--ls', metavar="COMMAND", dest='list_directory', help='List files in the directory')
        return parser

    def proto_logger(self):
        self.logger = CMEAdapter(
            extra={
                "protocol": "FTP",
                "host": self.host,
                "port": self.args.port,
                "hostname": self.hostname
            }
        )

    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            if self.enum_host_info():
                if self.print_host_info():
                    if self.login():
                        pass

    def enum_host_info(self):
        self.remote_version = self.conn.getwelcome()
        self.remote_version = self.remote_version.split("220", 1)[1]
        return True

    def print_host_info(self):
        self.logger.extra["protocol"] = "FTP"
        self.logger.display(f"Banner:{self.remote_version}")
        return True

    def create_conn_obj(self):
        self.conn = FTP()
        try:
            self.conn.connect(host=self.host, port=self.args.port)
        except error_reply:
            return False
        except error_temp:
            return False
        except error_perm:
            return False
        except error_proto:
            return False
        except socket.error:
            return False
        return True

    def plaintext_login(self, username, password):
        try:
            self.conn.login(user=username, passwd=password)

            self.logger.success(
                f"{username}:{process_secret(password)}"
            )

            self.conn.close()
            return True
        except Exception as e:
            self.logger.fail(
                f'{username}:{process_secret(password)} (Response:{e})'
            )
            self.conn.close()
            return False
