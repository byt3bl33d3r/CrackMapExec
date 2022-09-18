#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
from cme.connection import *
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
from ftplib import FTP, error_reply, error_temp, error_perm, error_proto
import configparser


class ftp(connection):

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        ftp_parser = parser.add_parser('ftp', help="own stuff using FTP", parents=[std_parser, module_parser])
        ftp_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        ftp_parser.add_argument("--port", type=int, default=21, help="FTP port (default: 21)")
        ftp_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")

        # TODO: Create more options for the protocol
        #cgroup = ftp_parser.add_argument_group("FTP Access", "Options for enumerating your access")
        #cgroup.add_argument('--ls', metavar="COMMAND", dest='list_directory', help='List files in the directory')
        return parser

    def proto_logger(self):
        self.logger = CMEAdapter(extra={'protocol': 'FTP',
                                        'host': self.host,
                                        'port': self.args.port,
                                        'hostname': self.hostname})

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
        self.logger.extra['protocol'] = "FTP"
        self.logger.info(u"Banner:{}".format(self.remote_version))
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

            self.logger.success(u'{}:{}'.format(username,
                                                password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8))

            if not self.args.continue_on_success:
                self.conn.close()
                return True
            self.conn.close()

        except Exception as e:
            self.logger.error(u'{}:{} (Response:{})'.format(username,
                                                 password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                 e))
            self.conn.close()
            return False
