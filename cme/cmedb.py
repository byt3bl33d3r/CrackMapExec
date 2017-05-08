#!/usr/bin/env python2
import cmd
import sqlite3
import sys
import os
from ConfigParser import ConfigParser
from cme.loaders.protocol_loader import protocol_loader

class UserExitedProto(Exception):
    pass

class CMEDatabaseNavigator(cmd.Cmd):

    def __init__(self, config_path):
        cmd.Cmd.__init__(self)

        self.config_path = config_path

        try:
            self.config = ConfigParser()
            self.config.read(self.config_path)
        except Exception as e:
            print "[-] Error reading cme.conf: {}".format(e)
            sys.exit(1)

        self.workspace_dir = os.path.expanduser('~/.cme/workspaces')
        self.conn = None
        self.p_loader = protocol_loader()
        self.protocols = self.p_loader.get_protocols()

        self.workspace = self.config.get('CME', 'workspace')
        self.do_workspace(self.workspace)

        self.db = self.config.get('CME', 'last_used_db')
        if self.db:
            self.do_proto(self.db)

    def open_proto_db(self, db_path):
        #Set the database connection to autocommit w/ isolation level
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.text_factory = str
        self.conn.isolation_level = None

    def write_configfile(self):
        with open(self.config_path, 'wb') as configfile:
            self.config.write(configfile)

    def do_proto(self, proto):
        if not proto: return

        proto_db_path = os.path.join(self.workspace_dir, self.workspace, proto + '.db')
        if os.path.exists(proto_db_path):
            self.open_proto_db(proto_db_path)
            protocol_object = self.p_loader.load_protocol(self.protocols[proto]['nvpath'])
            self.config.set('CME', 'last_used_db', proto)
            self.write_configfile()

            try:
                proto_menu = getattr(protocol_object, 'navigator')(self)
                proto_menu.cmdloop()
            except UserExitedProto:
                pass

    def do_workspace(self, line):
        if not line: return

        line = line.strip()

        if line.split()[0] == 'create':
            new_workspace = line.split()[1].strip()

            print "[*] Creating workspace '{}'".format(new_workspace)
            os.mkdir(os.path.join(self.workspace_dir, new_workspace))

            for protocol in self.protocols.keys():
                try:
                    protocol_object = self.p_loader.load_protocol(self.protocols[protocol]['dbpath'])
                except KeyError:
                    continue

                proto_db_path = os.path.join(self.workspace_dir, new_workspace, protocol + '.db')

                if not os.path.exists(proto_db_path):
                    print '[*] Initializing {} protocol database'.format(protocol.upper())
                    conn = sqlite3.connect(proto_db_path)
                    c = conn.cursor()

                    # try to prevent some of the weird sqlite I/O errors
                    c.execute('PRAGMA journal_mode = OFF')
                    c.execute('PRAGMA foreign_keys = 1')

                    getattr(protocol_object, 'database').db_schema(c)

                    # commit the changes and close everything off
                    conn.commit()
                    conn.close()

            self.do_workspace(new_workspace)

        elif os.path.exists(os.path.join(self.workspace_dir, line)):
            self.config.set('CME', 'workspace', line)
            self.write_configfile()

            self.workspace = line
            self.prompt = 'cmedb ({}) > '.format(line)

    def do_exit(self, line):
        sys.exit(0)

def main():
    config_path = os.path.expanduser('~/.cme/cme.conf')

    if not os.path.exists(config_path):
        print "[-] Unable to find config file"
        sys.exit(1)

    try:
        cmedbnav = CMEDatabaseNavigator(config_path)
        cmedbnav.cmdloop()
    except KeyboardInterrupt:
        pass
