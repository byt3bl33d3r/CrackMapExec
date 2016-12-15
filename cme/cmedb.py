#!/usr/bin/env python2
import cmd
import sqlite3
import sys
import os
from ConfigParser import ConfigParser
from cme.loaders.protocol_loader import protocol_loader

class CMEDatabaseNavigator(cmd.Cmd):

    def __init__(self, config_path):
        cmd.Cmd.__init__(self)
        self.workspace_dir = os.path.expanduser('~/.cme/workspaces')
        self.workspace = 'default'
        self.db = None
        self.conn = None
        self.prompt = 'cmedb ({}) > '.format(self.workspace)
        self.p_loader = protocol_loader()
        self.protocols = self.p_loader.get_protocols()

        try:
            self.config = ConfigParser()
            self.config.read(config_path)
        except Exception as e:
            print "[-] Error reading cme.conf: {}".format(e)
            sys.exit(1)

    def open_proto_db(self, db_path):
        #Set the database connection to autocommit w/ isolation level
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.text_factory = str
        self.conn.isolation_level = None

    def do_proto(self, proto):
        if not proto: return

        proto_db_path = os.path.join(self.workspace_dir, self.workspace, proto + '.db')
        if os.path.exists(proto_db_path):
            self.open_proto_db(proto_db_path)
            protocol_object = self.p_loader.load_protocol(self.protocols[proto]['nvpath'])

            #try:
            proto_menu = getattr(protocol_object, 'navigator')(self)
            proto_menu.cmdloop()
            #except:
            #    pass

    def do_workspace(self, line):
        if not line: return

        if os.path.exists(os.path.join(self.workspace_dir, line)):
            self.workspace = line
            self.prompt = 'cmedb ({}) >'.format(line)

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
