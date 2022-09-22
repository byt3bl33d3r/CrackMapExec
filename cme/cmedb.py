#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cmd
import sqlite3
import sys
import os
import requests
from time import sleep
from terminaltables import AsciiTable
import configparser
from cme.loaders.protocol_loader import protocol_loader
from requests import ConnectionError
import csv

# The following disables the InsecureRequests warning and the 'Starting new HTTPS connection' log message
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class UserExitedProto(Exception):
    pass


class DatabaseNavigator(cmd.Cmd):

    def __init__(self, main_menu, database, proto):
        cmd.Cmd.__init__(self)

        self.main_menu = main_menu
        self.config = main_menu.config
        self.proto = proto
        self.db = database
        self.prompt = 'cmedb ({})({}) > '.format(main_menu.workspace, proto)

    def do_back(self, line):
        raise UserExitedProto

    def do_exit(self, line):
        sys.exit(0)

    def print_table(self, data, title=None):
        print("")
        table = AsciiTable(data)
        if title:
            table.title = title
        print(table.table)
        print("")

    def do_export(self, line):
        if not line:
            print("[-] not enough arguments")
            return

        line = line.split()

        if line[0].lower() == 'creds':
            if len(line) < 3:
                print("[-] invalid arguments, export creds <plaintext|hashes|both|csv> <filename>")
                return
            if line[1].lower() == 'plaintext':
                creds = self.db.get_credentials(credtype="plaintext")
            elif line[1].lower() == 'hashes':
                creds = self.db.get_credentials(credtype="hash")
            else:
                creds = self.db.get_credentials()

            with open(os.path.expanduser(line[2]), 'w') as export_file:
                for cred in creds:
                    credid, domain, user, password, credtype, fromhost = cred
                    if line[1].lower() == 'csv':
                        export_file.write('{},{},{},{},{},{}\n'.format(credid,domain,user,password,credtype,fromhost))
                    else:
                        export_file.write('{}\n'.format(password))
            print('[+] creds exported')

        elif line[0].lower() == 'hosts':
            if len(line) < 2:
                print("[-] invalid arguments, export hosts <filename>")
                return
            hosts = self.db.get_computers()
            with open(os.path.expanduser(line[1]), 'w') as export_file:
                for host in hosts:
                    hostid,ipaddress,hostname,domain,opsys,dc = host
                    export_file.write('{},{},{},{},{},{}\n'.format(hostid,ipaddress,hostname,domain,opsys,dc))
            print('[+] hosts exported')

        elif line[0].lower() == 'shares':
            if len(line) < 3:
                print("[-] invalid arguments, export shares <simple|detailed> <filename>")
                return
            
            if line[1].lower() == 'simple':
                shares = self.db.get_shares()
                with open(os.path.expanduser(line[2]), 'w') as export_file:
                    shareCSV = csv.writer(export_file, delimiter=";", quoting=csv.QUOTE_ALL, lineterminator='\n')
                    csv_header = ["id","computer","userid","name","remark","read","write"]
                    shareCSV.writerow(csv_header)                  
                    #id|computerid|userid|name|remark|read|write
                    for share in shares:
                        shareid,hostname,userid,sharename,shareremark,read,write = share
                        shareCSV.writerow([shareid,hostname,userid,sharename,shareremark,read,write])
                    print('[+] shares exported')  
                    
            elif line[1].lower() == 'detailed': #Detailed view gets hostsname, and usernames, and true false statement
                shares = self.db.get_shares()
                #id|computerid|userid|name|remark|read|write
                with open(os.path.expanduser(line[2]), 'w') as export_file:
                    shareCSV = csv.writer(export_file, delimiter=";", quoting=csv.QUOTE_ALL, lineterminator='\n')
                    csv_header = ["id","computer","userid","name","remark","read","write"]
                    shareCSV.writerow(csv_header)
                    for share in shares:
                        shareid,hostname,userid,sharename,shareremark,read,write = share

                        #Format is domain\user
                        prettyuser = f"{self.db.get_users(userid)[0][1]}\{self.db.get_users(userid)[0][2]}"

                        # #Format is hostname
                        # prettyhost = f"{self.db.get_computers(hostid)[0][2]}"

                        shareCSV.writerow([shareid,hostname,prettyuser,sharename,shareremark,bool(read),bool(write)])
                    print('[+] shares exported')

            else:
                print("[-] invalid arguments, export shares <simple|detailed> <filename>")
                return

        else:
            print('[-] invalid argument, specify creds, hosts or shares')
            

    def do_import(self, line):
        if not line:
            return

        if line == 'empire':
            headers = {'Content-Type': 'application/json'}

            # Pull the username and password from the config file
            payload = {'username': self.config.get('Empire', 'username'),
                       'password': self.config.get('Empire', 'password')}

            # Pull the host and port from the config file
            base_url = 'https://{}:{}'.format(self.config.get('Empire', 'api_host'), self.config.get('Empire', 'api_port'))

            try:
                r = requests.post(base_url + '/api/admin/login', json=payload, headers=headers, verify=False)
                if r.status_code == 200:
                    token = r.json()['token']

                    url_params = {'token': token}
                    r = requests.get(base_url + '/api/creds', headers=headers, params=url_params, verify=False)
                    creds = r.json()

                    for cred in creds['creds']:
                        if cred['credtype'] == 'token' or cred['credtype'] == 'krbtgt' or cred['username'].endswith('$'):
                            continue

                        self.db.add_credential(cred['credtype'], cred['domain'], cred['username'], cred['password'])

                    print("[+] Empire credential import successful")
                else:
                    print("[-] Error authenticating to Empire's RESTful API server!")

            except ConnectionError as e:
                print("[-] Unable to connect to Empire's RESTful API server: {}".format(e))

    def complete_import(self, text, line, begidx, endidx):
        "Tab-complete 'import' commands."

        commands = ["empire", "metasploit"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]

    def complete_export(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."

        commands = ["creds", "plaintext", "hashes"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]


class CMEDBMenu(cmd.Cmd):

    def __init__(self, config_path):
        cmd.Cmd.__init__(self)

        self.config_path = config_path

        try:
            self.config = configparser.ConfigParser()
            self.config.read(self.config_path)
        except Exception as e:
            print("[-] Error reading cme.conf: {}".format(e))
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
        # Set the database connection to autocommit w/ isolation level
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.text_factory = str
        self.conn.isolation_level = None

    def write_configfile(self):
        with open(self.config_path, 'w') as configfile:
            self.config.write(configfile)

    def do_proto(self, proto):
        if not proto:
            return

        proto_db_path = os.path.join(self.workspace_dir, self.workspace, proto + '.db')
        if os.path.exists(proto_db_path):
            self.open_proto_db(proto_db_path)
            db_nav_object = self.p_loader.load_protocol(self.protocols[proto]['nvpath'])
            db_object = self.p_loader.load_protocol(self.protocols[proto]['dbpath'])
            self.config.set('CME', 'last_used_db', proto)
            self.write_configfile()

            try:
                proto_menu = getattr(db_nav_object, 'navigator')(self, getattr(db_object, 'database')(self.conn), proto)
                proto_menu.cmdloop()
            except UserExitedProto:
                pass

    def do_workspace(self, line):
        if not line:
            return

        line = line.strip()

        if line.split()[0] == 'create':
            new_workspace = line.split()[1].strip()

            print("[*] Creating workspace '{}'".format(new_workspace))
            os.mkdir(os.path.join(self.workspace_dir, new_workspace))

            for protocol in self.protocols.keys():
                try:
                    protocol_object = self.p_loader.load_protocol(self.protocols[protocol]['dbpath'])
                except KeyError:
                    continue

                proto_db_path = os.path.join(self.workspace_dir, new_workspace, protocol + '.db')

                if not os.path.exists(proto_db_path):
                    print('[*] Initializing {} protocol database'.format(protocol.upper()))
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
        print("[-] Unable to find config file")
        sys.exit(1)

    try:
        cmedbnav = CMEDBMenu(config_path)
        cmedbnav.cmdloop()
    except KeyboardInterrupt:
        pass
