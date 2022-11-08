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

        # Need to use if/elif/else to keep compatibility with py3.8/3.9
        # Reference DB Function cme/protocols/smb/database.py
        # Users
        if line[0].lower() == 'creds':
            if len(line) < 3:
                print("[-] invalid arguments, export creds <simple/detailed> <filename>")
                return
            
            filename = line[2]
            creds = self.db.get_credentials()
            csv_header = ["id","domain","username","password","credtype","pillaged_from"]
            
            if line[1].lower() == "simple":
                self.write_csv(filename,csv_header,creds)
                
            elif line[1].lower() == "detailed":
                formattedCreds = []
               
                for cred in creds:
                    entry = []
                    
                    entry.append(cred[0]) # ID
                    entry.append(cred[1]) # Domain
                    entry.append(cred[2]) # Username
                    entry.append(cred[3]) # Password/Hash
                    entry.append(cred[4]) # Cred Type
                    
                    
                    if cred[5] == None:
                        entry.append("")
                    else:
                        entry.append(self.db.get_computers(cred[5])[0][2])
                    formattedCreds.append(entry)
                self.write_csv(filename,csv_header,formattedCreds)
            print('[+] creds exported')

        #Hosts
        elif line[0].lower() == 'hosts':
            if len(line) < 3:
                print("[-] invalid arguments, export hosts <simple/detailed> <filename>")
                return
            hosts = self.db.get_computers()
            csv_header = ["id","ip","hostname","domain","os","dc","smbv1","signing"]
            filename = line[2]
            
            if line[1].lower() == 'simple':
                self.write_csv(filename,csv_header,hosts)
            
            #TODO, maybe add more detail like who is an admin on it, shares discovered, ect
            elif line[1].lower() == 'detailed':
                self.write_csv(filename,csv_header,hosts)
            
            
            print('[+] hosts exported')

        #Shares
        elif line[0].lower() == 'shares':
            if len(line) < 3:
                print("[-] invalid arguments, export shares <simple|detailed> <filename>")
                return
            
            shares = self.db.get_shares()
            csv_header = ["id","computer","userid","name","remark","read","write"]
            filename = line[2]
            
            if line[1].lower() == 'simple':

                self.write_csv(filename,csv_header,shares)
                
                
                print('[+] shares exported')  
                    
            elif line[1].lower() == 'detailed': #Detailed view gets hostsname, and usernames, and true false statement
                formattedShares = []
                for share in shares:
                    entry = []
                    #shareID
                    entry.append(share[0])
                    
                    #computer
                    entry.append(self.db.get_computers(share[1])[0][2])
                    
                    #userID
                    user = self.db.get_users(share[2])[0]
                    entry.append(f"{user[1]}\{user[2]}")
                    
                    #name
                    entry.append(share[3])
                    
                    #remark
                    entry.append(share[4])
                    
                    #read
                    entry.append(bool(share[5]))
                    
                    #write
                    entry.append(bool(share[6]))
                    
                    formattedShares.append(entry)
                
                self.write_csv(filename,csv_header,formattedShares)


                        #Format is domain\user
                        #prettyuser = f"{self.db.get_users(userid)[0][1]}\{self.db.get_users(userid)[0][2]}"


                        #Format is hostname
                        #prettyhost = f"{}"

                        
                print('[+] shares exported')
            
        #Local Admin
        elif line[0].lower() == 'local_admins':
            if len(line) < 3:
                print("[-] invalid arguments, export local_admins <simple|detailed> <filename>")

                return

            # These Values don't change between simple and detailed
            local_admins = self.db.get_admin_relations()
            csv_header = ["id","userid","computer"]
            filename = line[2]
            
            if line[1].lower() == 'simple':
                self.write_csv(filename,csv_header,local_admins)
            
            elif line[1].lower() == 'detailed':
                
                formattedLocalAdmins = []
                
                for entry in local_admins:
                    formattedEntry = [] # Can't modify a tuple which is what self.db.get_admin_relations() returns.
                    
                    #Entry ID
                    formattedEntry.append(entry[0])
                    
                    #DOMAIN/Username
                    user = self.db.get_users(filterTerm=entry[1])[0]
                    formattedEntry.append(f"{user[1]}/{user[2]}")
                    
                    #Hostname
                    formattedEntry.append(self.db.get_computers(filterTerm=entry[2])[0][2]) 
                    
                    
                    formattedLocalAdmins.append(formattedEntry)
                    
                self.write_csv(filename,csv_header,formattedLocalAdmins)
                print('[+] Local Admins exported')
                     
        else:
            print('[-] invalid argument, specify creds, hosts, local_admins or shares')
            
    def write_csv(self,filename,headers,entries):
        """
        Writes a CSV file with the provided parameters.
        """
        with open(os.path.expanduser(filename), 'w') as export_file:
            csvFile = csv.writer(export_file,delimiter=";", quoting=csv.QUOTE_ALL, lineterminator='\n',escapechar="\\")
            csvFile.writerow(headers)
            for entry in entries:
                csvFile.writerow(entry)
        
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
        helpString = "[-] wordkspace create <targetName> | workspace list | workspace <targetName>"
        if not line:
            print(helpString)
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

        elif line.split()[0] == 'list':
            print("[*] Enumerating Workspaces")
            for workspace in os.listdir(os.path.join(self.workspace_dir)):
                if(workspace==self.workspace):
                    print("==> "+workspace)
                else:
                    print(workspace)        

        elif os.path.exists(os.path.join(self.workspace_dir, line)):
            self.config.set('CME', 'workspace', line)
            self.write_configfile()

            self.workspace = line
            self.prompt = 'cmedb ({}) > '.format(line)
        
        else:
            print(helpString)


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
