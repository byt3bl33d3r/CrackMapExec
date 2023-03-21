#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cmd
import logging
import shutil
import sqlite3
import sys
import os
import requests
from terminaltables import AsciiTable
import configparser
from cme.loaders.protocol_loader import protocol_loader
from cme.paths import CONFIG_PATH, WS_PATH, WORKSPACE_DIR
from requests import ConnectionError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.exc import SAWarning
import asyncio
import csv
import warnings
from textwrap import dedent

# The following disables the InsecureRequests warning and the 'Starting new HTTPS connection' log message
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# if there is an issue with SQLAlchemy and a connection cannot be cleaned up properly it spews out annoying warnings
warnings.filterwarnings("ignore", category=SAWarning)


class UserExitedProto(Exception):
    pass


def create_db_engine(db_path):
    db_engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}",
        isolation_level="AUTOCOMMIT",
        future=True
    )  # can add echo=True
    # db_engine.execution_options(isolation_level="AUTOCOMMIT")
    # db_engine.connect().connection.text_factory = str
    return db_engine


def print_table(data, title=None):
    print("")
    table = AsciiTable(data)
    if title:
        table.title = title
    print(table.table)
    print("")

def write_csv(filename, headers, entries):
    """
    Writes a CSV file with the provided parameters.
    """
    with open(os.path.expanduser(filename), 'w') as export_file:
        csv_file = csv.writer(export_file, delimiter=";", quoting=csv.QUOTE_ALL, lineterminator='\n', escapechar="\\")
        csv_file.writerow(headers)
        for entry in entries:
            csv_file.writerow(entry)


def write_list(filename, entries):
    """
    Writes a file with a simple list
    """
    with open(os.path.expanduser(filename), "w") as export_file:
        for line in entries:
            export_file.write(line + "\n")
    return


def complete_import(text, line):
    """
    Tab-complete 'import' commands
    """
    commands = ["empire", "metasploit"]
    mline = line.partition(' ')[2]
    offs = len(mline) - len(text)
    return [s[offs:] for s in commands if s.startswith(mline)]


def complete_export(text, line):
    """
    Tab-complete 'creds' commands.
    """
    commands = ["creds", "plaintext", "hashes", "shares", "local_admins", "signing"]
    mline = line.partition(' ')[2]
    offs = len(mline) - len(text)
    return [s[offs:] for s in commands if s.startswith(mline)]


def print_help(help_string):
    print(dedent(help_string))


class DatabaseNavigator(cmd.Cmd):
    def __init__(self, main_menu, database, proto):
        cmd.Cmd.__init__(self)
        self.main_menu = main_menu
        self.config = main_menu.config
        self.proto = proto
        self.db = database
        self.prompt = 'cmedb ({})({}) > '.format(main_menu.workspace, proto)

    def do_exit(self, line):
        asyncio.run(self.db.shutdown_db())
        sys.exit()

    def help_exit(self):
        help_string = """
        Exits
        """
        print_help(help_string)

    def do_back(self, line):
        raise UserExitedProto

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
                print("[-] invalid arguments, export creds <simple|detailed> <filename>")
                return
            
            filename = line[2]
            creds = self.db.get_credentials()
            csv_header = ["id", "domain", "username", "password", "credtype", "pillaged_from"]
            
            if line[1].lower() == "simple":
                write_csv(filename, csv_header, creds)
            elif line[1].lower() == "detailed":
                formatted_creds = []
               
                for cred in creds:
                    entry = [
                        cred[0],  # ID
                        cred[1],  # Domain
                        cred[2],  # Username
                        cred[3],  # Password/Hash
                        cred[4],  # Cred Type
                    ]
                    if cred[5] is None:
                        entry.append("")
                    else:
                        entry.append(self.db.get_hosts(cred[5])[0][2])
                    formatted_creds.append(entry)
                write_csv(filename, csv_header, formatted_creds)
            else:
                print('[-] No such export option: %s' % line[1])
                return 
            print('[+] Creds exported')
        # Hosts
        elif line[0].lower() == 'hosts':
            if len(line) < 3:
                print("[-] invalid arguments, export hosts <simple|detailed|signing> <filename>")
                return

            csv_header_simple = ["id", "ip", "hostname", "domain", "os", "dc", "smbv1", "signing"]
            csv_header_detailed = ["id", "ip", "hostname", "domain", "os", "dc", "smbv1", "signing", "spooler", "zerologon", "petitpotam"]
            filename = line[2]

            if line[1].lower() == "simple":
                hosts = self.db.get_hosts()
                simple_hosts = [host[:8] for host in hosts]
                write_csv(filename, csv_header_simple, simple_hosts)
            # TODO: maybe add more detail like who is an admin on it, shares discovered, etc
            elif line[1].lower() == "detailed":
                hosts = self.db.get_hosts()
                write_csv(filename, csv_header_detailed, hosts)
            elif line[1].lower() == "signing":
                hosts = self.db.get_hosts("signing")
                signing_hosts = [host[1] for host in hosts]
                write_list(filename, signing_hosts)
            else:
                print('[-] No such export option: %s' % line[1])
                return 
            print('[+] Hosts exported')
        # Shares
        elif line[0].lower() == 'shares':
            if len(line) < 3:
                print("[-] invalid arguments, export shares <simple|detailed> <filename>")
                return
            
            shares = self.db.get_shares()
            csv_header = ["id", "host", "userid", "name", "remark", "read", "write"]
            filename = line[2]
            
            if line[1].lower() == 'simple':
                write_csv(filename, csv_header, shares)
                print('[+] shares exported')
            # Detailed view gets hostname, usernames, and true false statement
            elif line[1].lower() == 'detailed':
                formatted_shares = []
                for share in shares:
                    user = self.db.get_users(share[2])[0]
                    
                    entry = [
                        share[0],                               # shareID
                        self.db.get_hosts(share[1])[0][2],      # hosts
                        f"{user[1]}\{user[2]}",                 # userID
                        share[3],                               # name
                        share[4],                               # remark
                        bool(share[5]),                         # read
                        bool(share[6])                          # write
                    ]
                    formatted_shares.append(entry)
                write_csv(filename, csv_header, formatted_shares)
            else:
                print('[-] No such export option: %s' % line[1])
                return 
            print('[+] Shares exported')
        # Local Admin
        elif line[0].lower() == 'local_admins':
            if len(line) < 3:
                print("[-] invalid arguments, export local_admins <simple|detailed> <filename>")
                return

            # These values don't change between simple and detailed
            local_admins = self.db.get_admin_relations()
            csv_header = ["id", "userid", "host"]
            filename = line[2]
            
            if line[1].lower() == 'simple':
                write_csv(filename, csv_header, local_admins)
            elif line[1].lower() == 'detailed':
                formatted_local_admins = []
                for entry in local_admins:
                    user = self.db.get_users(filter_term=entry[1])[0]
                    
                    formatted_entry = [
                        entry[0],                                           # Entry ID
                        f"{user[1]}/{user[2]}",                             # DOMAIN/Username
                        self.db.get_hosts(filter_term=entry[2])[0][2]    # Hostname
                    ]
                    # Can't modify a tuple which is what self.db.get_admin_relations() returns
                    formatted_local_admins.append(formatted_entry)
                write_csv(filename, csv_header, formatted_local_admins)
            else:
                print('[-] No such export option: %s' % line[1])
                return 
            print('[+] Local Admins exported')
        elif line[0].lower() == 'dpapi':
            if len(line) < 3:
                print("[-] invalid arguments, export dpapi <simple|detailed> <filename>")
                return

            # These values don't change between simple and detailed
            dpapi_secrets = self.db.get_dpapi_secrets()
            csv_header = ["id", "host", "dpapi_type", "windows_user", "username", "password", "url"]
            filename = line[2]

            if line[1].lower() == 'simple':
                write_csv(filename, csv_header, dpapi_secrets)
            elif line[1].lower() == 'detailed':
                formatted_dpapi_secret = []
                for entry in dpapi_secrets:
                    
                    formatted_entry = [
                        entry[0],                                        # Entry ID
                        self.db.get_hosts(filter_term=entry[1])[0][2],   # Hostname
                        entry[2],                                        # DPAPI type
                        entry[3],                                        # Windows User
                        entry[4],                                        # Username
                        entry[5],                                        # Password
                        entry[6],                                        # URL
                    ]
                    # Can't modify a tuple which is what self.db.get_admin_relations() returns
                    formatted_dpapi_secret.append(formatted_entry)
                write_csv(filename, csv_header, formatted_dpapi_secret)
            else:
                print('[-] No such export option: %s' % line[1])
                return 
            print('[+] DPAPI secrets exported')
        else:
            print("[-] Invalid argument, specify creds, hosts, local_admins, shares or dpapi")

    def help_export(self):
        help_string = """
        export [creds|hosts|local_admins|shares|signing] [simple|detailed|*] [filename]
        Exports information to a specified file
        
        * hosts has an additional third option from simple and detailed: signing - this simply writes a list of ips of
        hosts where signing is enabled
        """
        print_help(help_string)

    def do_import(self, line):
        if not line:
            return

        if line == 'empire':
            headers = {
                'Content-Type': 'application/json'
            }
            # Pull the username and password from the config file
            payload = {
                'username': self.config.get('Empire', 'username'),
                'password': self.config.get('Empire', 'password')
            }
            # Pull the host and port from the config file
            base_url = 'https://{}:{}'.format(
                self.config.get('Empire', 'api_host'),
                self.config.get('Empire', 'api_port')
            )

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


        self.conn = None
        self.p_loader = protocol_loader()
        self.protocols = self.p_loader.get_protocols()

        self.workspace = self.config.get('CME', 'workspace')
        self.do_workspace(self.workspace)

        self.db = self.config.get('CME', 'last_used_db')
        if self.db:
            self.do_proto(self.db)

    def write_configfile(self):
        with open(self.config_path, 'w') as configfile:
            self.config.write(configfile)

    def do_proto(self, proto):
        if not proto:
            return

        proto_db_path = os.path.join(WORKSPACE_DIR, self.workspace, proto + '.db')
        if os.path.exists(proto_db_path):
            self.conn = create_db_engine(proto_db_path)
            db_nav_object = self.p_loader.load_protocol(self.protocols[proto]['nvpath'])
            db_object = self.p_loader.load_protocol(self.protocols[proto]['dbpath'])
            self.config.set('CME', 'last_used_db', proto)
            self.write_configfile()
            try:
                proto_menu = getattr(db_nav_object, 'navigator')(self, getattr(db_object, 'database')(self.conn), proto)
                proto_menu.cmdloop()
            except UserExitedProto:
                pass
    def help_proto(self):
        help_string = """
        proto [smb|mssql|winrm]
            *unimplemented protocols: ftp, rdp, ldap, ssh
        Changes cmedb to the specified protocol
        """
        print_help(help_string)

    def do_workspace(self, line):
        line = line.strip()
        if not line:
            subcommand = ''
            self.help_workspace()
        else:
            subcommand = line.split()[0]

        if subcommand == 'create':
            new_workspace = line.split()[1].strip()
            print("[*] Creating workspace '{}'".format(new_workspace))
            self.create_workspace(new_workspace, self.p_loader, self.protocols)
            self.do_workspace(new_workspace)
        elif subcommand == 'list':
            print("[*] Enumerating Workspaces")
            for workspace in os.listdir(os.path.join(WORKSPACE_DIR)):
                if workspace == self.workspace:
                    print("==> "+workspace)
                else:
                    print(workspace)
        elif os.path.exists(os.path.join(WORKSPACE_DIR, line)):
            self.config.set('CME', 'workspace', line)
            self.write_configfile()
            self.workspace = line
            self.prompt = 'cmedb ({}) > '.format(line)

    def help_workspace(self):
        help_string = """
        workspace [create <targetName> | workspace list | workspace <targetName>]
        """
        print_help(help_string)

    def do_exit(self, line):
        sys.exit()

    def help_exit(self):
        help_string = """
        Exits
        """
        print_help(help_string)


def create_workspace(workspace_name, p_loader, protocols):
    os.mkdir(os.path.join(WORKSPACE_DIR, workspace_name))

    for protocol in protocols.keys():
        try:
            protocol_object = p_loader.load_protocol(protocols[protocol]['dbpath'])
        except KeyError:
            continue
        proto_db_path = os.path.join(WORKSPACE_DIR, workspace_name, protocol + '.db')

        if not os.path.exists(proto_db_path):
            print('[*] Initializing {} protocol database'.format(protocol.upper()))
            conn = sqlite3.connect(proto_db_path)
            c = conn.cursor()

            # try to prevent some weird sqlite I/O errors
            c.execute('PRAGMA journal_mode = OFF')
            c.execute('PRAGMA foreign_keys = 1')

            getattr(protocol_object, 'database').db_schema(c)

            # commit the changes and close everything off
            conn.commit()
            conn.close()


def delete_workspace(workspace_name):
    shutil.rmtree(os.path.join(WORKSPACE_DIR, workspace_name))


def create_workspace(workspace_name, p_loader, protocols):
    os.mkdir(os.path.join(WORKSPACE_DIR, workspace_name))

    for protocol in protocols.keys():
        try:
            protocol_object = p_loader.load_protocol(protocols[protocol]['dbpath'])
        except KeyError:
            continue
        proto_db_path = os.path.join(WORKSPACE_DIR, workspace_name, protocol + '.db')

        if not os.path.exists(proto_db_path):
            print('[*] Initializing {} protocol database'.format(protocol.upper()))
            conn = sqlite3.connect(proto_db_path)
            c = conn.cursor()

            # try to prevent some weird sqlite I/O errors
            c.execute('PRAGMA journal_mode = OFF')
            c.execute('PRAGMA foreign_keys = 1')

            getattr(protocol_object, 'database').db_schema(c)

            # commit the changes and close everything off
            conn.commit()
            conn.close()


def delete_workspace(workspace_name):
    shutil.rmtree(os.path.join(WORKSPACE_DIR, workspace_name))


def initialize_db(logger):
    if not os.path.exists(os.path.join(WS_PATH, 'default')):
        logger.info('Creating default workspace')
        os.mkdir(os.path.join(WS_PATH, 'default'))

    p_loader = protocol_loader()
    protocols = p_loader.get_protocols()
    for protocol in protocols.keys():
        try:
            protocol_object = p_loader.load_protocol(protocols[protocol]['dbpath'])
        except KeyError:
            continue

        proto_db_path = os.path.join(WS_PATH, 'default', protocol + '.db')

        if not os.path.exists(proto_db_path):
            logger.info('Initializing {} protocol database'.format(protocol.upper()))
            conn = sqlite3.connect(proto_db_path)
            c = conn.cursor()
            # try to prevent some weird sqlite I/O errors
            c.execute('PRAGMA journal_mode = OFF')  # could try setting to PERSIST if DB corruption starts occurring
            c.execute('PRAGMA foreign_keys = 1')
            # set a small timeout (5s) so if another thread is writing to the database, the entire program doesn't crash
            c.execute('PRAGMA busy_timeout = 5000')
            getattr(protocol_object, 'database').db_schema(c)
            # commit the changes and close everything off
            conn.commit()
            conn.close()


def main():
    if not os.path.exists(CONFIG_PATH):
        print("[-] Unable to find config file")
        sys.exit(1)
    try:
        cmedbnav = CMEDBMenu(CONFIG_PATH)
        cmedbnav.cmdloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
