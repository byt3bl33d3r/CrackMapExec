#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cme.cmedb import DatabaseNavigator, print_help, print_table
from cme.helpers.misc import validate_ntlm


class navigator(DatabaseNavigator):
    def display_creds(self, creds):
        data = [["CredID", "Admin On", "CredType", "Domain", "UserName", "Password"]]

        for cred in creds:
            cred_id = cred[0]
            domain = cred[1]
            username = cred[2]
            password = cred[3]
            credtype = cred[4]
            # pillaged_from = cred[5]

            links = self.db.get_admin_relations(user_id=cred_id)
            data.append(
                [
                    cred_id,
                    str(len(links)) + " Host(s)",
                    credtype,
                    domain,
                    username,
                    password,
                ]
            )
        print_table(data, title="Credentials")

    def display_hosts(self, hosts):
        data = [["HostID", "Admins", "IP", "Port", "Hostname", "Domain", "OS"]]

        for host in hosts:
            host_id = host[0]
            ip = host[1]
            port = host[2]
            hostname = host[3]
            domain = host[4]

            try:
                os = host[5].decode()
            except:
                os = host[5]

            links = self.db.get_admin_relations(host_id=host_id)
            data.append(
                [
                    host_id,
                    str(len(links)) + " Cred(s)",
                    ip,
                    port,
                    hostname,
                    domain,
                    os,
                ]
            )
        print_table(data, title="Hosts")

    def do_hosts(self, line):
        filter_term = line.strip()

        if filter_term == "":
            hosts = self.db.get_hosts()
            self.display_hosts(hosts)
        else:
            hosts = self.db.get_hosts(filter_term=filter_term)

            if len(hosts) > 1:
                self.display_hosts(hosts)
            elif len(hosts) == 1:
                data = [["HostID", "IP", "Port", "Hostname", "Domain", "OS"]]
                host_id_list = []

                for host in hosts:
                    host_id = host[0]
                    host_id_list.append(host_id)
                    ip = host[1]
                    port = host[2]
                    hostname = host[3]
                    domain = host[4]

                    try:
                        os = host[5].decode()
                    except:
                        os = host[5]

                    data.append([host_id, ip, port, hostname, domain, os])
                print_table(data, title="Host")

                data = [["CredID", "CredType", "Domain", "UserName", "Password"]]
                for host_id in host_id_list:
                    links = self.db.get_admin_relations(host_id=host_id)

                    for link in links:
                        link_id, cred_id, host_id = link
                        creds = self.db.get_credentials(filter_term=cred_id)

                        for cred in creds:
                            cred_id = cred[0]
                            domain = cred[1]
                            username = cred[2]
                            password = cred[3]
                            credtype = cred[4]
                            # pillaged_from = cred[5]
                            data.append([cred_id, credtype, domain, username, password])
                print_table(data, title="Credential(s) with Admin Access")

    def help_hosts(self):
        help_string = """
        hosts [filter_term]
        By default prints all hosts
        Table format:
        | 'HostID', 'IP', 'Port', 'Hostname', 'Domain', 'OS' |
        Subcommands:
        filter_term - filters hosts with filter_term
            If a single host is returned (e.g. `hosts 15`, it prints the following tables:
                Host | 'HostID', 'IP', 'Hostname', 'Domain', 'OS', 'DC', 'SMBv1', 'Signing', 'Spooler', 'Zerologon', 'PetitPotam' |
                Credential(s) with Admin Access | 'CredID', 'CredType', 'Domain', 'UserName', 'Password' |
            Otherwise, it prints the default host table from a `like` query on the `ip` and `hostname` columns
        """
        print_help(help_string)

    def do_creds(self, line):
        filter_term = line.strip()

        if filter_term == "":
            creds = self.db.get_credentials()
            self.display_creds(creds)
        elif filter_term.split()[0].lower() == "add":
            # add format: "domain username password <notes> <credType> <sid>
            args = filter_term.split()[1:]

            if len(args) == 3:
                domain, username, password = args
                if validate_ntlm(password):
                    self.db.add_credential("hash", domain, username, password)
                else:
                    self.db.add_credential("plaintext", domain, username, password)
            else:
                print("[!] Format is 'add domain username password")
                return
        elif filter_term.split()[0].lower() == "remove":
            args = filter_term.split()[1:]
            if len(args) != 1:
                print("[!] Format is 'remove <credID>'")
                return
            else:
                self.db.remove_credentials(args)
                self.db.remove_admin_relation(user_ids=args)
        elif filter_term.split()[0].lower() == "plaintext":
            creds = self.db.get_credentials(cred_type="plaintext")
            self.display_creds(creds)
        elif filter_term.split()[0].lower() == "hash":
            creds = self.db.get_credentials(cred_type="hash")
            self.display_creds(creds)
        else:
            creds = self.db.get_credentials(filter_term=filter_term)
            if len(creds) != 1:
                self.display_creds(creds)
            elif len(creds) == 1:
                data = [
                    [
                        "CredID",
                        "CredType",
                        "Pillaged From HostID",
                        "Domain",
                        "UserName",
                        "Password",
                    ]
                ]
                cred_id_list = []

                for cred in creds:
                    cred_id = cred[0]
                    cred_id_list.append(cred_id)
                    domain = cred[1]
                    username = cred[2]
                    password = cred[3]
                    credtype = cred[4]
                    pillaged_from = cred[5]

                    data.append([cred_id, credtype, pillaged_from, domain, username, password])
                print_table(data, title="Credential(s)")

                data = [["HostID", "IP", "Hostname", "Domain", "OS"]]
                for cred_id in cred_id_list:
                    links = self.db.get_admin_relations(user_id=cred_id)

                    for link in links:
                        link_id, cred_id, host_id = link
                        hosts = self.db.get_hosts(host_id)

                        for host in hosts:
                            host_id = host[0]
                            ip = host[1]
                            hostname = host[2]
                            domain = host[3]
                            os = host[4]

                            data.append([host_id, ip, hostname, domain, os])
                print_table(data, title="Admin Access to Host(s)")

    def help_creds(self):
        help_string = """
        creds [add|remove|plaintext|hash|filter_term]
        By default prints all creds
        Table format:
        | 'CredID', 'Admin On', 'CredType', 'Domain', 'UserName', 'Password' |
        Subcommands:
            add - format: "add domain username password <notes> <credType> <sid>"
            remove - format: "remove <credID>"
            plaintext - prints plaintext creds
            hash - prints hashed creds
            filter_term - filters creds with filter_term
                If a single credential is returned (e.g. `creds 15`, it prints the following tables:
                    Credential(s) | 'CredID', 'CredType', 'Pillaged From HostID', 'Domain', 'UserName', 'Password' |
                    Member of Group(s) | 'GroupID', 'Domain', 'Name' |
                    Admin Access to Host(s) | 'HostID', 'IP', 'Hostname', 'Domain', 'OS'
                Otherwise, it prints the default credential table from a `like` query on the `username` column
        """
        print_help(help_string)

    def do_clear_database(self, line):
        if input("This will destroy all data in the current database, are you SURE you want to run this? (y/n): ") == "y":
            self.db.clear_database()

    def help_clear_database(self):
        help_string = """
        clear_database
        THIS COMPLETELY DESTROYS ALL DATA IN THE CURRENTLY CONNECTED DATABASE
        YOU CANNOT UNDO THIS COMMAND
        """
        print_help(help_string)
