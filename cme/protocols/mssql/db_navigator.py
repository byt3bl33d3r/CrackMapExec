#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cme.helpers.misc import validate_ntlm
from cme.cmedb import DatabaseNavigator, print_table, print_help


class navigator(DatabaseNavigator):
    def display_creds(self, creds):
        data = [["CredID", "Admin On", "CredType", "Domain", "UserName", "Password"]]

        for cred in creds:
            cred_id = cred[0]
            credtype = cred[1]
            domain = cred[2]
            username = cred[3]
            password = cred[4]
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
        data = [["HostID", "Admins", "IP", "Hostname", "Domain", "OS", "DB Instances"]]
        for host in hosts:
            host_id = host[0]
            ip = host[1]
            hostname = host[2]
            domain = host[3]
            os = host[4]
            instances = host[5]

            links = self.db.get_admin_relations(host_id=host_id)

            data.append(
                [
                    host_id,
                    str(len(links)) + " Cred(s)",
                    ip,
                    hostname,
                    domain,
                    os,
                    instances,
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
                data = [["HostID", "IP", "Hostname", "Domain", "OS"]]
                host_id_list = []

                for host in hosts:
                    host_id = host[0]
                    host_id_list.append(host_id)

                    ip = host[1]
                    hostname = host[2]
                    domain = host[3]
                    os = host[4]

                    data.append([host_id, ip, hostname, domain, os])

                print_table(data, title="Host(s)")

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

    def do_creds(self, line):
        filter_term = line.strip()

        if filter_term == "":
            creds = self.db.get_credentials()
            self.display_creds(creds)
        elif filter_term.split()[0].lower() == "add":
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
                self.db.remove_links(credIDs=args)
        elif filter_term.split()[0].lower() == "plaintext":
            creds = self.db.get_credentials(cred_type="plaintext")
            self.display_creds(creds)
        elif filter_term.split()[0].lower() == "hash":
            creds = self.db.get_credentials(cred_type="hash")
            self.display_creds(creds)
        else:
            creds = self.db.get_credentials(filter_term=filter_term)
            data = [["CredID", "CredType", "Domain", "UserName", "Password"]]
            cred_id_list = []

            for cred in creds:
                cred_id = cred[0]
                cred_id_list.append(cred_id)

                credType = cred[1]
                domain = cred[2]
                username = cred[3]
                password = cred[4]

                data.append([cred_id, credType, domain, username, password])

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

    def do_clear_database(self, line):
        if (
            input(
                "This will destroy all data in the current database, are you SURE you want to run this? (y/n): "
            )
            == "y"
        ):
            self.db.clear_database()

    def help_clear_database(self):
        help_string = """
        clear_database
        THIS COMPLETELY DESTROYS ALL DATA IN THE CURRENTLY CONNECTED DATABASE
        YOU CANNOT UNDO THIS COMMAND
        """
        print_help(help_string)

    def complete_hosts(self, text, line):
        """
        Tab-complete 'creds' commands
        """
        commands = ["add", "remove"]

        mline = line.partition(" ")[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]

    def complete_creds(self, text, line):
        """
        Tab-complete 'creds' commands
        """
        commands = ["add", "remove", "hash", "plaintext"]

        mline = line.partition(" ")[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]
