#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cme.cmedb import DatabaseNavigator, print_table, print_help


class navigator(DatabaseNavigator):
    def display_creds(self, creds):
        data = [[
            "CredID",
            "Total Logins",
            "Username",
            "Password",
        ]]

        for cred in creds:
            total_users = self.db.get_loggedin_relations(cred_id=cred[0])
            data.append([
                cred[0],
                str(len(total_users)) + " Host(s)",
                cred[1],
                cred[2],
            ])
        print_table(data, title="Credentials")

    def display_hosts(self, hosts):
        data = [[
            "HostID",
            "Total Users",
            "Host",
            "Port",
            "Banner",
        ]]

        for h in hosts:
            total_users = self.db.get_loggedin_relations(host_id=h[0])
            data.append([
                h[0],
                str(len(total_users)) + " User(s)",
                h[1],
                h[2],
                h[3],
            ])
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
                data = [[
                    "HostID",
                    "Host",
                    "Port",
                    "Banner"
                ]]
                host_id_list = [h[0] for h in hosts]

                for h in hosts:
                    data.append([h[0], h[1], h[2], h[3], h[4]])

                print_table(data, title="Host")

                login_data = [[
                    "CredID",
                    "UserName",
                    "Password"
                ]]
                for host_id in host_id_list:
                    login_links = self.db.get_loggedin_relations(host_id=host_id)

                    for link in login_links:
                        link_id, cred_id, host_id = link
                        creds = self.db.get_credentials(filter_term=cred_id)
                        for cred in creds:
                            cred_data = [cred[0], cred[1], cred[2]]
                            if cred_data not in login_data:
                                login_data.append(cred_data)

                if len(login_data) > 1:
                    print_table(login_data, title="Credential(s) with Logins",)

    @staticmethod
    def help_hosts(self):
        help_string = """
        hosts [filter_term]
        By default prints all hosts
        Table format:
        | 'HostID', 'Host', 'Port', 'Banner' |
        """
        print_help(help_string)

    def do_creds(self, line):
        filter_term = line.strip()

        if filter_term == "":
            creds = self.db.get_credentials()
            self.display_creds(creds)
        elif filter_term.split()[0].lower() == "add":
            # add format: "username password"
            args = filter_term.split()[1:]

            if len(args) == 2:
                username, password = args
                self.db.add_credential(username, password)
            else:
                print("[!] Format is 'add username password")
                return
        elif filter_term.split()[0].lower() == "remove":
            args = filter_term.split()[1:]
            if len(args) != 1:
                print("[!] Format is 'remove <credID>'")
                return
            else:
                self.db.remove_credentials(args)
                self.db.remove_admin_relation(user_ids=args)
        else:
            creds = self.db.get_credentials(filter_term=filter_term)
            if len(creds) != 1:
                self.display_creds(creds)
            elif len(creds) == 1:
                cred_data = [["CredID", "UserName", "Password"]]
                cred_id_list = []

                for cred in creds:
                    cred_id = cred[0]
                    cred_id_list.append(cred_id)
                    username = cred[1]
                    password = cred[2]

                    cred_data.append([cred_id, username, password])
                print_table(cred_data, title="Credential(s)")

                access_data = [["HostID", "Host", "Port", "Banner"]]

                for cred_id in cred_id_list:
                    logins = self.db.get_loggedin_relations(cred_id=cred_id)

                    for link in logins:
                        link_id, cred_id, host_id = link
                        hosts = self.db.get_hosts(host_id)
                        for h in hosts:
                            access_data.append([h[0], h[1], h[2], h[3]])

                # we look if it's greater than one because the header row always exists
                if len(access_data) > 1:
                    print_table(access_data, title="Access to Host(s)")

    def help_creds(self):
        help_string = """
        creds [add|remove|filter_term]
        By default prints all creds
        Table format:
        | 'CredID', 'Login To', 'UserName', 'Password' |
        Subcommands:
            add - format: "add username password <notes> <credType>"
            remove - format: "remove <credID>"
            filter_term - filters creds with filter_term
                If a single credential is returned (e.g. `creds 15`, it prints the following tables:
                    Credential(s) | 'CredID', 'UserName', 'Password' |
                    Access to Host(s) | 'HostID', 'Host', 'OS', 'Banner'
                Otherwise, it prints the default credential table from a `like` query on the `username` column
        """
        print_help(help_string)

    def do_clear_database(self, line):
        if input("This will destroy all data in the current database, are you SURE you want to run this? (y/n): ") == "y":
            self.db.clear_database()

    @staticmethod
    def help_clear_database(self):
        help_string = """
        clear_database
        THIS COMPLETELY DESTROYS ALL DATA IN THE CURRENTLY CONNECTED DATABASE
        YOU CANNOT UNDO THIS COMMAND
        """
        print_help(help_string)
