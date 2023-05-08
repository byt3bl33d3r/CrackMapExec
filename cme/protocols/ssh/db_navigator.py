#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cme.cmedb import DatabaseNavigator, print_table, print_help


class navigator(DatabaseNavigator):
    def display_creds(self, creds):
        data = [
            [
                "CredID",
                "Admin On",
                "Total Logins",
                "Total Shells",
                "Username",
                "Password",
                "CredType",
            ]
        ]

        for cred in creds:
            cred_id = cred[0]
            username = cred[1]
            password = cred[2]
            credtype = cred[3]

            admin_links = self.db.get_admin_relations(cred_id=cred_id)
            total_users = self.db.get_loggedin_relations(cred_id=cred_id)
            total_shell = total_users = self.db.get_loggedin_relations(cred_id=cred_id, shell=True)

            data.append(
                [
                    cred_id,
                    str(len(admin_links)) + " Host(s)",
                    str(len(total_users)) + " Host(s)",
                    str(len(total_shell)) + " Shells(s)",
                    username,
                    password,
                    credtype,
                ]
            )
        print_table(data, title="Credentials")

    # pull/545
    def display_hosts(self, hosts):
        data = [["HostID", "Admins", "Total Users", "Host", "Port", "Banner", "OS"]]

        for h in hosts:
            host_id = h[0]
            host = h[1]
            port = h[2]
            banner = h[3]
            os = h[4]

            admin_users = self.db.get_admin_relations(host_id=host_id)
            total_users = self.db.get_loggedin_relations(host_id=host_id)
            data.append(
                [
                    host_id,
                    str(len(admin_users)) + " Cred(s)",
                    str(len(total_users)) + " User(s)",
                    host,
                    port,
                    banner,
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
                data = [["HostID", "Host", "Port", "Banner", "OS"]]
                host_id_list = []

                for h in hosts:
                    host_id = h[0]
                    host_id_list.append(host_id)
                    host = h[1]
                    port = h[2]
                    banner = h[3]
                    os = h[4]

                    data.append([host_id, host, port, banner, os])
                print_table(data, title="Host")

                admin_access_data = [["CredID", "CredType", "UserName", "Password", "Shell"]]
                nonadmin_access_data = [["CredID", "CredType", "UserName", "Password", "Shell"]]
                for host_id in host_id_list:
                    admin_links = self.db.get_admin_relations(host_id=host_id)
                    nonadmin_links = self.db.get_loggedin_relations(host_id=host_id)

                    for link in admin_links:
                        link_id, cred_id, host_id = link
                        creds = self.db.get_credentials(filter_term=cred_id)

                        for cred in creds:
                            cred_id = cred[0]
                            username = cred[1]
                            password = cred[2]
                            credtype = cred[3]
                            shell = True

                            admin_access_data.append([cred_id, credtype, username, password, shell])

                    # probably a better way to do this without looping through and requesting them all again,
                    # but I just want to get this working for now
                    for link in nonadmin_links:
                        link_id, cred_id, host_id, shell = link
                        creds = self.db.get_credentials(filter_term=cred_id)
                        for cred in creds:
                            cred_id = cred[0]
                            username = cred[1]
                            password = cred[2]
                            credtype = cred[3]
                            shell = shell

                            cred_data = [cred_id, credtype, username, password, shell]

                            if cred_data not in admin_access_data:
                                nonadmin_access_data.append(cred_data)

                if len(nonadmin_access_data) > 1:
                    print_table(
                        nonadmin_access_data,
                        title="Credential(s) with Non Admin Access",
                    )
                if len(admin_access_data) > 1:
                    print_table(admin_access_data, title="Credential(s) with Admin Access")

    def help_hosts(self):
        help_string = """
        hosts [filter_term]
        By default prints all hosts
        Table format:
        | 'HostID', 'Host', 'Port', 'Banner', 'OS' |
        """
        print_help(help_string)

    def do_creds(self, line):
        filter_term = line.strip()

        if filter_term == "":
            creds = self.db.get_credentials()
            self.display_creds(creds)
        # TODO
        # elif filter_term.split()[0].lower() == "add":
        #     # add format: "domain username password <notes> <credType> <sid>
        #     args = filter_term.split()[1:]
        #
        #     if len(args) == 3:
        #         domain, username, password = args
        #         if validate_ntlm(password):
        #             self.db.add_credential("hash", domain, username, password)
        #         else:
        #             self.db.add_credential("plaintext", domain, username, password)
        #     else:
        #         print("[!] Format is 'add username password")
        #         return
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
        elif filter_term.split()[0].lower() == "key":
            creds = self.db.get_credentials(cred_type="key")
            self.display_creds(creds)
        else:
            creds = self.db.get_credentials(filter_term=filter_term)
            if len(creds) != 1:
                self.display_creds(creds)
            elif len(creds) == 1:
                cred_data = [["CredID", "UserName", "Password", "CredType"]]
                cred_id_list = []

                for cred in creds:
                    cred_id = cred[0]
                    cred_id_list.append(cred_id)
                    username = cred[1]
                    password = cred[2]
                    credtype = cred[3]

                    cred_data.append([cred_id, username, password, credtype])
                print_table(cred_data, title="Credential(s)")

                admin_access_data = [["HostID", "Host", "Port", "Banner", "OS", "Shell"]]
                nonadmin_access_data = [["HostID", "Host", "Port", "Banner", "OS", "Shell"]]

                for cred_id in cred_id_list:
                    admin_links = self.db.get_admin_relations(cred_id=cred_id)
                    nonadmin_links = self.db.get_loggedin_relations(cred_id=cred_id)

                    for link in admin_links:
                        link_id, cred_id, host_id = link
                        hosts = self.db.get_hosts(host_id)
                        for h in hosts:
                            host_id = h[0]
                            host = h[1]
                            port = h[2]
                            banner = h[3]
                            os = h[4]
                            shell = True  # if we have root via SSH, we know it's a shell

                            admin_access_data.append([host_id, host, port, banner, os, shell])

                    # probably a better way to do this without looping through and requesting them all again,
                    # but I just want to get this working for now
                    for link in nonadmin_links:
                        link_id, cred_id, host_id, shell = link
                        hosts = self.db.get_hosts(host_id)
                        for h in hosts:
                            host_id = h[0]
                            host = h[1]
                            port = h[2]
                            banner = h[3]
                            os = h[4]
                            host_data = [host_id, host, port, banner, os, shell]
                            if host_data not in admin_access_data:
                                nonadmin_access_data.append(host_data)

                # we look if it's greater than one because the header row always exists
                if len(nonadmin_access_data) > 1:
                    print_table(nonadmin_access_data, title="Non-Admin Access to Host(s)")
                if len(admin_access_data) > 1:
                    print_table(admin_access_data, title="Admin Access to Host(s)")

    def help_creds(self):
        help_string = """
        creds [add|remove|plaintext|key|filter_term]
        By default prints all creds
        Table format:
        | 'CredID', 'Admin On', 'CredType', 'UserName', 'Password', 'Key' (if key type) |
        Subcommands:
            add - format: "add username password <notes> <credType>"
            remove - format: "remove <credID>"
            plaintext - prints plaintext creds
            key - prints ssh key creds
            filter_term - filters creds with filter_term
                If a single credential is returned (e.g. `creds 15`, it prints the following tables:
                    Credential(s) | 'CredID', 'CredType', 'UserName', 'Password', 'Key' |
                    Admin Access to Host(s) | 'HostID', 'Host', 'OS', 'Banner'
                Otherwise, it prints the default credential table from a `like` query on the `username` column
        """
        print_help(help_string)

    def display_keys(self, keys):
        data = [["Key ID", "Cred ID", "Key Data"]]
        for key in keys:
            data.append([key[0], key[1], key[2]])
        print_table(data, "Keys")

    def do_keys(self, line):
        filter_term = line.strip()

        if filter_term == "":
            keys = self.db.get_keys()
            self.display_keys(keys)
        elif filter_term == "cred_id":
            cred_id = filter_term.split()[1]
            keys = self.db.get_keys(cred_id=cred_id)
            self.display_keys(keys)
        else:
            key_id = filter_term
            keys = self.db.get_keys(key_id=key_id)
            self.display_keys(keys)

    def help_keys(self):
        help_string = """
        list SSH keys
        keys [id]
        """
        print_help(help_string)

    def do_clear_database(self, line):
        if input("This will destroy all data in the current database, are you SURE you" " want to run this? (y/n): ") == "y":
            self.db.clear_database()

    def help_clear_database(self):
        help_string = """
        clear_database
        THIS COMPLETELY DESTROYS ALL DATA IN THE CURRENTLY CONNECTED DATABASE
        YOU CANNOT UNDO THIS COMMAND
        """
        print_help(help_string)

    @staticmethod
    def complete_hosts(self, text, line):
        """
        Tab-complete 'hosts' commands.
        """
        commands = ["add", "remove"]

        mline = line.partition(" ")[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]

    def complete_creds(self, text, line):
        """
        Tab-complete 'creds' commands.
        """
        commands = ["add", "remove", "key", "plaintext"]

        mline = line.partition(" ")[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]
