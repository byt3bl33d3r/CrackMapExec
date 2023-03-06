#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cme.helpers.misc import validate_ntlm
from cme.cmedb import DatabaseNavigator, print_table, print_help


class navigator(DatabaseNavigator):
    def display_creds(self, creds):
        data = [['CredID', 'Admin On', 'CredType', 'Domain', 'UserName', 'Password']]

        for cred in creds:
            cred_id = cred[0]
            domain = cred[1]
            username = cred[2]
            password = cred[3]
            credtype = cred[4]
            # pillaged_from = cred[5]

            links = self.db.get_admin_relations(user_id=cred_id)
            data.append([cred_id, str(len(links)) + ' Host(s)', credtype, domain, username, password])
        print_table(data, title='Credentials')

    def display_groups(self, groups):
        data = [['GroupID', 'Domain', 'Name', 'Enumerated Members', 'AD Members', 'Last Query Time']]

        for group in groups:
            group_id = group[0]
            domain = group[1]
            name = group[2]
            members = len(self.db.get_group_relations(group_id=group_id))
            ad_members = group[3]
            last_query_time = group[4]

            data.append([group_id, domain, name, members, ad_members, last_query_time])
        print_table(data, title='Groups')

    # pull/545
    def display_hosts(self, hosts):
        data = [[
            'HostID',
            'Admins',
            'IP',
            'Hostname',
            'Domain',
            'OS',
            'SMBv1',
            'Signing',
            'Spooler',
            'Zerologon',
            'PetitPotam'
        ]]
    
        for host in hosts:
            host_id = host[0]
            ip = host[1]
            hostname = host[2]
            domain = host[3]

            try:
                os = host[4].decode()
            except:
                os = host[4]
            try:
                smbv1 = host[6]
                signing = host[7]
            except IndexError:
                smbv1 = ''
                signing = ''
            try:
                spooler = host[8]
                zerologon = host[9]
                petitpotam = host[10]
            except IndexError:
                spooler = ''
                zerologon = ''
                petitpotam = ''

            links = self.db.get_admin_relations(host_id=host_id)
            data.append([
                host_id,
                str(len(links)) + ' Cred(s)',
                ip,
                hostname,
                domain,
                os,
                smbv1,
                signing,
                spooler,
                zerologon,
                petitpotam
            ])
        print_table(data, title='Hosts')
    
    def display_shares(self, shares):
        data = [["ShareID", "computer", "Name", "Remark", "Read Access", "Write Access"]]

        for share in shares:
            share_id = share[0]
            computer_id = share[1]
            name = share[3]
            remark = share[4]

            users_r_access = self.db.get_users_with_share_access(
                computer_id=computer_id,
                share_name=name,
                permissions='r'
            )
            users_w_access = self.db.get_users_with_share_access(
                computer_id=computer_id,
                share_name=name,
                permissions='w'
            )
            data.append([
                share_id,
                computer_id,
                name,
                remark,
                f"{len(users_r_access)} User(s)",
                f"{len(users_w_access)} Users"
            ])
        print_table(data)

    def do_shares(self, line):
        filter_term = line.strip()

        if filter_term == "":
            shares = self.db.get_shares()
            self.display_shares(shares)
        else:
            shares = self.db.get_shares(filter_term=filter_term)

            if len(shares) > 1:
                self.display_shares(shares)
            elif len(shares) == 1:
                share = shares[0]
                share_id = share[0]
                computer_id = share[1]
                name = share[3]
                remark = share[4]

                users_r_access = self.db.get_users_with_share_access(
                    computer_id=computer_id,
                    share_name=name,
                    permissions='r'
                )
                users_w_access = self.db.get_users_with_share_access(
                    computer_id=computer_id,
                    share_name=name,
                    permissions='w'
                )

                data = [["ShareID", "Name", "Remark"], [share_id, name, remark]]
                print_table(data, title='Share')
                host = self.db.get_computers(filter_term=computer_id)[0]
                data = [['HostID', 'IP', 'Hostname', 'Domain', 'OS', 'DC']]

                host_id = host[0]
                ip = host[1]
                hostname = host[2]
                domain = host[3]
                os = host[4]
                dc = host[5]

                data.append([host_id, ip, hostname, domain, os, dc])
                print_table(data, title='Share Location')

                if users_r_access:
                    data = [['CredID', 'CredType', 'Domain', 'UserName', 'Password']]
                    for user in users_r_access:
                        userid = user[0]
                        creds = self.db.get_credentials(filter_term=userid)

                        for cred in creds:
                            cred_id = cred[0]
                            domain = cred[1]
                            username = cred[2]
                            password = cred[3]
                            credtype = cred[4]
                            data.append([cred_id, credtype, domain, username, password])
                    print_table(data, title='Users(s) with Read Access')

                if users_w_access:
                    data = [['CredID', 'CredType', 'Domain', 'UserName', 'Password']]
                    for user in users_w_access:
                        userid = user[0]
                        creds = self.db.get_credentials(filter_term=userid)

                        for cred in creds:
                            cred_id = cred[0]
                            domain = cred[1]
                            username = cred[2]
                            password = cred[3]
                            credtype = cred[4]

                            data.append([cred_id, credtype, domain, username, password])
                    print_table(data, title='Users(s) with Write Access')

    def help_shares(self):
        help_string = """
        shares [filter_term]
        By default prints all shares
        Can use a filter term to filter shares
        """
        print_help(help_string)

    def do_groups(self, line):
        filter_term = line.strip()

        if filter_term == "":
            groups = self.db.get_groups()
            self.display_groups(groups)
        else:
            groups = self.db.get_groups(filter_term=filter_term)

            if len(groups) > 1:
                self.display_groups(groups)
            elif len(groups) == 1:
                data = [['GroupID', 'Domain', 'Name']]

                for group in groups:
                    group_id = group[0]
                    domain = group[1]
                    name = group[2]

                    data.append([group_id, domain, name])
                print_table(data, title='Group')
                data = [['CredID', 'CredType', 'Pillaged From HostID', 'Domain', 'UserName', 'Password']]

                for group in groups:
                    members = self.db.get_group_relations(group_id=group[0])

                    for member in members:
                        _, userid, _ = member
                        creds = self.db.get_credentials(filter_term=userid)

                        for cred in creds:
                            cred_id = cred[0]
                            domain = cred[1]
                            username = cred[2]
                            password = cred[3]
                            credtype = cred[4]
                            pillaged_from = cred[5]

                            data.append([cred_id, credtype, pillaged_from, domain, username, password])
                print_table(data, title='Member(s)')

    def help_groups(self):
        help_string = """
        groups [filter_term]
        By default prints all groups
        Can use a filter term to filter groups
        """
        print_help(help_string)

    def do_hosts(self, line):
        filter_term = line.strip()

        if filter_term == "":
            hosts = self.db.get_computers()
            self.display_hosts(hosts)
        else:
            hosts = self.db.get_computers(filter_term=filter_term)

            if len(hosts) > 1:
                self.display_hosts(hosts)
            elif len(hosts) == 1:
                data = [['HostID', 'IP', 'Hostname', 'Domain', 'OS', 'DC']]
                host_id_list = []

                for host in hosts:
                    host_id = host[0]
                    host_id_list.append(host_id)
                    ip = host[1]
                    hostname = host[2]
                    domain = host[3]
                    os = host[4]
                    dc = host[5]

                    data.append([host_id, ip, hostname, domain, os, dc])
                print_table(data, title='Host')

                data = [['CredID', 'CredType', 'Domain', 'UserName', 'Password']]
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
                print_table(data, title='Credential(s) with Admin Access')

    def help_hosts(self):
        help_string = """
        hosts [filter_term]
        By default prints all hosts
        Can use a filter term to filter hosts
        The filter can be an integer for a specific host id, "dc" for domain controllers, or an ip/hostname
        """
        print_help(help_string)

    def do_dpapi(self, line):
        filterTerm = line.strip()

        if filterTerm == "":
            secrets = self.db.get_dpapi_secrets()
            secrets.insert(0,["ID","Host", "DPAPI Type", "Windows User", "Username", "Password", "URL"])
            self.print_table(secrets, title='DPAPI Secrets')
        elif filterTerm.split()[0].lower() == "browser":
            secrets = self.db.get_dpapi_secrets(dpapi_type="MSEDGE")
            secrets += self.db.get_dpapi_secrets(dpapi_type="GOOGLE CHROME")
            secrets += self.db.get_dpapi_secrets(dpapi_type="IEX")
            secrets += self.db.get_dpapi_secrets(dpapi_type="FIREFOX")
            if len(secrets) > 0:
                secrets.insert(0,["ID","Host", "DPAPI Type", "Windows User", "Username", "Password", "URL"])
                self.print_table(secrets, title='DPAPI Secrets')
        elif filterTerm.split()[0].lower() == "chrome":
            secrets = self.db.get_dpapi_secrets(dpapi_type="GOOGLE CHROME")
            if len(secrets) > 0:
                secrets.insert(0,["ID","Host", "DPAPI Type", "Windows User", "Username", "Password", "URL"])
                self.print_table(secrets, title='DPAPI Secrets')
        elif filterTerm.split()[0].lower() == "msedge":
            secrets = self.db.get_dpapi_secrets(dpapi_type="MSEDGE")
            if len(secrets) > 0:
                secrets.insert(0,["ID","Host", "DPAPI Type", "Windows User", "Username", "Password", "URL"])
                self.print_table(secrets, title='DPAPI Secrets')
        elif filterTerm.split()[0].lower() == "credentials":
            secrets = self.db.get_dpapi_secrets(dpapi_type="CREDENTIAL")
            if len(secrets) > 0:
                secrets.insert(0,["ID","Host", "DPAPI Type", "Windows User", "Username", "Password", "URL"])
                self.print_table(secrets, title='DPAPI Secrets')
        elif filterTerm.split()[0].lower() == "iex":
            secrets = self.db.get_dpapi_secrets(dpapi_type="IEX")
            if len(secrets) > 0:
                secrets.insert(0,["ID","Host", "DPAPI Type", "Windows User", "Username", "Password", "URL"])
                self.print_table(secrets, title='DPAPI Secrets')
        elif filterTerm.split()[0].lower() == "firefox":
            secrets = self.db.get_dpapi_secrets(dpapi_type="FIREFOX")
            if len(secrets) > 0:
                secrets.insert(0,["ID","Host", "DPAPI Type", "Windows User", "Username", "Password", "URL"])
                self.print_table(secrets, title='DPAPI Secrets')
        else:
            secrets = self.db.get_dpapi_secrets(filterTerm=filterTerm)
            if len(secrets) > 0:
                secrets.insert(0,["ID","Host", "DPAPI Type", "Windows User", "Username", "Password", "URL"])
                self.print_table(secrets, title='DPAPI Secrets')

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
                data = [['CredID', 'CredType', 'Pillaged From HostID', 'Domain', 'UserName', 'Password']]
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
                print_table(data, title='Credential(s)')

                data = [['GroupID', 'Domain', 'Name']]
                for cred_id in cred_id_list:
                    links = self.db.get_group_relations(userID=cred_id)

                    for link in links:
                        link_id, user_id, group_id = link
                        groups = self.db.get_groups(group_id)

                        for group in groups:
                            group_id = group[0]
                            domain = group[1]
                            name = group[2]
                            data.append([group_id, domain, name])

                print_table(data, title='Member of Group(s)')

                data = [['HostID', 'IP', 'Hostname', 'Domain', 'OS']]
                for cred_id in cred_id_list:
                    links = self.db.get_admin_relations(user_id=cred_id)

                    for link in links:
                        link_id, cred_id, host_id = link
                        hosts = self.db.get_computers(host_id)

                        for host in hosts:
                            host_id = host[0]
                            ip = host[1]
                            hostname = host[2]
                            domain = host[3]
                            os = host[4]

                            data.append([host_id, ip, hostname, domain, os])
                print_table(data, title='Admin Access to Host(s)')

    def do_clear_database(self, line):
        self.db.clear_database()

    def complete_hosts(self, text, line):
        """
        Tab-complete 'hosts' commands.
        """
        commands = ["add", "remove", "dc"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]

    def complete_creds(self, text, line):
        """
        Tab-complete 'creds' commands.
        """
        commands = ["add", "remove", "hash", "plaintext"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]
