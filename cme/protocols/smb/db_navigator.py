#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cme.helpers.misc import validate_ntlm
from cme.cmedb import DatabaseNavigator, print_table, print_help
from termcolor import colored
import functools

help_header = functools.partial(colored, color='cyan', attrs=['bold'])
help_kw = functools.partial(colored, color='green', attrs=['bold'])

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

    def display_groups(self, groups):
        data = [
            [
                "GroupID",
                "Domain",
                "Name",
                "RID",
                "Enumerated Members",
                "AD Members",
                "Last Query Time",
            ]
        ]

        for group in groups:
            group_id = group[0]
            domain = group[1]
            name = group[2]
            rid = group[3]
            members = len(self.db.get_group_relations(group_id=group_id))
            ad_members = group[4]
            last_query_time = group[5]
            data.append([group_id, domain, name, rid, members, ad_members, last_query_time])
        print_table(data, title="Groups")

    # pull/545
    def display_hosts(self, hosts):
        data = [
            [
                "HostID",
                "Admins",
                "IP",
                "Hostname",
                "Domain",
                "OS",
                "SMBv1",
                "Signing",
                "Spooler",
                "Zerologon",
                "PetitPotam",
            ]
        ]

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
                smbv1 = ""
                signing = ""
            try:
                spooler = host[8]
                zerologon = host[9]
                petitpotam = host[10]
            except IndexError:
                spooler = ""
                zerologon = ""
                petitpotam = ""

            links = self.db.get_admin_relations(host_id=host_id)
            data.append(
                [
                    host_id,
                    str(len(links)) + " Cred(s)",
                    ip,
                    hostname,
                    domain,
                    os,
                    smbv1,
                    signing,
                    spooler,
                    zerologon,
                    petitpotam,
                ]
            )
        print_table(data, title="Hosts")

    def display_shares(self, shares):
        data = [["ShareID", "host", "Name", "Remark", "Read Access", "Write Access"]]

        for share in shares:
            share_id = share[0]
            host_id = share[1]
            name = share[3]
            remark = share[4]

            users_r_access = self.db.get_users_with_share_access(host_id=host_id, share_name=name, permissions="r")
            users_w_access = self.db.get_users_with_share_access(host_id=host_id, share_name=name, permissions="w")
            data.append(
                [
                    share_id,
                    host_id,
                    name,
                    remark,
                    f"{len(users_r_access)} User(s)",
                    f"{len(users_w_access)} Users",
                ]
            )
        print_table(data)

    def do_shares(self, line):
        filter_term = line.strip()

        if filter_term == "":
            shares = self.db.get_shares()
            self.display_shares(shares)
        elif filter_term in ["r", "w", "rw"]:
            shares = self.db.get_shares_by_access(line)
            self.display_shares(shares)
        else:
            shares = self.db.get_shares(filter_term=filter_term)

            if len(shares) > 1:
                self.display_shares(shares)
            elif len(shares) == 1:
                share = shares[0]
                share_id = share[0]
                host_id = share[1]
                name = share[3]
                remark = share[4]

                users_r_access = self.db.get_users_with_share_access(host_id=host_id, share_name=name, permissions="r")
                users_w_access = self.db.get_users_with_share_access(host_id=host_id, share_name=name, permissions="w")

                data = [["ShareID", "Name", "Remark"], [share_id, name, remark]]
                print_table(data, title="Share")
                host = self.db.get_hosts(filter_term=host_id)[0]
                data = [
                    ["HostID", "IP", "Hostname", "Domain", "OS", "DC"],
                    [host[0], host[1], host[2], host[3], host[4], host[5]],
                ]

                print_table(data, title="Share Location")

                if users_r_access:
                    data = [["CredID", "CredType", "Domain", "UserName", "Password"]]
                    for user in users_r_access:
                        userid = user[0]
                        creds = self.db.get_credentials(filter_term=userid)

                        for cred in creds:
                            data.append([cred[0], cred[4], cred[1], cred[2], cred[3]])
                    print_table(data, title="Users(s) with Read Access")

                if users_w_access:
                    data = [["CredID", "CredType", "Domain", "UserName", "Password"]]
                    for user in users_w_access:
                        userid = user[0]
                        creds = self.db.get_credentials(filter_term=userid)

                        for cred in creds:
                            data.append([cred[0], cred[4], cred[1], cred[2], cred[3]])
                    print_table(data, title="Users(s) with Write Access")

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
                data = [
                    [
                        "GroupID",
                        "Domain",
                        "Name",
                        "RID",
                        "Enumerated Members",
                        "AD Members",
                        "Last Query Time",
                    ]
                ]

                for group in groups:
                    data.append(
                        [
                            group[0],
                            group[1],
                            group[2],
                            group[3],
                            len(self.db.get_group_relations(group_id=group[0])),
                            group[4],
                            group[5],
                        ]
                    )
                print_table(data, title="Group")
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

                for group in groups:
                    members = self.db.get_group_relations(group_id=group[0])

                    for member in members:
                        _, userid, _ = member
                        creds = self.db.get_credentials(filter_term=userid)

                        for cred in creds:
                            data.append([cred[0], cred[4], cred[5], cred[1], cred[2], cred[3]])
                print_table(data, title="Member(s)")

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
            hosts = self.db.get_hosts()
            self.display_hosts(hosts)
        else:
            hosts = self.db.get_hosts(filter_term=filter_term)

            if len(hosts) > 1:
                self.display_hosts(hosts)
            elif len(hosts) == 1:
                data = [
                    [
                        "HostID",
                        "IP",
                        "Hostname",
                        "Domain",
                        "OS",
                        "DC",
                        "SMBv1",
                        "Signing",
                        "Spooler",
                        "Zerologon",
                        "PetitPotam",
                    ]
                ]
                host_id_list = []

                for host in hosts:
                    host_id = host[0]
                    host_id_list.append(host_id)
                    ip = host[1]
                    hostname = host[2]
                    domain = host[3]

                    try:
                        os = host[4].decode()
                    except:
                        os = host[4]
                    try:
                        dc = host[5]
                    except IndexError:
                        dc = ""
                    try:
                        smbv1 = host[6]
                        signing = host[7]
                    except IndexError:
                        smbv1 = ""
                        signing = ""
                    try:
                        spooler = host[8]
                        zerologon = host[9]
                        petitpotam = host[10]
                    except IndexError:
                        spooler = ""
                        zerologon = ""
                        petitpotam = ""

                    data.append(
                        [
                            host_id,
                            ip,
                            hostname,
                            domain,
                            os,
                            dc,
                            smbv1,
                            signing,
                            spooler,
                            zerologon,
                            petitpotam,
                        ]
                    )
                print_table(data, title="Host")

                data = [["CredID", "CredType", "Domain", "UserName", "Password"]]
                for host_id in host_id_list:
                    links = self.db.get_admin_relations(host_id=host_id)

                    for link in links:
                        link_id, cred_id, host_id = link
                        creds = self.db.get_credentials(filter_term=cred_id)

                        for cred in creds:
                            data.append([cred[0], cred[4], cred[1], cred[2], cred[3]])

                print_table(data, title="Credential(s) with Admin Access")

    def do_wcc(self, line):
        valid_columns = {
            'ip':'IP',
            'hostname':'Hostname',
            'check':'Check',
            'description':'Description',
            'status':'Status',
            'reasons':'Reasons'
        }

        line = line.strip()

        if line.lower() == 'full':
            columns_to_display = list(valid_columns.values())
        else:
            requested_columns = line.split(' ')
            columns_to_display = list(valid_columns[column.lower()] for column in requested_columns if column.lower() in valid_columns)

        results = self.db.get_check_results()
        self.display_wcc_results(results, columns_to_display)

    def display_wcc_results(self, results, columns_to_display=None):
        data = [
            [
                "IP",
                "Hostname",
                "Check",
                "Status"
            ]
        ]
        if columns_to_display:
            data = [columns_to_display]

        checks = self.db.get_checks()
        checks_dict = {}
        for check in checks:
            check = check._asdict()
            checks_dict[check['id']] = check

        for (result_id, host_id, check_id, secure, reasons)  in results:
            status = 'OK' if secure else 'KO'
            host = self.db.get_hosts(host_id)[0]._asdict()
            check = checks_dict[check_id]
            row = []
            for column in data[0]:
                if column == 'IP':
                    row.append(host['ip'])
                if column == 'Hostname':
                    row.append(host['hostname'])
                if column == 'Check':
                    row.append(check['name'])
                if column == 'Description':
                    row.append(check['description'])
                if column == 'Status':
                    row.append(status)
                if column == 'Reasons':
                    row.append(reasons)
            data.append(row)

        print_table(data, title="Windows Configuration Checks")

    def help_wcc(self):
        help_string = f"""
        {help_header('USAGE')}
            {help_header('wcc')} [{help_kw('full')}]
            {help_header('wcc')} <{help_kw('ip')}|{help_kw('hostname')}|{help_kw('check')}|{help_kw('description')}|{help_kw('status')}|{help_kw('reasons')}>...

        {help_header('DESCRIPTION')}
            Display Windows Configuration Checks results

            {help_header('wcc')} [{help_kw('full')}]
                If full is provided, display all columns. Otherwise, display IP, Hostname, Check and Status

            {help_header('wcc')} <{help_kw('ip')}|{help_kw('hostname')}|{help_kw('check')}|{help_kw('description')}|{help_kw('status')}|{help_kw('reasons')}>...
                Display only the requested columns (case-insensitive)
            """
        print_help(help_string)

    def help_hosts(self):
        help_string = """
        hosts [dc|spooler|zerologon|petitpotam|filter_term]
        By default prints all hosts
        Table format:
        | 'HostID', 'IP', 'Hostname', 'Domain', 'OS', 'DC', 'SMBv1', 'Signing', 'Spooler', 'Zerologon', 'PetitPotam' |
        Subcommands:
            dc - list all domain controllers
            spooler - list all hosts with Spooler service enabled
            zerologon - list all hosts vulnerable to zerologon
            petitpotam - list all hosts vulnerable to petitpotam
            filter_term - filters hosts with filter_term
                If a single host is returned (e.g. `hosts 15`, it prints the following tables:
                    Host | 'HostID', 'IP', 'Hostname', 'Domain', 'OS', 'DC', 'SMBv1', 'Signing', 'Spooler', 'Zerologon', 'PetitPotam' |
                    Credential(s) with Admin Access | 'CredID', 'CredType', 'Domain', 'UserName', 'Password' |
                Otherwise, it prints the default host table from a `like` query on the `ip` and `hostname` columns
        """
        print_help(help_string)

    def do_dpapi(self, line):
        filter_term = line.strip()

        if filter_term == "":
            secrets = self.db.get_dpapi_secrets()
            secrets.insert(
                0,
                [
                    "ID",
                    "Host",
                    "DPAPI Type",
                    "Windows User",
                    "Username",
                    "Password",
                    "URL",
                ],
            )
            print_table(secrets, title="DPAPI Secrets")
        elif filter_term.split()[0].lower() == "browser":
            secrets = self.db.get_dpapi_secrets(dpapi_type="MSEDGE")
            secrets += self.db.get_dpapi_secrets(dpapi_type="GOOGLE CHROME")
            secrets += self.db.get_dpapi_secrets(dpapi_type="IEX")
            secrets += self.db.get_dpapi_secrets(dpapi_type="FIREFOX")
            if len(secrets) > 0:
                secrets.insert(
                    0,
                    [
                        "ID",
                        "Host",
                        "DPAPI Type",
                        "Windows User",
                        "Username",
                        "Password",
                        "URL",
                    ],
                )
                print_table(secrets, title="DPAPI Secrets")
        elif filter_term.split()[0].lower() == "chrome":
            secrets = self.db.get_dpapi_secrets(dpapi_type="GOOGLE CHROME")
            if len(secrets) > 0:
                secrets.insert(
                    0,
                    [
                        "ID",
                        "Host",
                        "DPAPI Type",
                        "Windows User",
                        "Username",
                        "Password",
                        "URL",
                    ],
                )
                print_table(secrets, title="DPAPI Secrets")
        elif filter_term.split()[0].lower() == "msedge":
            secrets = self.db.get_dpapi_secrets(dpapi_type="MSEDGE")
            if len(secrets) > 0:
                secrets.insert(
                    0,
                    [
                        "ID",
                        "Host",
                        "DPAPI Type",
                        "Windows User",
                        "Username",
                        "Password",
                        "URL",
                    ],
                )
                print_table(secrets, title="DPAPI Secrets")
        elif filter_term.split()[0].lower() == "credentials":
            secrets = self.db.get_dpapi_secrets(dpapi_type="CREDENTIAL")
            if len(secrets) > 0:
                secrets.insert(
                    0,
                    [
                        "ID",
                        "Host",
                        "DPAPI Type",
                        "Windows User",
                        "Username",
                        "Password",
                        "URL",
                    ],
                )
                print_table(secrets, title="DPAPI Secrets")
        elif filter_term.split()[0].lower() == "iex":
            secrets = self.db.get_dpapi_secrets(dpapi_type="IEX")
            if len(secrets) > 0:
                secrets.insert(
                    0,
                    [
                        "ID",
                        "Host",
                        "DPAPI Type",
                        "Windows User",
                        "Username",
                        "Password",
                        "URL",
                    ],
                )
                print_table(secrets, title="DPAPI Secrets")
        elif filter_term.split()[0].lower() == "firefox":
            secrets = self.db.get_dpapi_secrets(dpapi_type="FIREFOX")
            if len(secrets) > 0:
                secrets.insert(
                    0,
                    [
                        "ID",
                        "Host",
                        "DPAPI Type",
                        "Windows User",
                        "Username",
                        "Password",
                        "URL",
                    ],
                )
                print_table(secrets, title="DPAPI Secrets")
        else:
            secrets = self.db.get_dpapi_secrets(filter_term=filter_term)
            if len(secrets) > 0:
                secrets.insert(
                    0,
                    [
                        "ID",
                        "Host",
                        "DPAPI Type",
                        "Windows User",
                        "Username",
                        "Password",
                        "URL",
                    ],
                )
                print_table(secrets, title="DPAPI Secrets")

    def help_dpapi(self):
        help_string = """
        dpapi [browser|chrome|msedge|credentials|iex|firefox|filter_term]
        By default prints all dpapi dumped secrets
        Table format:
        | 'ID', 'Host', 'DPAPI Type', 'Windows User', 'Username', 'Password', 'URL' |
        Subcommands:
            browser - list all secrets dumped from browser
            chrome - list all secrets dumped from chrome
            msedge - list all secrets dumped from microsoft edge
            credentials - list all secrets dumped from credential manager (user and system)
            iex - list all secrets dumped from Internet Explorer
            firefox - list all secrets dumped from Firefox
            filter_term - filters dpapi secrets with filter_term
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
                    cred_id_list.append(cred[0])
                    data.append([cred[0], cred[4], cred[5], cred[1], cred[2], cred[3]])

                print_table(data, title="Credential(s)")

                data = [["GroupID", "Domain", "Name"]]
                for cred_id in cred_id_list:
                    links = self.db.get_group_relations(user_id=cred_id)

                    for link in links:
                        link_id, user_id, group_id = link
                        groups = self.db.get_groups(group_id)

                        for group in groups:
                            group_id = group[0]
                            domain = group[1]
                            name = group[2]
                            data.append([group_id, domain, name])

                print_table(data, title="Member of Group(s)")

                data = [["HostID", "IP", "Hostname", "Domain", "OS"]]
                for cred_id in cred_id_list:
                    links = self.db.get_admin_relations(user_id=cred_id)

                    for link in links:
                        link_id, cred_id, host_id = link
                        hosts = self.db.get_hosts(host_id)

                        for host in hosts:
                            data.append([host[0], host[1], host[2], host[3], host[4]])

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
        if input("This will destroy all data in the current database, are you SURE you" " want to run this? (y/n): ") == "y":
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
        Tab-complete 'hosts' commands.
        """
        commands = ("add", "remove", "dc")

        mline = line.partition(" ")[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]

    def complete_creds(self, text, line):
        """
        Tab-complete 'creds' commands.
        """
        commands = ("add", "remove", "hash", "plaintext")

        mline = line.partition(" ")[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]
