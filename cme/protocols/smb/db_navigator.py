from cme.helpers.misc import validate_ntlm
from cme.cmedb import DatabaseNavigator


class navigator(DatabaseNavigator):

    def display_creds(self, creds):

        data = [['CredID', 'Admin On', 'CredType', 'Domain', 'UserName', 'Password']]

        for cred in creds:

            credID = cred[0]
            domain = cred[1]
            username = cred[2]
            password = cred[3]
            credtype = cred[4]
            # pillaged_from = cred[5]

            links = self.db.get_admin_relations(userID=credID)

            data.append([credID, str(len(links)) + ' Host(s)', credtype, domain, username, password])

        self.print_table(data, title='Credentials')

    def display_groups(self, groups):

        data = [['GroupID', 'Domain', 'Name', 'Members']]

        for group in groups:
            groupID = group[0]
            domain = group[1]
            name = group[2]
            members = len(self.db.get_group_relations(groupID=groupID))

            data.append([groupID, domain, name, members])

        self.print_table(data, title='Groups')

    def display_hosts(self, hosts):

        data = [['HostID', 'Admins', 'IP', 'Hostname', 'Domain', 'OS']]

        for host in hosts:

            hostID = host[0]
            ip = host[1]
            hostname = host[2]
            domain = host[3]
            try:
                os = host[4].decode()
            except:
                os = host[4]

            links = self.db.get_admin_relations(hostID=hostID)

            data.append([hostID, str(len(links)) + ' Cred(s)', ip, hostname, domain, os])

        self.print_table(data, title='Hosts')
    
    def display_shares(self, shares):

        data = [["ShareID", "Name", "Remark", "Read Access", "Write Access"]]

        for share in shares:
            
            shareID = share[0]
            computerid = share[1]
            name = share[3]
            remark = share[4]

            users_r_access = self.db.get_users_with_share_access(
                computerID=computerid,
                share_name=name,
                permissions='r'
            )

            users_w_access = self.db.get_users_with_share_access(
                computerID=computerid,
                share_name=name,
                permissions='w'
            )

            data.append([shareID, name, remark, f"{len(users_r_access)} User(s)", f"{len(users_w_access)} Users"])

        self.print_table(data)

    def do_shares(self, line):
        filterTerm = line.strip()

        if filterTerm == "":
            shares = self.db.get_shares()
            self.display_shares(shares)
        else:
            shares = self.db.get_shares(filterTerm=filterTerm)

            if len(shares) > 1:
                self.display_shares(shares)
            elif len(shares) == 1:
                share = shares[0]
                shareID = share[0]
                computerID = share[1]
                name = share[3]
                remark = share[4]

                users_r_access = self.db.get_users_with_share_access(
                    computerID=computerID,
                    share_name=name,
                    permissions='r'
                )

                users_w_access = self.db.get_users_with_share_access(
                    computerID=computerID,
                    share_name=name,
                    permissions='w'
                )

                data = [["ShareID", "Name", "Remark"]]

                data.append([shareID, name, remark])
            
                self.print_table(data, title='Share')

                host = self.db.get_computers(filterTerm=computerID)[0]

                data = [['HostID', 'IP', 'Hostname', 'Domain', 'OS', 'DC']]
  
                hostID = host[0]

                ip = host[1]
                hostname = host[2]
                domain = host[3]
                os = host[4]
                dc = host[5]

                data.append([hostID, ip, hostname, domain, os, dc])

                self.print_table(data, title='Share Location')

                if users_r_access:
                    data = [['CredID', 'CredType', 'Domain', 'UserName', 'Password']]
                    for user in users_r_access:
                        userid = user[0]
                        creds = self.db.get_credentials(filterTerm=userid)

                        for cred in creds:
                            credID = cred[0]
                            domain = cred[1]
                            username = cred[2]
                            password = cred[3]
                            credtype = cred[4]

                            data.append([credID, credtype, domain, username, password])

                    self.print_table(data, title='Users(s) with Read Access')

                if users_w_access:
                    data = [['CredID', 'CredType', 'Domain', 'UserName', 'Password']]
                    for user in users_w_access:
                        userid = user[0]
                        creds = self.db.get_credentials(filterTerm=userid)

                        for cred in creds:
                            credID = cred[0]
                            domain = cred[1]
                            username = cred[2]
                            password = cred[3]
                            credtype = cred[4]

                            data.append([credID, credtype, domain, username, password])

                    self.print_table(data, title='Users(s) with Write Access')


    def do_groups(self, line):

        filterTerm = line.strip()

        if filterTerm == "":
            groups = self.db.get_groups()
            self.display_groups(groups)

        else:
            groups = self.db.get_groups(filterTerm=filterTerm)

            if len(groups) > 1:
                self.display_groups(groups)
            elif len(groups) == 1:

                data = [['GroupID', 'Domain', 'Name']]

                for group in groups:
                    groupID = group[0]
                    domain = group[1]
                    name = group[2]

                    data.append([groupID, domain, name])

                self.print_table(data, title='Group')

                data = [['CredID', 'CredType', 'Pillaged From HostID', 'Domain', 'UserName', 'Password']]

                for group in groups:
                    members = self.db.get_group_relations(groupID=group[0])

                    for member in members:
                        _,userid,_ = member
                        creds = self.db.get_credentials(filterTerm=userid)

                        for cred in creds:
                            credID = cred[0]
                            domain = cred[1]
                            username = cred[2]
                            password = cred[3]
                            credtype = cred[4]
                            pillaged_from = cred[5]

                            data.append([credID, credtype, pillaged_from, domain, username, password])

                self.print_table(data, title='Member(s)')

    def do_hosts(self, line):

        filterTerm = line.strip()

        if filterTerm == "":
            hosts = self.db.get_computers()
            self.display_hosts(hosts)
        else:
            hosts = self.db.get_computers(filterTerm=filterTerm)

            if len(hosts) > 1:
                self.display_hosts(hosts)
            elif len(hosts) == 1:
                data = [['HostID', 'IP', 'Hostname', 'Domain', 'OS', 'DC']]
                hostIDList = []

                for host in hosts:
                    hostID = host[0]
                    hostIDList.append(hostID)

                    ip = host[1]
                    hostname = host[2]
                    domain = host[3]
                    os = host[4]
                    dc = host[5]

                    data.append([hostID, ip, hostname, domain, os, dc])

                self.print_table(data, title='Host')

                data = [['CredID', 'CredType', 'Domain', 'UserName', 'Password']]
                for hostID in hostIDList:
                    links = self.db.get_admin_relations(hostID=hostID)

                    for link in links:
                        linkID, credID, hostID = link
                        creds = self.db.get_credentials(filterTerm=credID)

                        for cred in creds:
                            credID = cred[0]
                            domain = cred[1]
                            username = cred[2]
                            password = cred[3]
                            credtype = cred[4]
                            # pillaged_from = cred[5]

                            data.append([credID, credtype, domain, username, password])

                self.print_table(data, title='Credential(s) with Admin Access')

    def do_creds(self, line):

        filterTerm = line.strip()

        if filterTerm == "":
            creds = self.db.get_credentials()
            self.display_creds(creds)

        elif filterTerm.split()[0].lower() == "add":

            # add format: "domain username password <notes> <credType> <sid>
            args = filterTerm.split()[1:]

            if len(args) == 3:
                domain, username, password = args
                if validate_ntlm(password):
                    self.db.add_credential("hash", domain, username, password)
                else:
                    self.db.add_credential("plaintext", domain, username, password)

            else:
                print("[!] Format is 'add domain username password")
                return

        elif filterTerm.split()[0].lower() == "remove":

            args = filterTerm.split()[1:]
            if len(args) != 1:
                print("[!] Format is 'remove <credID>'")
                return
            else:
                self.db.remove_credentials(args)
                self.db.remove_admin_relation(userIDs=args)

        elif filterTerm.split()[0].lower() == "plaintext":
            creds = self.db.get_credentials(credtype="plaintext")
            self.display_creds(creds)

        elif filterTerm.split()[0].lower() == "hash":
            creds = self.db.get_credentials(credtype="hash")
            self.display_creds(creds)

        else:
            creds = self.db.get_credentials(filterTerm=filterTerm)
            if len(creds) != 1:
                self.display_creds(creds)
            elif len(creds) == 1:
                data = [['CredID', 'CredType', 'Pillaged From HostID', 'Domain', 'UserName', 'Password']]
                credIDList = []

                for cred in creds:
                    credID = cred[0]
                    credIDList.append(credID)

                    domain = cred[1]
                    username = cred[2]
                    password = cred[3]
                    credtype = cred[4]
                    pillaged_from = cred[5]

                    data.append([credID, credtype, pillaged_from, domain, username, password])

                self.print_table(data, title='Credential(s)')

                data = [['GroupID', 'Domain', 'Name']]
                for credID in credIDList:
                    links = self.db.get_group_relations(userID=credID)

                    for link in links:
                        linkID, userID, groupID = link
                        groups = self.db.get_groups(groupID)

                        for group in groups:
                            groupID = group[0]
                            domain = group[1]
                            name = group[2]

                            data.append([groupID, domain, name])

                self.print_table(data, title='Member of Group(s)')

                data = [['HostID', 'IP', 'Hostname', 'Domain', 'OS']]
                for credID in credIDList:
                    links = self.db.get_admin_relations(userID=credID)

                    for link in links:
                        linkID, credID, hostID = link
                        hosts = self.db.get_computers(hostID)

                        for host in hosts:
                            hostID = host[0]
                            ip = host[1]
                            hostname = host[2]
                            domain = host[3]
                            os = host[4]

                            data.append([hostID, ip, hostname, domain, os])

                self.print_table(data, title='Admin Access to Host(s)')

    def complete_hosts(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."

        commands = ["add", "remove", "dc"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]

    def complete_creds(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."

        commands = ["add", "remove", "hash", "plaintext"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]
