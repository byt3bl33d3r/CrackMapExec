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

    def display_hosts(self, hosts):

        data = [['HostID', 'Admins', 'IP', 'Hostname', 'Domain', 'OS', 'DB Instances']]

        for host in hosts:

            hostID = host[0]
            ip = host[1]
            hostname = host[2]
            domain = host[3]
            os = host[4]
            instances = host[5]

            links = self.db.get_admin_relations(hostID=hostID)

            data.append([hostID, str(len(links)) + ' Cred(s)', ip, hostname, domain, os, instances])

        self.print_table(data, title='Hosts')

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
                data = [['HostID', 'IP', 'Hostname', 'Domain', 'OS']]
                hostIDList = []

                for host in hosts:
                    hostID = host[0]
                    hostIDList.append(hostID)

                    ip = host[1]
                    hostname = host[2]
                    domain = host[3]
                    os = host[4]

                    data.append([hostID, ip, hostname, domain, os])

                self.print_table(data, title='Host(s)')

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
                self.db.remove_links(credIDs=args)

        elif filterTerm.split()[0].lower() == "plaintext":
            creds = self.db.get_credentials(credtype="plaintext")
            self.display_creds(creds)

        elif filterTerm.split()[0].lower() == "hash":
            creds = self.db.get_credentials(credtype="hash")
            self.display_creds(creds)

        else:
            creds = self.db.get_credentials(filterTerm=filterTerm)

            data = [['CredID', 'CredType', 'Domain', 'UserName', 'Password']]
            credIDList = []

            for cred in creds:
                credID = cred[0]
                credIDList.append(credID)

                credType = cred[1]
                domain = cred[2]
                username = cred[3]
                password = cred[4]

                data.append([credID, credType, domain, username, password])

            self.print_table(data, title='Credential(s)')

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

        commands = ["add", "remove"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]

    def complete_creds(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."

        commands = ["add", "remove", "hash", "plaintext"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]
