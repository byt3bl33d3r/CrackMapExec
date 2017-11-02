from cme.cmedb import DatabaseNavigator


class navigator(DatabaseNavigator):

    def display_creds(self, creds):
        data = [['CredID', 'URL', 'UserName', 'Password']]
        for cred in creds:
            credID = cred[0]
            url = cred[2]
            username = cred[3]
            password = cred[4]

            # links = self.db.get_links(credID=credID)

            data.append([credID, url.decode('utf-8'), username.decode('utf-8'), password.decode('utf-8')])

        self.print_table(data, title='Credential(s)')

    def display_hosts(self, hosts):
        # print "\nHosts:\n"
        # print "  HostID  IP        Hostname     Port   Title URL"
        return

    def do_creds(self, line):

        filterTerm = line.strip()

        if filterTerm == "":
            creds = self.db.get_credentials()
            self.display_creds(creds)

        elif filterTerm.split()[0].lower() == "add":

            args = filterTerm.split()[1:]

            if len(args) == 3:
                url, username, password = args
                self.db.add_credential(url, username, password)

            else:
                print "[!] Format is 'add url username password"
                return

        elif filterTerm.split()[0].lower() == "remove":

            args = filterTerm.split()[1:]
            if len(args) != 1 :
                print "[!] Format is 'remove <credID>'"
                return
            else:
                self.db.remove_credentials(args)
                self.db.remove_links(credIDs=args)

        else:
            creds = self.db.get_credentials(filterTerm=filterTerm)
            self.display_creds(creds)

    def do_hosts(self, line):

        filterTerm = line.strip()

        if filterTerm == "":
            creds = self.db.get_hosts()
            self.display_creds(creds)

        elif filterTerm.split()[0].lower() == "add":

            args = filterTerm.split()[1:]

            if len(args) == 3:
                return
                # url, username, password = args
                # self.db.add_host()

            else:
                print "[!] Format is 'add url ip hostname port"
                return

        elif filterTerm.split()[0].lower() == "remove":

            args = filterTerm.split()[1:]
            if len(args) != 1 :
                print "[!] Format is 'remove <hostID>'"

            return
            # self.db.remove_host()

        else:
            hosts = self.db.get_hosts(filterTerm=filterTerm)
            self.display_hosts(hosts)

    def complete_creds(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."

        commands = ["add", "remove"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]

    def complete_hosts(self, text, line, begidx, endidx):
        "Tab-complete 'hosts' commands."

        commands = ["add", "remove"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]
