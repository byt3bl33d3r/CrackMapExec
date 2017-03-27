import cmd
from cme.protocols.mssql.database import database
from cme.cmedb import UserExitedProto

class navigator(cmd.Cmd):
    def __init__(self, main_menu):
        cmd.Cmd.__init__(self)

        self.main_menu = main_menu
        self.config = main_menu.config
        self.db = database(main_menu.conn)
        self.prompt = 'cmedb ({})({}) > '.format(main_menu.workspace, 'mssql')

    def do_back(self, line):
        raise UserExitedProto

    def display_creds(self, creds):

        print "\nCredentials:\n"
        print "  CredID  Admin On     CredType    Domain           UserName             Password"
        print "  ------  --------     --------    ------           --------             --------"

        for cred in creds:
            # (id, credtype, domain, username, password, host, notes, sid)
            credID = cred[0]
            credType = cred[1]
            domain = cred[2]
            username = cred[3]
            password = cred[4]

            links = self.db.get_links(credID=credID)

            print u"  {}{}{}{}{}{}".format('{:<8}'.format(credID),
                                           '{:<13}'.format(str(len(links)) + ' Host(s)'),
                                           '{:<12}'.format(credType),
                                           u'{:<17}'.format(domain.decode('utf-8')),
                                           u'{:<21}'.format(username.decode('utf-8')),
                                           u'{:<17}'.format(password.decode('utf-8')))

        print ""

    def display_hosts(self, hosts):

        print "\nHosts:\n"
        print "  HostID  Admins         IP               Hostname                 Domain           OS"
        print "  ------  ------         --               --------                 ------           --"

        for host in hosts:
            # (id, ip, hostname, domain, os)
            hostID = host[0]
            ip = host[1]
            hostname = host[2]
            domain = host[3]
            os = host[4]

            links = self.db.get_links(hostID=hostID)

            print u"  {}{}{}{}{}{}".format('{:<8}'.format(hostID),
                                           '{:<15}'.format(str(len(links)) + ' Cred(s)'),
                                           '{:<17}'.format(ip),
                                           u'{:<25}'.format(hostname.decode('utf-8')),
                                           u'{:<17}'.format(domain.decode('utf-8')),
                                           '{:<17}'.format(os))

        print ""

    def do_hosts(self, line):

        filterTerm = line.strip()

        if filterTerm == "":
            hosts = self.db.get_hosts()
            self.display_hosts(hosts)

        else:
            hosts = self.db.get_hosts(filterTerm=filterTerm)

            if len(hosts) > 1:
                self.display_hosts(hosts)
            elif len(hosts) == 1:
                print "\nHost(s):\n"
                print "  HostID  IP               Hostname                 Domain           OS"
                print "  ------  --               --------                 ------           --"

                hostIDList = []

                for host in hosts:
                    hostID = host[0]
                    hostIDList.append(hostID)

                    ip = host[1]
                    hostname = host[2]
                    domain = host[3]
                    os = host[4]

                    print u"  {}{}{}{}{}".format('{:<8}'.format(hostID),
                                                 '{:<17}'.format(ip),
                                                 u'{:<25}'.format(hostname.decode('utf-8')),
                                                 u'{:<17}'.format(domain.decode('utf-8')),
                                                 '{:<17}'.format(os))

                print ""

                print "\nCredential(s) with Admin Access:\n"
                print "  CredID  CredType    Domain           UserName             Password"
                print "  ------  --------    ------           --------             --------"

                for hostID in hostIDList:
                    links = self.db.get_links(hostID=hostID)

                    for link in links:
                        linkID, credID, hostID = link
                        creds = self.db.get_credentials(filterTerm=credID)

                        for cred in creds:
                            credID = cred[0]
                            credType = cred[1]
                            domain = cred[2]
                            username = cred[3]
                            password = cred[4]

                            print u"  {}{}{}{}{}".format('{:<8}'.format(credID),
                                                        '{:<12}'.format(credType),
                                                        u'{:<17}'.format(domain.decode('utf-8')),
                                                        u'{:<21}'.format(username.decode('utf-8')),
                                                        u'{:<17}'.format(password.decode('utf-8')))

                print ""

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
                print "[!] Format is 'add domain username password"
                return

        elif filterTerm.split()[0].lower() == "remove":

            args = filterTerm.split()[1:]
            if len(args) != 1 :
                print "[!] Format is 'remove <credID>'"
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

            print "\nCredential(s):\n"
            print "  CredID  CredType    Domain           UserName             Password"
            print "  ------  --------    ------           --------             --------"

            credIDList = []

            for cred in creds:
                credID = cred[0]
                credIDList.append(credID)

                credType = cred[1]
                domain = cred[2]
                username = cred[3]
                password = cred[4]

                print u"  {}{}{}{}{}{}".format('{:<8}'.format(credID),
                                              '{:<12}'.format(credType),
                                              u'{:<22}'.format(domain.decode('utf-8')),
                                              u'{:<21}'.format(username.decode('utf-8')),
                                              u'{:<17}'.format(password.decode('utf-8'))
                                              )

            print ""

            print "\nAdmin Access to Host(s):\n"
            print "  HostID  IP               Hostname                 Domain           OS"
            print "  ------  --               --------                 ------           --"

            for credID in credIDList:
                links = self.db.get_links(credID=credID)

                for link in links:
                    linkID, credID, hostID =  link
                    hosts = self.db.get_hosts(hostID)

                    for host in hosts:
                        hostID = host[0]
                        ip = host[1]
                        hostname = host[2]
                        domain = host[3]
                        os = host[4]

                        print u"  {}{}{}{}{}".format('{:<8}'.format(hostID),
                                                     '{:<17}'.format(ip),
                                                     u'{:<25}'.format(hostname.decode('utf-8')),
                                                     u'{:<17}'.format(domain.decode('utf-8')),
                                                     '{:<17}'.format(os))

            print ""

    def complete_creds(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."

        commands = [ "add", "remove", "hash", "plaintext"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]
