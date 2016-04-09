import cmd
import sqlite3
import sys
import os
from core.database import CMEDatabase

class CMEDatabaseNavigator(cmd.Cmd):

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = 'cmedb > '
        try:
            # set the database connectiont to autocommit w/ isolation level
            conn = sqlite3.connect('data/cme.db', check_same_thread=False)
            conn.text_factory = str
            conn.isolation_level = None
            self.db = CMEDatabase(conn)
        except Exception as e:
            print "Could not connect to database: {}".format(e)
            sys.exit(1)

    def do_exit(self, line):
        sys.exit(0)

    def do_host(self, line):

        if not line:
            return

        hosts = self.db.get_hosts(line)

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
                creds = self.db.get_credentials(credID)

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

    def do_cred(self, line):

        if not line:
            return

        creds = self.db.get_credentials(line)

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

            print u"  {}{}{}{}{}".format('{:<8}'.format(credID), 
                                         '{:<12}'.format(credType), 
                                         u'{:<17}'.format(domain.decode('utf-8')), 
                                         u'{:<21}'.format(username.decode('utf-8')), 
                                         u'{:<17}'.format(password.decode('utf-8')))

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

    def do_hosts(self, line):

        hosts = self.db.get_hosts()
        
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

    def do_creds(self, line):
        
        creds = self.db.get_credentials()

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

if __name__ == '__main__':

    if not os.path.exists('data/cme.db'):
        print 'Could not find CME database, did you run the setup_database.py script?'
        sys.exit(1)

    try:
        cmedbnav = CMEDatabaseNavigator()
        cmedbnav.cmdloop()
    except KeyboardInterrupt:
        pass