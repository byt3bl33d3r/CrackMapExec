import cmd
import sqlite3
import sys

class CMEDatabaseNavigator(cmd.Cmd):

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = 'cmedb > '
        try:
            # set the database connectiont to autocommit w/ isolation level
            self.conn = sqlite3.connect('data/cme.db', check_same_thread=False)
            self.conn.text_factory = str
            self.conn.isolation_level = None
        except Exception as e:
            print "Could not connect to database: {}".format(e)
            sys.exit(1)

    def do_exit(self, line):
        sys.exit(0)

    def do_hosts(self, line):

        cur = self.conn.cursor()
        cur.execute("SELECT * FROM hosts")
        hosts = cur.fetchall()
        cur.close()

        print "\nHosts:\n"
        print "  HostID  IP               Hostname                 Domain           OS"
        print "  ------  --               --------                 ------           --"

        for host in hosts:
            # (id, ip, hostname, domain, os)
            hostID = host[0]
            ip = host[1]
            hostname = host[2]
            domain = host[3]
            os = host[4]

            print u"  {}{}{}{}{}".format('{0: <8}'.format(hostID), '{0: <17}'.format(ip), '{0: <25}'.format(hostname), '{0: <17}'.format(domain), '{0: <17}'.format(os))

        print ""

    def do_creds(self, line):
        
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM credentials")
        creds = cur.fetchall()
        cur.close()

        print "\nCredentials:\n"
        print "  CredID  CredType   Domain                   UserName         Password"
        print "  ------  --------   ------                   --------         --------"

        for cred in creds:
            # (id, credtype, domain, username, password, host, notes, sid)
            credID = cred[0]
            credType = cred[1]
            domain = cred[2]
            username = cred[3]
            password = cred[4]

            print u"  {}{}{}{}{}".format('{0: <8}'.format(credID), '{0: <11}'.format(credType), '{0: <25}'.format(domain), '{0: <17}'.format(username), '{0: <17}'.format(password))

        print ""

if __name__ == '__main__':
    cmedbnav = CMEDatabaseNavigator()
    cmedbnav.cmdloop()