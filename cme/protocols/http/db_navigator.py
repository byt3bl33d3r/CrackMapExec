import cmd
from cme.protocols.http.database import database

class navigator(cmd.Cmd):
    def __init__(self, main_menu):
        cmd.Cmd.__init__(self)

        self.main_menu = main_menu
        self.config = main_menu.config
        self.db = database(main_menu.conn)
        self.prompt = 'cmedb ({})({}) > '.format(main_menu.workspace, 'http')

    def do_back(self, line):
        raise

    def display_creds(self, creds):

        print "\nCredentials:\n"
        print "  CredID  URL              UserName             Password"
        print "  ------  ---              --------             --------"

        for cred in creds:
            credID = cred[0]
            url = cred[2]
            username = cred[3]
            password = cred[4]

            links = self.db.get_links(credID=credID)

            print u"  {}{}{}{}{}{}".format('{:<8}'.format(credID),
                                           u'{:<17}'.format(url.decode('utf-8')),
                                           u'{:<21}'.format(username.decode('utf-8')),
                                           u'{:<17}'.format(password.decode('utf-8')))

        print ""

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
            elf.display_credsI(creds)

    def complete_creds(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."

        commands = [ "add", "remove"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]
