import cmd
from cme.protocols.ssh.database import database
from cme.cmedb import UserExitedProto

class navigator(cmd.Cmd):
    def __init__(self, main_menu):
        cmd.Cmd.__init__(self)

        self.main_menu = main_menu
        self.config = main_menu.config
        self.db = database(main_menu.conn)
        self.prompt = 'cmedb ({})({}) > '.format(main_menu.workspace, 'ssh')

    def do_back(self, line):
        raise UserExitedProto