import logging
import os
import configparser

class Context:

    def __init__(self, db, logger, args):
        self.db = db
        self.log = logger
        self.log.debug = logging.debug
        self.log_folder_path = os.path.join(os.path.expanduser('~/.cme'), 'logs')
        self.localip = None

        self.conf = configparser.ConfigParser()
        self.conf.read(os.path.expanduser('~/.cme/cme.conf'))

        for key, value in vars(args).items():
            setattr(self, key, value)
