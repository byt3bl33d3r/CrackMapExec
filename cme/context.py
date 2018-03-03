import logging
import os
from ConfigParser import ConfigParser


class Context:

    def __init__(self, db, logger, args):
        self.db = db
        self.log = logger
        self.log.debug = logging.debug
        self.log_folder_path = os.path.join(os.path.expanduser('~/.cme'), 'logs')
        self.target = None

        self.conf = ConfigParser()
        self.conf.read(os.path.expanduser('~/.cme/cme.conf'))

        for key, value in vars(args).iteritems():
            setattr(self, key, value)
