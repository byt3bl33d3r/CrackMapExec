import logging

class Context:

    def __init__(self, db, logger, arg_namespace):
        self.db = db
        self.log = logger
        self.log.debug = logging.debug
        self.localip = None

        for key, value in vars(arg_namespace).iteritems():
            setattr(self, key, value)