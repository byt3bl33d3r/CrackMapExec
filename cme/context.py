#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import os


class Context:
    def __init__(self, db, logger, args):
        for key, value in vars(args).items():
            setattr(self, key, value)

        self.db = db
        self.log_folder_path = os.path.join(os.path.expanduser("~/.cme"), "logs")
        self.localip = None

        self.conf = configparser.ConfigParser()
        self.conf.read(os.path.expanduser("~/.cme/cme.conf"))

        self.log = logger
        # self.log.debug = logging.debug
