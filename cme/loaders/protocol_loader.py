#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import types
from importlib.machinery import SourceFileLoader
import os
import cme


class protocol_loader:
    def __init__(self):
        self.cme_path = os.path.expanduser('~/.cme')

    def load_protocol(self, protocol_path):
        loader = SourceFileLoader('protocol', protocol_path)
        protocol = types.ModuleType(loader.name)
        loader.exec_module(protocol)
        #if self.module_is_sane(module, module_path):
        return protocol

    def get_protocols(self):
        protocols = {}

        protocol_paths = [os.path.join(os.path.dirname(cme.__file__), 'protocols'), os.path.join(self.cme_path, 'protocols')]

        for path in protocol_paths:
            for protocol in os.listdir(path):
                if protocol[-3:] == '.py' and protocol[:-3] != '__init__':
                    protocol_path = os.path.join(path, protocol)
                    protocol_name = protocol[:-3]

                    protocols[protocol_name] = {'path': protocol_path}

                    db_file_path = os.path.join(path, protocol_name, 'database.py')
                    db_nav_path = os.path.join(path, protocol_name, 'db_navigator.py')
                    if os.path.exists(db_file_path):
                        protocols[protocol_name]['dbpath'] = db_file_path
                    if os.path.exists(db_nav_path):
                        protocols[protocol_name]['nvpath'] = db_nav_path

        return protocols
