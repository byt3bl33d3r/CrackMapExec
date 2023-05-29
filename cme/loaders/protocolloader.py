#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from types import ModuleType
from importlib.machinery import SourceFileLoader
from os import listdir
from os.path import join as path_join
from os.path import dirname, exists, expanduser
import cme


class ProtocolLoader:
    def __init__(self):
        self.cme_path = expanduser("~/.cme")

    def load_protocol(self, protocol_path):
        loader = SourceFileLoader("protocol", protocol_path)
        protocol = ModuleType(loader.name)
        loader.exec_module(protocol)
        return protocol

    def get_protocols(self):
        protocols = {}
        protocol_paths = [
            path_join(dirname(cme.__file__), "protocols"),
            path_join(self.cme_path, "protocols"),
        ]

        for path in protocol_paths:
            for protocol in listdir(path):
                if protocol[-3:] == ".py" and protocol[:-3] != "__init__":
                    protocol_path = path_join(path, protocol)
                    protocol_name = protocol[:-3]

                    protocols[protocol_name] = {"path": protocol_path}

                    db_file_path = path_join(path, protocol_name, "database.py")
                    db_nav_path = path_join(path, protocol_name, "db_navigator.py")
                    protocol_args_path = path_join(path, protocol_name, "proto_args.py")
                    if exists(db_file_path):
                        protocols[protocol_name]["dbpath"] = db_file_path
                    if exists(db_nav_path):
                        protocols[protocol_name]["nvpath"] = db_nav_path
                    if exists(protocol_args_path):
                        protocols[protocol_name]["argspath"] = protocol_args_path

        return protocols
