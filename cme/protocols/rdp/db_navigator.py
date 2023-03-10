#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cme.cmedb import DatabaseNavigator


class navigator(DatabaseNavigator):
    def do_clear_database(self, line):
        if input("This will destroy all data in the current database, are you SURE you want to run this? (y/n): ") == "y":
            self.db.clear_database()
