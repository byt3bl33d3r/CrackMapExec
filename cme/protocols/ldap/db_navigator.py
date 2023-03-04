#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cme.cmedb import DatabaseNavigator


class navigator(DatabaseNavigator):
    def do_clear_database(self, line):
        self.db.clear_database()
