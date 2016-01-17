#!/usr/bin/python
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: [MS-TDS] & [MC-SQLR] example.
#
# Author:
#  Alberto Solino (beto@coresecurity.com/@agsolino)
#
# Reference for:
#  Structure
#

import os
import cmd
from impacket import tds
from impacket.tds import SQLErrorException, TDS_LOGINACK_TOKEN, TDS_ERROR_TOKEN, TDS_ENVCHANGE_TOKEN, TDS_INFO_TOKEN, \
    TDS_ENVCHANGE_VARCHAR, TDS_ENVCHANGE_DATABASE, TDS_ENVCHANGE_LANGUAGE, TDS_ENVCHANGE_CHARSET, TDS_ENVCHANGE_PACKETSIZE

def printRepliesCME(self):
    for keys in self.replies.keys():
        for i, key in enumerate(self.replies[keys]):
            if key['TokenType'] == TDS_ERROR_TOKEN:
                error =  "ERROR(%s): Line %d: %s" % (key['ServerName'].decode('utf-16le'), key['LineNumber'], key['MsgText'].decode('utf-16le'))                                      
                self.lastError = SQLErrorException("ERROR: Line %d: %s" % (key['LineNumber'], key['MsgText'].decode('utf-16le')))
                self._MSSQL__rowsPrinter.error(error)

            elif key['TokenType'] == TDS_INFO_TOKEN:
                self._MSSQL__rowsPrinter.info("INFO(%s): Line %d: %s" % (key['ServerName'].decode('utf-16le'), key['LineNumber'], key['MsgText'].decode('utf-16le')))

            elif key['TokenType'] == TDS_LOGINACK_TOKEN:
                self._MSSQL__rowsPrinter.info("ACK: Result: %s - %s (%d%d %d%d) " % (key['Interface'], key['ProgName'].decode('utf-16le'), key['MajorVer'], key['MinorVer'], key['BuildNumHi'], key['BuildNumLow']))

            elif key['TokenType'] == TDS_ENVCHANGE_TOKEN:
                if key['Type'] in (TDS_ENVCHANGE_DATABASE, TDS_ENVCHANGE_LANGUAGE, TDS_ENVCHANGE_CHARSET, TDS_ENVCHANGE_PACKETSIZE):
                    record = TDS_ENVCHANGE_VARCHAR(key['Data'])
                    if record['OldValue'] == '':
                        record['OldValue'] = 'None'.encode('utf-16le')
                    elif record['NewValue'] == '':
                        record['NewValue'] = 'None'.encode('utf-16le')
                    if key['Type'] == TDS_ENVCHANGE_DATABASE:
                        _type = 'DATABASE'
                    elif key['Type'] == TDS_ENVCHANGE_LANGUAGE:
                        _type = 'LANGUAGE'
                    elif key['Type'] == TDS_ENVCHANGE_CHARSET:
                        _type = 'CHARSET'
                    elif key['Type'] == TDS_ENVCHANGE_PACKETSIZE:
                        _type = 'PACKETSIZE'
                    else:
                        _type = "%d" % key['Type']                 
                    self._MSSQL__rowsPrinter.info("ENVCHANGE(%s): Old Value: %s, New Value: %s" % (_type,record['OldValue'].decode('utf-16le'), record['NewValue'].decode('utf-16le')))

tds.MSSQL.printReplies = printRepliesCME

class SQLSHELL(cmd.Cmd):
    def __init__(self, SQL, logger):
        cmd.Cmd.__init__(self)
        self.sql = SQL
        self.logger = logger
        self.prompt = 'SQL> '
        self.intro = '[!] Press help for extra shell commands'

    def do_help(self, line):
        print """
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 enable_xp_cmdshell         - you know what it means
 disable_xp_cmdshell        - you know what it means
 xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
 ! {cmd}                    - executes a local shell cmd
 """ 

    def do_shell(self, s):
        os.system(s)

    def do_xp_cmdshell(self, s):
        try:
            self.sql.sql_query("exec master..xp_cmdshell '%s'" % s)
            self.sql.printReplies()
            self.sql.colMeta[0]['TypeData'] = 80*2
            self.sql.printRows()
        except:
            pass

    def do_lcd(self, s):
        if s == '':
            print os.getcwd()
        else:
            os.chdir(s)

    def do_enable_xp_cmdshell(self, line):
        try:
            self.sql.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
            self.sql.printReplies()
            self.sql.printRows()
        except:
            pass

    def do_disable_xp_cmdshell(self, line):
        try:
            self.sql.sql_query("exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure 'show advanced options', 0 ;RECONFIGURE;")
            self.sql.printReplies()
            self.sql.printRows()
        except:
            pass

    def default(self, line):
        try:
            self.sql.sql_query(line)
            self.sql.printReplies()
            self.sql.printRows()
        except:
            pass
     
    def emptyline(self):
        pass

    def do_exit(self, line):
        return True