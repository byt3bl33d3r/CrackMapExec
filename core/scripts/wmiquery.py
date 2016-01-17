#!/usr/bin/python
# Copyright (c) 2003-2015 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: [MS-WMI] example. It allows to issue WQL queries and
#              get description of the objects.
#
#              e.g.: select name from win32_account
#              e.g.: describe win32_process
# 
# Author:
#  Alberto Solino (@agsolino)
#
# Reference for:
#  DCOM
#
import sys
import os
import logging
import cmd

from impacket import version
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
import core.settings as settings

class WMIQUERY:

    def __init__(self, logger, username, domain, password, hashes = None, doKerberos = False, aesKey = None, oxidResolver = True):
        self.__logger = logger
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__doKerberos = doKerberos
        self.__aesKey = aesKey
        self.__oxidResolver = oxidResolver
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
        if self.__password is None:
            self.__password = ''

    def run(self, command, address, namespace):

        dcom = DCOMConnection(address, self.__username, self.__password, self.__domain, 
                              self.__lmhash, self.__nthash, self.__aesKey, self.__oxidResolver, self.__doKerberos)

        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
        iWbemLevel1Login.RemRelease()

        shell = WMIShell(self.__logger, iWbemServices, address)
        shell.onecmd(command)

        iWbemServices.RemRelease()
        dcom.disconnect()

class WMIShell(cmd.Cmd):
    def __init__(self, logger, iWbemServices, address):
        cmd.Cmd.__init__(self)
        self.logger = logger
        self.address = address
        self.iWbemServices = iWbemServices

    def do_help(self, line):
        print """
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 describe {class}           - describes class
 ! {cmd}                    - executes a local shell cmd
 """ 

    def do_shell(self, s):
        os.system(s)

    def do_describe(self, sClass):
        sClass = sClass.strip('\n')
        if sClass[-1:] == ';':
            sClass = sClass[:-1]
        try:
            iObject, _ = self.iWbemServices.GetObject(sClass)
            iObject.printInformation()
            iObject.RemRelease()
        except Exception, e:
            #import traceback
            #print traceback.print_exc()
            logging.error(str(e))

    def do_lcd(self, s):
        if s == '':
            print os.getcwd()
        else:
            os.chdir(s)

    def printReply(self, iEnum):
        printHeader = True
        while True:
            try:
                pEnum = iEnum.Next(0xffffffff,1)[0]
                record = pEnum.getProperties()
                line = []
                for rec in record:
                    line.append('{}: {}'.format(rec, record[rec]['value']))
                self.logger.results(' | '.join(line))
            except Exception, e:
                #import traceback
                #print traceback.print_exc()
                if str(e).find('S_FALSE') < 0:
                    raise
                else:
                    break
        iEnum.RemRelease() 

    def default(self, line):
        line = line.strip('\n')
        if line[-1:] == ';':
            line = line[:-1]
        try:
            iEnumWbemClassObject = self.iWbemServices.ExecQuery(line.strip('\n'))
            self.logger.success('Executed specified WMI query')
            self.printReply(iEnumWbemClassObject)
            iEnumWbemClassObject.RemRelease()
        except Exception, e:
            logging.error(str(e))
     
    def emptyline(self):
        pass

    def do_exit(self, line):
        return True