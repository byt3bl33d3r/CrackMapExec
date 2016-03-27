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
import logging
import traceback

from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection

class WMIQUERY:

    def __init__(self, logger, connection, wmi_namespace):
        self.__logger = logger
        self.__addr = connection.host
        self.__username = connection.username
        self.__password = connection.password
        self.__hash = connection.hash
        self.__domain = connection.domain
        self.__namespace = wmi_namespace
        self.__doKerberos = False
        self.__aesKey = None
        self.__oxidResolver = True
        self.__lmhash = ''
        self.__nthash = ''
        
        if self.__hash is not None:
            self.__lmhash, self.__nthash = self.__hash.split(':')
        
        if self.__password is None:
            self.__password = ''

        self.__dcom = DCOMConnection(self.__addr, self.__username, self.__password, self.__domain, 
                              self.__lmhash, self.__nthash, self.__aesKey, self.__oxidResolver, self.__doKerberos)

        iInterface = self.__dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        self.__iWbemServices= iWbemLevel1Login.NTLMLogin(self.__namespace, NULL, NULL)
        iWbemLevel1Login.RemRelease()

    def query(self, query):

        query = query.strip('\n')

        if query[-1:] == ';':
            query = query[:-1]

        try:
            iEnumWbemClassObject = self.__iWbemServices.ExecQuery(query.strip('\n'))
            self.__logger.success('Executed specified WMI query')
            self.printReply(iEnumWbemClassObject)
            iEnumWbemClassObject.RemRelease()
        except Exception as e:
            traceback.print_exc()

        self.__iWbemServices.RemRelease()
        self.__dcom.disconnect()

    def describe(self, sClass):
        sClass = sClass.strip('\n')
        if sClass[-1:] == ';':
            sClass = sClass[:-1]
        try:
            iObject, _ = self.iWbemServices.GetObject(sClass)
            iObject.printInformation()
            iObject.RemRelease()
        except Exception as e:
            traceback.print_exc()

    def printReply(self, iEnum):
        printHeader = True
        while True:
            try:
                pEnum = iEnum.Next(0xffffffff,1)[0]
                record = pEnum.getProperties()
                line = []
                for rec in record:
                    line.append('{}: {}'.format(rec, record[rec]['value']))
                self.__logger.highlight(' | '.join(line))
            except Exception, e:
                #import traceback
                #print traceback.print_exc()
                if str(e).find('S_FALSE') < 0:
                    raise
                else:
                    break
        iEnum.RemRelease() 