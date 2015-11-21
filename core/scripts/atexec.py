#!/usr/bin/python
# Copyright (c) 2003-2015 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# ATSVC example for some functions implemented, creates, enums, runs, delete jobs
# This example executes a command on the target machine through the Task Scheduler 
# service. Returns the output of such command
#
# Author:
#  Alberto Solino (@agsolino)
#
# Reference for:
#  DCE/RPC for TSCH

import string
import sys
import argparse
import random
import logging

from core.logger import *
from gevent import sleep
from impacket import version
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from StringIO import StringIO


class TSCH_EXEC:
    def __init__(self, command=None, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, noOutput=False):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__command = command
        self.__noOutput = noOutput
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
        if password is None:
            self.__password = ''

    def play(self, addr):
        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % addr
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos)
        try:
            self.doStuff(rpctransport)
        except Exception, e:
            #import traceback
            #traceback.print_exc()
            logging.error(e)

    def doStuff(self, rpctransport):
        def output_callback(data):
            buf = StringIO(data.strip()).readlines()
            for line in buf:
                print_att(line.strip())

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        tmpName = ''.join([random.choice(string.letters) for _ in range(8)])
        tmpFileName = tmpName + '.tmp'

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
"""
        if self.__noOutput is False:
            xml+= """      <Arguments>/C {} &gt; %windir%\\Temp\\{} 2&gt;&amp;1</Arguments>
    </Exec>
  </Actions>
</Task>
        """.format(self.__command, tmpFileName)
        
        else:
            xml+= """      <Arguments>/C {}</Arguments>
    </Exec>
  </Actions>
</Task>
        """.format(self.__command)

        logging.info("Task XML: {}".format(xml))
        taskCreated = False
        try:
            logging.info('Creating task \\%s' % tmpName)
            tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            logging.info('Running task \\%s' % tmpName)
            tsch.hSchRpcRun(dce, '\\%s' % tmpName)

            done = False
            while not done:
                logging.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
                resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
                if resp['pLastRuntime']['wYear'] != 0:
                    done = True
                else:
                    sleep(2)

            logging.info('Deleting task \\%s' % tmpName)
            tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
            taskCreated = False
        except tsch.DCERPCSessionError, e:
            logging.error(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(dce, '\\%s' % tmpName)

        peer = ':'.join(map(str, rpctransport.get_socket().getpeername()))
        print_succ('{} Executed command via ATEXEC'.format(peer))

        if self.__noOutput is False:
            smbConnection = rpctransport.get_smb_connection()
            while True:
                try:
                    logging.info('Attempting to read ADMIN$\\Temp\\%s' % tmpFileName)
                    smbConnection.getFile('ADMIN$', 'Temp\\%s' % tmpFileName, output_callback)
                    break
                except Exception, e:
                    if str(e).find('SHARING') > 0:
                        sleep(3)
                    elif str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                        sleep(3)
                    else:
                        raise
            logging.debug('Deleting file ADMIN$\\Temp\\%s' % tmpFileName)
            smbConnection.deleteFile('ADMIN$', 'Temp\\%s' % tmpFileName)
        else:
            logging.info('Output retrieval disabled')

        dce.disconnect()