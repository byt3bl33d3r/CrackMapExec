#!/usr/bin/python
# Copyright (c) 2003-2015 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# [MS-SCMR] services common functions for manipulating services
#
# Author:
#  Alberto Solino (@agsolino)
#
# Reference for:
#  DCE/RPC.
# TODO: 
# [ ] Check errors

import sys
import logging
import codecs

from core.logger import *
from impacket import version
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.ndr import NULL
from impacket.crypto import *


class SVCCTL:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }

    def __init__(self, username, password, domain, protocol, action, options):
        self.__username = username
        self.__password = password
        self.__protocol = SVCCTL.KNOWN_PROTOCOLS.keys()
        self.__options = options
        self.__action = action.upper()
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.kerb
        self.__protocol = protocol
        self.__addr = None
        self.__port = None

        if options.hash is not None:
            self.__lmhash, self.__nthash = options.hash.split(':')

    def run(self, addr):

        # Try all requested protocols until one works.
        protodef = SVCCTL.KNOWN_PROTOCOLS[self.__protocol]
        port = protodef[1]
        self.__port = port

        logging.info("Trying protocol %s..." % self.__protocol)
        stringbinding = protodef[0] % addr

        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(port)
        rpctransport.set_kerberos(self.__doKerberos)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username,self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)

        try:
            self.__addr = addr
            self.doStuff(rpctransport)
        except Exception, e:
            #import traceback
            #traceback.print_exc()
            logging.critical(str(e))

    def doStuff(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        #dce.set_credentials(self.__username, self.__password)
        dce.connect()
        #dce.set_max_fragment_size(1)
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
        dce.bind(scmr.MSRPC_UUID_SCMR)
        #rpc = svcctl.DCERPCSvcCtl(dce)
        rpc = dce
        ans = scmr.hROpenSCManagerW(rpc)
        scManagerHandle = ans['lpScHandle']
        if self.__action != 'LIST' and self.__action != 'CREATE':
            ans = scmr.hROpenServiceW(rpc, scManagerHandle, self.__options.service_name+'\x00')
            serviceHandle = ans['lpServiceHandle']

        if self.__action == 'START':
            print_status(u"{}:{} Starting service {}".format(self.__addr, self.__port, self.__options.service_name))
            scmr.hRStartServiceW(rpc, serviceHandle)
            scmr.hRCloseServiceHandle(rpc, serviceHandle)
        elif self.__action == 'STOP':
            print_status(u"{}:{} Stopping service {}".format(self.__addr, self.__port, self.__options.service_name))
            scmr.hRControlService(rpc, serviceHandle, scmr.SERVICE_CONTROL_STOP)
            scmr.hRCloseServiceHandle(rpc, serviceHandle)
        elif self.__action == 'DELETE':
            print_status(u"{}:{} Deleting service {}".format(self.__addr, self.__port, self.__options.service_name))
            scmr.hRDeleteService(rpc, serviceHandle)
            scmr.hRCloseServiceHandle(rpc, serviceHandle)
        elif self.__action == 'CONFIG':
            print_succ("{}:{} Service config for {}:".format(self.__addr, self.__port, self.__options.service_name))
            resp = scmr.hRQueryServiceConfigW(rpc, serviceHandle)
            output = "TYPE              : %2d - " % resp['lpServiceConfig']['dwServiceType']
            if resp['lpServiceConfig']['dwServiceType'] & 0x1:
                output += "SERVICE_KERNEL_DRIVER "
            if resp['lpServiceConfig']['dwServiceType'] & 0x2:
                output += "SERVICE_FILE_SYSTEM_DRIVER "
            if resp['lpServiceConfig']['dwServiceType'] & 0x10:
                output += "SERVICE_WIN32_OWN_PROCESS "
            if resp['lpServiceConfig']['dwServiceType'] & 0x20:
                output += "SERVICE_WIN32_SHARE_PROCESS "
            if resp['lpServiceConfig']['dwServiceType'] & 0x100:
                output += "SERVICE_INTERACTIVE_PROCESS "
            print_att(output)

            output = "START_TYPE        : %2d - " % resp['lpServiceConfig']['dwStartType']
            if resp['lpServiceConfig']['dwStartType'] == 0x0:
                output += "BOOT START"
            elif resp['lpServiceConfig']['dwStartType'] == 0x1:
                output += "SYSTEM START"
            elif resp['lpServiceConfig']['dwStartType'] == 0x2:
                output += "AUTO START"
            elif resp['lpServiceConfig']['dwStartType'] == 0x3:
                output += "DEMAND START"
            elif resp['lpServiceConfig']['dwStartType'] == 0x4:
                output += "DISABLED"
            else:
                output += "UNKOWN"
            print_att(output)

            output = "ERROR_CONTROL     : %2d - " % resp['lpServiceConfig']['dwErrorControl']
            if resp['lpServiceConfig']['dwErrorControl'] == 0x0:
                output += "IGNORE"
            elif resp['lpServiceConfig']['dwErrorControl'] == 0x1:
                output += "NORMAL"
            elif resp['lpServiceConfig']['dwErrorControl'] == 0x2:
                output += "SEVERE"
            elif resp['lpServiceConfig']['dwErrorControl'] == 0x3:
                output += "CRITICAL"
            else:
                output += "UNKOWN"
            print_att(output)

            print_att("BINARY_PATH_NAME  : %s" % resp['lpServiceConfig']['lpBinaryPathName'][:-1])
            print_att("LOAD_ORDER_GROUP  : %s" % resp['lpServiceConfig']['lpLoadOrderGroup'][:-1])
            print_att("TAG               : %d" % resp['lpServiceConfig']['dwTagId'])
            print_att("DISPLAY_NAME      : %s" % resp['lpServiceConfig']['lpDisplayName'][:-1])
            print_att("DEPENDENCIES      : %s" % resp['lpServiceConfig']['lpDependencies'][:-1])
            print_att("SERVICE_START_NAME: %s" % resp['lpServiceConfig']['lpServiceStartName'][:-1])
        elif self.__action == 'STATUS':
            print_succ("{}:{} Service status for {}:".format(self.__addr, self.__port, self.__options.service_name))
            resp = scmr.hRQueryServiceStatus(rpc, serviceHandle)
            output = "%s - " % self.__options.service_name
            state = resp['lpServiceStatus']['dwCurrentState']
            if state == scmr.SERVICE_CONTINUE_PENDING:
               output += "CONTINUE PENDING"
            elif state == scmr.SERVICE_PAUSE_PENDING:
               output += "PAUSE PENDING"
            elif state == scmr.SERVICE_PAUSED:
               output += "PAUSED"
            elif state == scmr.SERVICE_RUNNING:
               output += "RUNNING"
            elif state == scmr.SERVICE_START_PENDING:
               output += "START PENDING"
            elif state == scmr.SERVICE_STOP_PENDING:
               output += "STOP PENDING"
            elif state == scmr.SERVICE_STOPPED:
               output += "STOPPED"
            else:
               output += "UNKOWN"
            print_att(output)
        elif self.__action == 'LIST':
            print_succ("{}:{} Available services:".format(self.__addr, self.__port))
            #resp = rpc.EnumServicesStatusW(scManagerHandle, svcctl.SERVICE_WIN32_SHARE_PROCESS )
            #resp = rpc.EnumServicesStatusW(scManagerHandle, svcctl.SERVICE_WIN32_OWN_PROCESS )
            #resp = rpc.EnumServicesStatusW(scManagerHandle, serviceType = svcctl.SERVICE_FILE_SYSTEM_DRIVER, serviceState = svcctl.SERVICE_STATE_ALL )
            resp = scmr.hREnumServicesStatusW(rpc, scManagerHandle)
            for i in range(len(resp)):
                output = "%30s - %70s - " % (resp[i]['lpServiceName'][:-1], resp[i]['lpDisplayName'][:-1])
                state = resp[i]['ServiceStatus']['dwCurrentState']
                if state == scmr.SERVICE_CONTINUE_PENDING:
                   output += "CONTINUE PENDING"
                elif state == scmr.SERVICE_PAUSE_PENDING:
                   output += "PAUSE PENDING"
                elif state == scmr.SERVICE_PAUSED:
                   output += "PAUSED"
                elif state == scmr.SERVICE_RUNNING:
                   output += "RUNNING"
                elif state == scmr.SERVICE_START_PENDING:
                   output += "START PENDING"
                elif state == scmr.SERVICE_STOP_PENDING:
                   output += "STOP PENDING"
                elif state == scmr.SERVICE_STOPPED:
                   output += "STOPPED"
                else:
                   output += "UNKOWN"
                print_att(output)
            print_att("Total Services: %d" % len(resp))
        elif self.__action == 'CREATE':
            print_status("{}:{} Creating service {}".format(self.__addr, self.__port, self.__options.service_name))
            scmr.hRCreateServiceW(rpc, scManagerHandle,self.__options.service_name + '\x00', self.__options.service_display_name + '\x00', lpBinaryPathName=self.__options.service_bin_path + '\x00')
        elif self.__action == 'CHANGE':
            print_status("{}:{} Changing service config for {}".format(self.__addr, self.__port, self.__options.service_name))
            if self.__options.start_type is not None:
                start_type = int(self.__options.start_type)
            else:
                start_type = scmr.SERVICE_NO_CHANGE
            if self.__options.service_type is not None:
                service_type = int(self.__options.service_type)
            else:
                service_type = scmr.SERVICE_NO_CHANGE

            if self.__options.service_display_name is not None:
                display = self.__options.service_display_name + '\x00'
            else:
                display = NULL
 
            if self.__options.service_bin_path is not None:
                path = self.__options.service_bin_path + '\x00'
            else:
                path = NULL
 
            if self.__options.start_name is not None:
                start_name = self.__options.start_name + '\x00'
            else:
                start_name = NULL 

            if self.__options.start_pass is not None:
                s = rpctransport.get_smb_connection()
                key = s.getSessionKey()
                try:
                    password = (self.__options.start_pass+'\x00').encode('utf-16le')
                except UnicodeDecodeError:
                    import sys
                    password = (self.__options.start_pass+'\x00').decode(sys.getfilesystemencoding()).encode('utf-16le')
                password = encryptSecret(key, password)
            else:
                password = NULL
 

            #resp = scmr.hRChangeServiceConfigW(rpc, serviceHandle,  display, path, service_type, start_type, start_name, password)
            scmr.hRChangeServiceConfigW(rpc, serviceHandle, service_type, start_type, scmr.SERVICE_ERROR_IGNORE, path, NULL, NULL, NULL, 0, start_name, password, 0, display)
            scmr.hRCloseServiceHandle(rpc, serviceHandle)
        else:
            logging.error("Unknown action %s" % self.__action)

        scmr.hRCloseServiceHandle(rpc, scManagerHandle)

        dce.disconnect()

        return