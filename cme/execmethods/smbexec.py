import logging
from gevent import sleep
from impacket.dcerpc.v5 import transport, scmr
from impacket.smbconnection import *
from cme.helpers import gen_random_string

class SMBEXEC:

    def __init__(self, host, protocol, username = '', password = '', domain = '', hashes = None, share = None, port=445):
        self.__host = host
        self.__port = port
        self.__username = username
        self.__password = password
        self.__serviceName = gen_random_string()
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__share = share
        self.__output = None
        self.__batchFile = None
        self.__outputBuffer = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__retOutput = False
        self.__rpctransport = None
        self.__scmr = None
        self.__conn = None
        #self.__mode  = mode
        #self.__aesKey = aesKey
        #self.__doKerberos = doKerberos

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
            self.__rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        #rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        self.__scmr = self.__rpctransport.get_dce_rpc()
        self.__scmr.connect()
        s = self.__rpctransport.get_smb_connection()
        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp['lpScHandle']
        self.transferClient = self.__rpctransport.get_smb_connection()

    def execute(self, command, output=False):
        self.__retOutput = output
        if self.__retOutput:
            self.cd('')

        self.execute_remote(command)
        self.finish()
        return self.__outputBuffer
            
    def cd(self, s):
        ret_state = self.__retOutput
        self.__retOutput = False
        self.execute_remote('cd ' )
        self.__retOutput = ret_state

    def get_output(self):

        if self.__retOutput is False:
            self.__outputBuffer = ''
            return

        def output_callback(data):
            self.__outputBuffer += data

        while True:
            try:
                self.transferClient.getFile(self.__share, self.__output, output_callback)        
                self.transferClient.deleteFile(self.__share, self.__output)
                break
            except Exception:
                sleep(2)

    def execute_remote(self, data):
        self.__output = '\\Windows\\Temp\\' + gen_random_string() 
        self.__batchFile = '%TEMP%\\' + gen_random_string() + '.bat'

        if self.__retOutput:
            command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile 
        else:
            command = self.__shell + 'echo ' + data + ' 2^>^&1 > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile 
        
        command += ' & ' + 'del ' + self.__batchFile 

        logging.debug('Executing command: ' + command)

        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName, lpBinaryPathName=command)
        service = resp['lpServiceHandle']

        try:
           scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output()

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
