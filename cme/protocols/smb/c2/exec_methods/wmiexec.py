import logging
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL


class WMIEXEC(object):
    def __init__(self, connection, command, payload, target, username, password, domain, hashes=None, retOutput=True):
        self.connection = connection
        self.command = command
        self.payload = payload
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.outputBuffer = ''
        #self.shell = 'cmd.exe /Q /C '
        self.pwd = 'C:\\'
        self.aesKey = None
        self.doKerberos = False
        self.retOutput = retOutput

        if hashes is not None:
            # This checks to see if we didn't provide the LM Hash
            if hashes.find(':') != -1:
                self.lmhash, self.nthash = hashes.split(':')
            else:
                self.nthash = hashes

        if self.password is None:
            self.password = ''

        self.dcom = DCOMConnection(
            self.target, self.username, self.password,
            self.domain, self.lmhash, self.nthash,
            self.aesKey, oxidResolver=True, doKerberos=self.doKerberos
        )

        iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        self.iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

    def execute_command(self, data):
        command = self.shell + data

        logging.debug('Command to execute: {}'.format(command))

        win32Process, _ = self.iWbemServices.GetObject('Win32_Process')
        win32Process.Create(command, self.pwd, None)
