import logging
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL


class WMIEXEC(object):
    def __init__(self, target, username, password, domain, lmhash, nthash, connection=None):
        self.connection = connection
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = None
        self.doKerberos = False
        self.pwd = 'C:\\'

        self.dcom = DCOMConnection(
            self.target, self.username, self.password,
            self.domain, self.lmhash, self.nthash,
            self.aesKey, oxidResolver=True, doKerberos=self.doKerberos
        )

        iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        self.iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

    def execute_command(self, command):
        logging.debug('Command to execute: {}'.format(command))

        win32Process, _ = self.iWbemServices.GetObject('Win32_Process')
        win32Process.Create(command, self.pwd, None)
