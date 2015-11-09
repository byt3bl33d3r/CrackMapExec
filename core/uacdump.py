from scripts.secretsdump import RemoteOperations
from impacket.dcerpc.v5 import rrp
from logger import *

class UACdump:

    def __init__(self, smbconnection, doKerb):
        self.smbconnection = smbconnection
        self.peer = ':'.join(map(str, smbconnection.getSMBServer().get_socket().getpeername()))
        self.doKerb = doKerb

    def run(self):
        remoteOps = RemoteOperations(self.smbconnection, self.doKerb)
        remoteOps.enableRegistry()
        ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
        regHandle = ans['phKey']
        ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
        keyHandle = ans['phkResult']
        dataType, uac_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'EnableLUA')

        print_succ("{} UAC status:".format(self.peer))
        if uac_value == 1:
            print_att('1 - UAC Enabled')
        elif uac_value == 0:
            print_att('0 - UAC Disabled')

        rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
        remoteOps.finish()
