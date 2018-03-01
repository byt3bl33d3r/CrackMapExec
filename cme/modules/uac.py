from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations

class CMEModule:

    name = 'uac'
    description = "Checks UAC status"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        '''

    def on_admin_login(self, context, connection):
        remoteOps = RemoteOperations(connection.conn, False)
        remoteOps.enableRegistry()

        ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
        regHandle = ans['phKey']
        ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
        keyHandle = ans['phkResult']
        dataType, uac_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'EnableLUA')

        if uac_value == 1:
            context.log.highlight('UAC Status: 1 (UAC Enabled)')
        elif uac_value == 0:
            context.log.highlight('UAC Status: 0 (UAC Disabled)')

        rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
        remoteOps.finish()
