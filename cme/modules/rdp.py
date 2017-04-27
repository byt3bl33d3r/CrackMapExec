from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from sys import exit

class CMEModule:

    name = 'rdp'
    description = 'Enables/Disables RDP'
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            ACTION  Enable/Disable RDP (choices: enable, disable)
        '''

        if not 'ACTION' in module_options:
            context.log.error('ACTION option not specified!')
            exit(1)

        if module_options['ACTION'].lower() not in ['enable', 'disable']:
            context.log.error('Invalid value for ACTION option!')
            exit(1)

        self.action = module_options['ACTION'].lower()

    def on_admin_login(self, context, connection):
        if self.action == 'enable':
            self.rdp_enable(context, connection.conn)
        elif self.action == 'disable':
            self.rdp_disable(context, connection.conn)

    def rdp_enable(self, context, smbconnection):
        remoteOps = RemoteOperations(smbconnection, False)
        remoteOps.enableRegistry()

        if remoteOps._RemoteOperations__rrp:
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans['phKey']

            ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Terminal Server')
            keyHandle = ans['phkResult']

            rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, 'fDenyTSConnections\x00',  rrp.REG_DWORD, 0)

            rtype, data = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'fDenyTSConnections\x00')

            if int(data) == 0:
                context.log.success('RDP enabled successfully')

        try:
            remoteOps.finish()
        except:
            pass

    def rdp_disable(self, context, smbconnection):
        remoteOps = RemoteOperations(smbconnection, False)
        remoteOps.enableRegistry()

        if remoteOps._RemoteOperations__rrp:
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans['phKey']

            ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Terminal Server')
            keyHandle = ans['phkResult']

            rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, 'fDenyTSConnections\x00',  rrp.REG_DWORD, 1)

            rtype, data = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'fDenyTSConnections\x00')

            if int(data) == 1:
                context.log.success('RDP disabled successfully')

        try:
            remoteOps.finish()
        except:
            pass
