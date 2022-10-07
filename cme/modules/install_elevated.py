class CMEModule:

    name = 'install_elevated'
    description = "Checks for AlwaysInstallElevated"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        '''

    def on_admin_login(self, context, connection):
        remoteOps = RemoteOperations(connection.conn, False)
        remoteOps.enableRegistry()

        try:
            ans_machine = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans_machine['phKey']
            ans_machine = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SOFTWARE\\Policies\\Microsoft\\Windows\\Installer')
            keyHandle = ans_machine['phkResult']
            dataType, aie_machine_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'AlwaysInstallElevated')

            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)


            ans_user = rrp.hOpenCurrentUser(remoteOps._RemoteOperations__rrp)
            regHandle = ans_user['phKey']
            ans_user = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SOFTWARE\\Policies\\Microsoft\\Windows\\Installer')
            keyHandle = ans_user['phkResult']
            dataType, aie_user_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'AlwaysInstallElevated')

            if aie_user_value == 1 and aie_machine_value == 1:
                context.log.highlight('AlwaysInstallElevated Status: 1 (Enabled)')
            elif aie_user_value == 0 or aie_machine_value == 0:
                context.log.highlight('AlwaysInstallElevated Status: 0 (Disabled)')

            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)

        except rrp.DCERPCSessionError:
            context.log.highlight('AlwaysInstallElevated Status: 0 (Disabled)')

        remoteOps.finish()
