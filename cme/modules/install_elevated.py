#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations

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
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            try:
                ans_machine = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
                regHandle = ans_machine['phKey']
                ans_machine = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SOFTWARE\\Policies\\Microsoft\\Windows\\Installer')
                keyHandle = ans_machine['phkResult']
                dataType, aie_machine_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'AlwaysInstallElevated')
                rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)

                if aie_machine_value == 0:
                    context.log.highlight('AlwaysInstallElevated Status: 0 (Disabled)')
                    return

            except rrp.DCERPCSessionError:
                context.log.highlight('AlwaysInstallElevated Status: 0 (Disabled)')
                return


            try:
                ans_user = rrp.hOpenCurrentUser(remoteOps._RemoteOperations__rrp)
                regHandle = ans_user['phKey']
                ans_user = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SOFTWARE\\Policies\\Microsoft\\Windows\\Installer')
                keyHandle = ans_user['phkResult']
                dataType, aie_user_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'AlwaysInstallElevated')
                rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)

            except rrp.DCERPCSessionError:
                context.log.highlight('AlwaysInstallElevated Status: 1 (Enabled: Computer Only)')
                return

            if aie_user_value == 0:
                context.log.highlight('AlwaysInstallElevated Status: 1 (Enabled: Computer Only)')
            else:
                context.log.highlight('AlwaysInstallElevated Status: 1 (Enabled)')
        finally:
            remoteOps.finish()
