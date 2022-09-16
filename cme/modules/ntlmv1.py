#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5.rrp import DCERPCSessionError

class CMEModule:
    '''
    Detect if the targets's LmCompatibilityLevel will allow NTLMv1 authentication
    Module by @Tw1sm
    '''
    name = 'ntlmv1'
    description = 'Detect if lmcompatibilitylevel on the target is set to 0 or 1'
    supported_protocols = ['smb']
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        self.output = 'NTLMv1 allowed on: {} - LmCompatibilityLevel = {}'

    def on_admin_login(self, context, connection):
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            if remoteOps._RemoteOperations__rrp:
                ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
                regHandle = ans['phKey']

                ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa')
                keyHandle = ans['phkResult']

                rtype, data = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'lmcompatibilitylevel\x00')

                if int(data) in [0, 1, 2]:
                    context.log.highlight(self.output.format(connection.conn.getRemoteHost(), data))

            try:
                remoteOps.finish()
            except:
                pass

        except DCERPCSessionError as e:
            try:
                remoteOps.finish()
            except:
                pass