#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5 import scmr
from impacket.examples.secretsdump import RemoteOperations


class CMEModule:
    name = "install_elevated"
    description = "Checks for AlwaysInstallElevated"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """ """

    def on_admin_login(self, context, connection):
        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()

            try:
                ans_machine = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
                reg_handle = ans_machine["phKey"]
                ans_machine = rrp.hBaseRegOpenKey(
                    remote_ops._RemoteOperations__rrp,
                    reg_handle,
                    "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                )
                key_handle = ans_machine["phkResult"]
                data_type, aie_machine_value = rrp.hBaseRegQueryValue(
                    remote_ops._RemoteOperations__rrp,
                    key_handle,
                    "AlwaysInstallElevated",
                )
                rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)

                if aie_machine_value == 0:
                    context.log.highlight("AlwaysInstallElevated Status: 0 (Disabled)")
                    return
            except rrp.DCERPCSessionError:
                context.log.highlight("AlwaysInstallElevated Status: 0 (Disabled)")
                return
            try:
                ans_user = rrp.hOpenCurrentUser(remote_ops._RemoteOperations__rrp)
                reg_handle = ans_user["phKey"]
                ans_user = rrp.hBaseRegOpenKey(
                    remote_ops._RemoteOperations__rrp,
                    reg_handle,
                    "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                )
                key_handle = ans_user["phkResult"]
                data_type, aie_user_value = rrp.hBaseRegQueryValue(
                    remote_ops._RemoteOperations__rrp,
                    key_handle,
                    "AlwaysInstallElevated",
                )
                rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
            except rrp.DCERPCSessionError:
                context.log.highlight("AlwaysInstallElevated Status: 1 (Enabled: Computer Only)")
                return
            if aie_user_value == 0:
                context.log.highlight("AlwaysInstallElevated Status: 1 (Enabled: Computer Only)")
            else:
                context.log.highlight("AlwaysInstallElevated Status: 1 (Enabled)")
        finally:
            try:
                remote_ops.finish()
            except scmr.DCERPCSessionError as e:
                context.log.debug(f"Received SessionError while attempting to clean up logins: {e}")
            except Exception as e:
                context.log.debug(f"Received general exception while attempting to clean up logins: {e}")
