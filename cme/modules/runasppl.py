#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class CMEModule:
    def __init__(self):
        self.name = "runasppl"
        self.description = "Check if the registry value RunAsPPL is set or not"
        self.supported_protocols = ["smb"]
        self.opsec_safe = True
        self.multiple_hosts = True

    def options(self, context, module_options):
        """
        Check if the registry value RunAsPPL is set via SMBExec and Powershell
        """

    def on_admin_login(self, context, connection):
        command = "reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ /v RunAsPPL"
        context.log.info("Executing command")
        p = connection.execute(command, True)
        if "The system was unable to find the specified registry key or value" in p:
            context.log.info(f"Unable to find RunAsPPL Registry Key")
        else:
            context.log.highlight(p)
