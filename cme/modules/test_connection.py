#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sys import exit


class CMEModule:
    """
    Executes the Test-Connection PowerShell cmdlet
    Module by @byt3bl33d3r
    """

    name = "test_connection"
    description = "Pings a host"
    supported_protocols = ["smb", "mssql"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        HOST      Host to ping
        """
        self.host = None

        if "HOST" not in module_options:
            context.log.fail("HOST option is required!")
            exit(1)

        self.host = module_options["HOST"]

    def on_admin_login(self, context, connection):
        # $ProgressPreference = 'SilentlyContinue' prevents the "preparing modules for the first time" error
        command = f"$ProgressPreference = 'SilentlyContinue'; Test-Connection {self.host} -quiet -count 1"

        output = connection.ps_execute(command, get_output=True)[0]

        context.log.debug(f"Output: {output}")
        context.log.debug(f"Type: {type(output)}")

        if output == "True":
            context.log.success("Pinged successfully")
        else:
            context.log.fail("Host unreachable")
