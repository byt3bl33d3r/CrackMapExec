class CMEModule:

    name = 'runasppl'
    description = "Check if the registry value RunAsPPL is set or not"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        '''

    def on_admin_login(self, context, connection):

        command = 'reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ /v RunAsPPL'
        context.log.info('Executing command')
        p = connection.execute(command, True)
        context.log.highlight(p)