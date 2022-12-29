class CMEModule:
    """
        Enable/Disable WinRM service
        Module by Eric Labrador 
    """
    name = 'winrm'
    description = 'Enable/Disable WinRM service'
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            ACTION  Enable/Disable WinRM service (choices: enable, disable)
        '''

        if not 'ACTION' in module_options:
            context.log.error('ACTION option not specified!')
            exit(1)

        if module_options['ACTION'].lower() not in ['enable', 'disable']:
            context.log.error('Invalid value for ACTION option!')
            exit(1)

        self.action = module_options['ACTION'].lower()

    def on_admin_login(self, context, connection):
        if self.action == 'enable':
            enable_winrm_command = 'powershell.exe "Enable-PSRemoting -Force"'
            connection.execute(enable_winrm_command, True).split("\r\n")
            context.log.highlight('WinRM enabled successfully')
        elif self.action == 'disable':
            disable_winrm_command = 'powershell.exe "Stop-Service WinRM"'
            connection.execute(disable_winrm_command, True).split("\r\n")
            context.log.highlight('WinRM disabled successfully')
