from cme.helpers.powershell import create_ps_command
from sys import exit

class CMEModule:
    '''
        Executes the Test-Connection PowerShell cmdlet
        Module by @byt3bl33d3r
    '''

    name = 'test_connection'
    description = "Pings a host"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            HOST      Host to ping
        '''
        self.host = None

        if 'HOST' not in module_options:
            context.log.error('HOST option is required!')
            exit(1)

        self.host = module_options['HOST']

    def on_admin_login(self, context, connection):
        command = 'Test-Connection {} -quiet -count 1'.format(self.host)

        output = connection.ps_execute(command, get_output=True)

        if output:
            output = output.strip()
            if bool(output) is True:
                context.log.success('Pinged successfully')
            elif bool(output) is False:
                context.log.error('Host unreachable')
