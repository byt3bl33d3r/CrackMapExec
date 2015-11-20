# CrackMapExec
A swiss army knife for pentesting Windows/Active Directory environments

Powered by [Impacket](https://github.com/CoreSecurity/impacket)

This project was inspired by/based off of:
- @agsolino's [wmiexec.py](https://github.com/CoreSecurity/impacket/blob/master/examples/wmiexec.py), [wmiquery.py](https://github.com/CoreSecurity/impacket/blob/master/examples/wmiquery.py), [smbexec.py](https://github.com/CoreSecurity/impacket/blob/master/examples/smbexec.py), [samrdump.py](https://github.com/CoreSecurity/impacket/blob/master/examples/samrdump.py), [secretsdump.py](https://github.com/CoreSecurity/impacket/blob/master/examples/secretsdump.py), [atexec.py](https://github.com/CoreSecurity/impacket/blob/master/examples/atexec.py) and [lookupsid.py](https://github.com/CoreSecurity/impacket/blob/master/examples/lookupsid.py) scripts (beyond awesome)
- @ShawnDEvans's [smbmap](https://github.com/ShawnDEvans/smbmap)
- @gojhonny's [CredCrack](https://github.com/gojhonny/CredCrack)
- @pentestgeek's [smbexec](https://github.com/pentestgeek/smbexec)

Additionally some code was stolen from @T-S-A's [smbspider](https://github.com/T-S-A/smbspider) script

This repo also includes the following scripts from the [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) project:
- [Invoke-Mimikatz.ps1](https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)
- [Invoke-NinjaCopy.ps1](https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)
- [Invoke-ReflectivePEInjection.ps1](https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)
- [Invoke-Shellcode.ps1](https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke--Shellcode.ps1)

and the [PowerView](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1) script from the [PowerTools](https://github.com/PowerShellEmpire/PowerTools) repository

#Description

CrackMapExec is your one-stop-shop for pentesting Windows/Active Directory environments!

From enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL's into memory using Powershell, dumping the NTDS.dit and more!

The biggest improvements over the above tools are:
- Pure Python script, no external tools required
- Fully concurrent threading
- Uses **ONLY** native WinAPI calls for discovering sessions, users, dumping SAM hashes etc...
- Opsec safe (no binaries are uploaded to dump clear-text credentials, inject shellcode etc...)

#Installation on Kali Linux

**Note: it's recommended to install CrackMapExec in a [virtualenv](http://docs.python-guide.org/en/latest/dev/virtualenvs), to avoid conflicts with the older Impacket version thats currently in the Kali repos**

Run ```pip install --upgrade -r requirements.txt```

#Quick Demo

Just a little demo showing off the basics

[![demo](https://asciinema.org/a/29787.png)](https://asciinema.org/a/29787)

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
                                                     
                                                  Version: 2.1
                               Codename: 'I gotta change the name of this thing'

positional arguments:
  target                The target range, CIDR identifier or file containing targets

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -t THREADS            Set how many concurrent threads to use (defaults to 100)
  -u USERNAME           Username(s) or file containing usernames
  -p PASSWORD           Password(s) or file containing passwords
  -H HASH               NTLM hash(es) or file containing NTLM hashes
  -C COMBO_FILE         Combo file containing a list of domain\username:password or username:password entries
  -k HEX_KEY            AES key to use for Kerberos Authentication (128 or 256 bits)
  -d DOMAIN             Domain name
  -n NAMESPACE          WMI Namespace (default: //./root/cimv2)
  -s SHARE              Specify a share (default: C$)
  --kerb                Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters
  --port {139,445}      SMB port (default: 445)
  --server {http,https}
                        Use the selected server (defaults to http)
  --fail-limit LIMIT    The max number of failed login attempts allowed per host (default: None)
  --gfail-limit LIMIT   The max number of failed login attempts allowed globally (default: None)
  --verbose             Enable verbose output

Credential Gathering:
  Options for gathering credentials

  --sam                 Dump SAM hashes from target systems
  --lsa                 Dump LSA secrets from target systems
  --ntds {ninja,vss,drsuapi}
                        Dump the NTDS.dit from target DCs using the specifed method
                        (drsuapi is the fastest)
  --ntds-history        Dump NTDS.dit password history
  --ntds-pwdLastSet     Shows the pwdLastSet attribute for each NTDS.dit account
  --mimikatz            Run Invoke-Mimikatz (sekurlsa::logonpasswords) on target systems
  --mimikatz-cmd MIMIKATZ_CMD
                        Run Invoke-Mimikatz with the specified command
  --enable-wdigest      Creates the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1
  --disable-wdigest     Deletes the 'UseLogonCredential' registry key

Mapping/Enumeration:
  Options for Mapping/Enumerating

  --shares              List shares
  --check-uac           Checks UAC status
  --sessions            Enumerate active sessions
  --disks               Enumerate disks
  --users               Enumerate users
  --rid-brute [MAX_RID]
                        Enumerate users by bruteforcing RID's (defaults to 4000)
  --pass-pol            Dump password policy
  --lusers              Enumerate logged on users
  --powerview POWERVIEW_CMD
                        Run the specified PowerView command
  --wmi QUERY           Issues the specified WMI query

Spidering:
  Options for spidering shares

  --spider [FOLDER]     Folder to spider (defaults to top level directory)
  --content             Enable file content searching
  --exclude-dirs DIR_LIST
                        Directories to exclude from spidering
  --pattern PATTERN     Pattern to search for in folders, filenames and file content
  --patternfile PATTERNFILE
                        File containing patterns to search for in folders, filenames and file content
  --depth DEPTH         Spider recursion depth (default: 10)

Command Execution:
  Options for executing commands

  --execm {atexec,wmi,smbexec}
                        Method to execute the command (default: wmi)
  --force-ps32          Force all PowerShell code/commands to run in a 32bit process
  --no-output           Do not retrieve command output
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

  --list [PATH]         List contents of a directory (defaults to top level directory)
  --download PATH       Download a file from the remote systems
  --upload SRC DST      Upload a file to the remote systems
  --delete PATH         Delete a remote file

Service Interaction:
  Options for interacting with Windows services

  --service {status,list,create,stop,start,config,change,delete}
  --name NAME           Service name
  --display NAME        Service display name
  --bin-path PATH       Binary path
  --service-type TYPE   Service type
  --start-type TYPE     Service start type
  --start-name NAME     Name of the account under which the service should run
  --start-pass PASS     Password of the account whose name was specified with the --start-name parameter

There's been an awakening... have you felt it?

```

#To do
- ~~Kerberos support~~
- ~~Execute custom commands with mimikatz~~
- Add a plugin system (??)
- ~~0wn everything~~ 
