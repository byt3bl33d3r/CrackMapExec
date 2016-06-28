![Supported Python versions](https://img.shields.io/badge/python-2.7-blue.svg)
# CrackMapExec
A swiss army knife for pentesting Windows/Active Directory environments

Powered by [Impacket](https://github.com/CoreSecurity/impacket)

This project was inspired by/based off of:
- @agsolino's [wmiexec.py](https://github.com/CoreSecurity/impacket/blob/master/examples/wmiexec.py), [wmiquery.py](https://github.com/CoreSecurity/impacket/blob/master/examples/wmiquery.py), [smbexec.py](https://github.com/CoreSecurity/impacket/blob/master/examples/smbexec.py), [samrdump.py](https://github.com/CoreSecurity/impacket/blob/master/examples/samrdump.py), [secretsdump.py](https://github.com/CoreSecurity/impacket/blob/master/examples/secretsdump.py), [atexec.py](https://github.com/CoreSecurity/impacket/blob/master/examples/atexec.py) and [lookupsid.py](https://github.com/CoreSecurity/impacket/blob/master/examples/lookupsid.py) scripts (beyond awesome)
- @ShawnDEvans's [smbmap](https://github.com/ShawnDEvans/smbmap)
- @gojhonny's [CredCrack](https://github.com/gojhonny/CredCrack)
- @pentestgeek's [smbexec](https://github.com/pentestgeek/smbexec)

Unintentional contributors:

- @T-S-A's [smbspider](https://github.com/T-S-A/smbspider) script
- The [Empire](https://github.com/PowerShellEmpire/Empire) project

This repo also includes the [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) repository as a submodule.

#Description

CrackMapExec is your one-stop-shop for pentesting Windows/Active Directory environments!

From enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL's into memory using Powershell, dumping the NTDS.dit and more!

The biggest improvements over the above tools are:
- Pure Python script, no external tools required
- Fully concurrent threading
- Uses **ONLY** native WinAPI calls for discovering sessions, users, dumping SAM hashes etc...
- Opsec safe (no binaries are uploaded to dump clear-text credentials, inject shellcode etc...)

Additionally, a database is used to store used/dumped credentals. It also automatically correlates Admin credentials to hosts and vice-versa allowing you to easily keep track of credential sets and gain additional situational awareness in large environments.

#Installation

Use [virtualenvwrapper](https://virtualenvwrapper.readthedocs.org/en/latest/) to install CrackMapExec in a python [virtualenv](http://docs.python-guide.org/en/latest/dev/virtualenvs)

To get the latest stable version: 

```
#~ pip install crackmapexec
```

If you like living on the bleeding-edge:

```
#~ git clone https://github.com/byt3bl33d3r/CrackMapExec
#- cd CrackMapExec && git submodule init && git submodule update --recursive
#~ python setup.py install
```

**Note for Kali/Debian/Ubuntu Users:**

If you get compilation errors run ```apt-get install -y libssl-dev libffi-dev python-dev build-essential``` and try again.

#Documentation, Tutorials, Examples
See the project's [wiki](https://github.com/byt3bl33d3r/CrackMapExec/wiki) for documentation and usage examples

#Quick Demo

**Demo of V3.0 coming soon!**

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
                                                     
                                                  Version: 3.1
                                              Codename: 'Duchess'


positional arguments:
  target                The target IP(s), range(s), CIDR(s), hostname(s), FQDN(s) or file(s) containg a list of targets

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -t THREADS            Set how many concurrent threads to use (defaults to 100)
  -id CRED_ID           Database credential ID to use for authentication
  -u [USERNAME [USERNAME ...]]
                        Username(s) or file(s) containing usernames
  -d DOMAIN             Domain name
  -p [PASSWORD [PASSWORD ...]]
                        Password(s) or file(s) containing passwords
  -H [HASH [HASH ...]]  NTLM hash(es) or file(s) containing NTLM hashes
  -M MODULE, --module MODULE
                        Payload module to use
  -o [MODULE_OPTION [MODULE_OPTION ...]]
                        Payload module options
  -L, --list-modules    List available modules
  --show-options        Display module options
  --share SHARE         Specify a share (default: C$)
  --smb-port {139,445}  SMB port (default: 445)
  --mssql-port PORT     MSSQL port (default: 1433)
  --server {http,https}
                        Use the selected server (default: https)
  --server-host HOST    IP to bind the server to (default: 0.0.0.0)
  --server-port PORT    Start the server on the specified port
  --local-auth          Authenticate locally to each target
  --timeout TIMEOUT     Max timeout in seconds of each thread (default: 20)
  --verbose             Enable verbose output

Credential Gathering:
  Options for gathering credentials

  --sam                 Dump SAM hashes from target systems
  --lsa                 Dump LSA secrets from target systems
  --ntds {vss,drsuapi}  Dump the NTDS.dit from target DCs using the specifed method
                        (drsuapi is the fastest)
  --ntds-history        Dump NTDS.dit password history
  --ntds-pwdLastSet     Shows the pwdLastSet attribute for each NTDS.dit account
  --wdigest {enable,disable}
                        Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1

Mapping/Enumeration:
  Options for Mapping/Enumerating

  --shares              Enumerate shares and access
  --uac                 Checks UAC status
  --sessions            Enumerate active sessions
  --disks               Enumerate disks
  --users               Enumerate users
  --rid-brute [MAX_RID]
                        Enumerate users by bruteforcing RID's (default: 4000)
  --pass-pol            Dump password policy
  --lusers              Enumerate logged on users
  --wmi QUERY           Issues the specified WMI query
  --wmi-namespace NAMESPACE
                        WMI Namespace (default: //./root/cimv2)

Spidering:
  Options for spidering shares

  --spider [FOLDER]     Folder to spider (default: root directory)
  --content             Enable file content searching
  --exclude-dirs DIR_LIST
                        Directories to exclude from spidering
  --pattern [PATTERN [PATTERN ...]]
                        Pattern(s) to search for in folders, filenames and file content
  --regex [REGEX [REGEX ...]]
                        Regex(s) to search for in folders, filenames and file content
  --depth DEPTH         Spider recursion depth (default: 10)

Command Execution:
  Options for executing commands

  --exec-method {atexec,smbexec,wmiexec}
                        Method to execute the command. Ignored if in MSSQL mode (default: wmiexec)
  --force-ps32          Force the PowerShell command to run in a 32-bit process
  --no-output           Do not retrieve command output
  -x COMMAND            Execute the specified command
  -X PS_COMMAND         Execute the specified PowerShell command

MSSQL Interaction:
  Options for interacting with MSSQL DBs

  --mssql               Switches CME into MSSQL Mode. If credentials are provided will authenticate against all discovered MSSQL DBs
  --mssql-query QUERY   Execute the specifed query against the MSSQL DB

I swear I had something for this...

```

#To do
- Kerberos support
- ~~0wn everything~~
