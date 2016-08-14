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

#To do
- Kerberos support
- ~~0wn everything~~
