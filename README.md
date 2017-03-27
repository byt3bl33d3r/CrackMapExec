![Supported Python versions](https://img.shields.io/badge/python-2.7-blue.svg)
# CrackMapExec
A swiss army knife for pentesting networks

# Acknowledgments
**(These are the people who did the hard stuff)**

This project was originally inspired by:
- [smbmap](https://github.com/ShawnDEvans/smbmap)
- [CredCrack](https://github.com/gojhonny/CredCrack)
- [smbexec](https://github.com/pentestgeek/smbexec)

Unintentional contributors:

- The [Empire](https://github.com/PowerShellEmpire/Empire) project
- @T-S-A's [smbspider](https://github.com/T-S-A/smbspider) script

This repository contains the following repositories as submodules:
- [Impacket](https://github.com/CoreSecurity/impacket)
- [Pywerview](https://github.com/the-useless-one/pywerview)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- [Invoke-Vnc](https://github.com/artkond/Invoke-Vnc)
- [Mimikittenz](https://github.com/putterpanda/mimikittenz)
- [NetRipper](https://github.com/NytroRST/NetRipper)
- [RandomPS-Scripts](https://github.com/xorrior/RandomPS-Scripts)

# Documentation, Tutorials, Examples
See the project's [wiki](https://github.com/byt3bl33d3r/CrackMapExec/wiki) for documentation and usage examples

# Description

CrackMapExec is your one-stop-shop for pentesting Windows/Active Directory environments!

From enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL's into memory using Powershell, dumping the NTDS.dit and more!

The biggest improvements over the above tools are:
- Pure Python script, no external tools required
- Fully concurrent threading
- Uses **ONLY** native WinAPI calls for discovering sessions, users, dumping SAM hashes etc...
- Opsec safe (no binaries are uploaded to dump clear-text credentials, inject shellcode etc...)

Additionally, a database is used to store used/dumped credentals. It also automatically correlates Admin credentials to hosts and vice-versa allowing you to easily keep track of credential sets and gain additional situational awareness in large environments.

# Installation

Use [virtualenvwrapper](https://virtualenvwrapper.readthedocs.org/en/latest/) to install CrackMapExec in a python [virtualenv](http://docs.python-guide.org/en/latest/dev/virtualenvs)

**Kali/Debian/Ubuntu Users:**

- Run: ```apt-get install -y libssl-dev libffi-dev python-dev build-essential```

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

# To do
- Kerberos support
- ~~0wn everything~~