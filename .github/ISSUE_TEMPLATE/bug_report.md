---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior i.e.:
Command: `crackmapexec smb -u username -p password`
Resulted in:
```
crackmapexec smb 10.10.10.10 -u username -p password -x "whoami"
SMB         10.10.10.10  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:domain) (signing:True) (SMBv1:False)
SMB         10.10.10.10  445    DC01             [+] domain\username:password
Traceback (most recent call last):
...
```

**Expected behavior**
A clear and concise description of what you expected to happen.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Crackmapexec info**
 - OS: [e.g. Kali]
 - Version of CME [e.g. v5.0.2]
 - Installed from: apt/github/pip/docker/...? Please try with latest release before openning an issue

**Additional context**
Add any other context about the problem here.
