from scripts.wmiexec import WMIEXEC
from scripts.smbexec import SMBEXEC
from scripts.atexec import TSCH_EXEC
from scripts.psexec import PSEXEC

import settings

class EXECUTOR:

    """Yes, I know this sounds like the pokemon... deal with it"""

    def __init__(self, command, host, domain, noOutput, smbconnection):

        if settings.args.execm == 'wmi':
            wmi_exec = WMIEXEC(command, 
                               settings.args.user,
                               settings.args.passwd, 
                               domain, 
                               settings.args.hash, 
                               settings.args.aesKey,
                               settings.args.share, 
                               noOutput, 
                               settings.args.kerb)
            wmi_exec.run(host, smbconnection)

        elif settings.args.execm == 'smbexec':
            smb_exec = SMBEXEC(command,
                               '{}/SMB'.format(settings.args.port), 
                               settings.args.user, 
                               settings.args.passwd, 
                               domain, 
                               settings.args.hash, 
                               settings.args.aesKey,
                               settings.args.kerb, 
                               'SHARE',
                               settings.args.share)
            smb_exec.run(host)

        elif settings.args.execm == 'atexec':
            atsvc_exec = TSCH_EXEC(command,
                                   settings.args.user, 
                                   settings.args.passwd, 
                                   domain,
                                   settings.args.hash, 
                                   settings.args.aesKey, 
                                   settings.args.kerb)
            atsvc_exec.play(host)

        elif settings.args.execm == 'psexec':
            ps_exec = PSEXEC(command, 
                              None,
                              None,
                              None,
                              '{}/SMB'.format(settings.args.port),
                              settings.args.user,
                              settings.args.passwd, 
                              domain,
                              settings.args.hash, 
                              settings.args.aesKey, 
                              settings.args.kerb)
            ps_exec.run(host)