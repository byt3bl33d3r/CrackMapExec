from scripts.wmiexec import WMIEXEC
from scripts.smbexec import SMBEXEC
from scripts.atexec import TSCH_EXEC

import settings

class EXECUTOR:

    """Yes, I know this sounds like the pokemon... deal with it"""

    def __init__(self, command, host, domain, noOutput, smbconnection, method):

        if method == 'wmi':
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

        elif method == 'smbexec':
            smb_exec = SMBEXEC(command,
                               '{}/SMB'.format(settings.args.port), 
                               settings.args.user,
                               settings.args.passwd, 
                               domain, 
                               settings.args.hash, 
                               settings.args.aesKey,
                               settings.args.kerb, 
                               'SHARE',
                               settings.args.share,
                               noOutput)
            smb_exec.run(host)

        elif method == 'atexec':
            atsvc_exec = TSCH_EXEC(command,
                                   settings.args.user, 
                                   settings.args.passwd, 
                                   domain,
                                   settings.args.hash, 
                                   settings.args.aesKey, 
                                   settings.args.kerb,
                                   noOutput)
            atsvc_exec.play(host)