from core.utils import shutdown
from core.logger import *
from impacket.nmb import NetBIOSError
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.rpcrt import DCERPCException
from core.scripts.wmiexec import WMIEXEC
from smartlogin import smart_login
from time import time
import os
import socket
import StringIO
import settings
import traceback
import socket
import csv

def connect(host):
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

        print_status("{}:{} is running {} (name:{}) (domain:{})".format(host, settings.args.port, smb.getServerOS(), s_name, domain))

        '''
        DC's seem to want us to logoff first
        Workstations sometimes reset the connection, so we handle both cases here
        '''
        try:
            smb.logoff()
        except NetBIOSError:
            pass
        except socket.error:
            smb = SMBConnection(host, host, None, settings.args.port)

        if (settings.args.user is not None and (settings.args.passwd is not None or settings.args.hash is not None)) or settings.args.combo_file:

            smb = smart_login(host, smb, domain)

            noOutput = False
            local_ip = smb.getSMBServer().get_socket().getsockname()[0]

            if settings.args.download:
                out = open(settings.args.download.split('\\')[-1], 'wb')
                smb.getFile(settings.args.share, settings.args.download, out.write)
                print_succ("{}:{} {} Downloaded file".format(host, settings.args.port, s_name))

            if settings.args.delete:
                smb.deleteFile(settings.args.share, settings.args.delete)
                print_succ("{}:{} {} Deleted file".format(host, settings.args.port, s_name))

            if settings.args.upload:
                up = open(settings.args.upload[0] , 'rb')
                smb.putFile(settings.args.share, settings.args.upload[1], up.read)
                print_succ("{}:{} {} Uploaded file".format(host, settings.args.port, s_name))

            if settings.args.list:
                if settings.args.list == '' or settings.args.list == '.' : 
                    settings.args.list = '*'
                else:
                    settings.args.list = settings.args.list + '/*'

                dir_list = smb.listPath(settings.args.share, settings.args.list)
                if settings.args.list == '*':
                    settings.args.list = settings.args.share
                else:
                    settings.args.list = settings.args.share + '/' + settings.args.list[:-2]

                print_succ("{}:{} Contents of {}:".format(host, settings.args.port, settings.args.list))
                for f in dir_list:
                    print_att("{}rw-rw-rw- {:>7} {} {}".format('d' if f.is_directory() > 0 else '-', 
                                                             f.get_filesize(),
                                                             strftime('%Y-%m-%d %H:%M', localtime(f.get_mtime_epoch())), 
                                                             f.get_longname()))

            if settings.args.spider:
                start_time = time()
                print_status("{}:{} {} Started spidering".format(host, settings.args.port, s_name))
                spider(smb, host, settings.args.share, settings.args.spider, settings.args.pattern, settings.args.depth)
                print_status("{}:{} {} Done spidering (Completed in {})".format(host, settings.args.port, s_name, time() - start_time))

            if settings.args.command:
                if settings.args.execm == 'wmi':
                    wmi_exec = WMIEXEC(settings.args.command, settings.args.user, settings.args.passwd, domain, settings.args.hash, settings.args.aesKey, settings.args.share, noOutput, settings.args.kerb)
                    wmi_exec.run(host)

                elif settings.args.execm == 'smbexec':
                    smb_exec = CMDEXEC(settings.args.command , settings.args.port, username, password, domain, options.hashes, options.aesKey, options.k, options.mode, options.share)
                    smb_exec.run(host)

                elif setting.args.execm == 'atexec':
                    atsvc_exec = TSCH_EXEC(username, password, domain, options.hashes, options.aesKey, options.k, settings.args.command)
                    atsvc_exec.play(address)

                elif settings.args.execm == 'psexec':
                    executer = PSEXEC(command, options.path, options.file, options.c, None, username, password, domain, options.hashes, options.aesKey, options.k)
                    executer.run(address)

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
