import settings
import os
import socket
from impacket.smbconnection import SessionError


def hash_login(connection, user, domain, ntlm_hash, cme_logger):
    if str(connection).find('SMBConnection') != -1:
        lmhash, nthash = ntlm_hash.split(':')
        if settings.args.kerb:
            connection.kerberosLogin(user, '', domain, lmhash, nthash, settings.args.aesKey)
        else:
            connection.login(user, '', domain, lmhash, nthash)

        cme_logger.success(u"Login successful {}\\{}:{}".format(domain, user, ntlm_hash))
        return connection, user, None, ntlm_hash, domain

    elif str(connection).find('MSSQL') != -1:
        try:
            if settings.args.kerb:
                res = connection.kerberosLogin(None, user, '', domain, ntlm_hash, settings.args.aesKey)
                if res is not True:
                    connection.printReplies()
                    raise Exception
            else:
                res = connection.login(None, user, '', domain, ntlm_hash, True)
                if res is not True:
                    connection.printReplies()
                    raise Exception
            
            cme_logger.success(u"Login successful {}\\{}:{}".format(domain, user, ntlm_hash))
            return connection, user, None, ntlm_hash, domain

        except Exception as e:
            cme_logger.error(str(e))

def normal_login(connection, user, passwd, domain, cme_logger):
    if str(connection).find('SMBConnection') != -1:
        if settings.args.kerb:
            connection.kerberosLogin(user, passwd, domain, '', '', settings.args.aesKey)
        else:
            connection.login(user, passwd, domain, '', '')

        cme_logger.success(u"Login successful {}\\{}:{}".format(domain, user, passwd))
        return connection, user, passwd, None, domain

    elif str(connection).find('MSSQL') != -1:
        try:
            if settings.args.kerb:
                res = connection.kerberosLogin(None, user, passwd, domain, None, settings.args.aesKey)
                if res is not True:
                    connection.printReplies()
                    raise Exception
            else:
                res = connection.login(None, user, passwd, domain, None, True)
                if res is not True:
                    connection.printReplies()
                    raise Exception
            
            cme_logger.success(u"Login successful {}\\{}:{}".format(domain, user, passwd))
            return connection, user, passwd, None, domain

        except Exception as e:
            cme_logger.error(str(e))

def smart_login(host, domain, connection, cme_logger):

    usernames  = []
    user_files = []
    passwords  = []
    pass_files = []
    hashes     = []
    hash_files = []

    fails = 0

    if settings.args.combo_file:
        with open(settings.args.combo_file, 'r') as combo_file:
            for line in combo_file:

                if settings.args.fail_limit:
                    if settings.args.fail_limit == fails:
                        cme_logger.info('Reached login fail limit')
                        raise socket.error
                
                if settings.args.gfail_limit:
                    if settings.gfails >= settings.args.gfail_limit:
                        cme_logger.info('Reached global login fail limit')
                        raise socket.error

                try:
                    line = line.strip()

                    #Ok , we're dealing with an entry in pwdump format
                    if line[-3:] == ':::':
                        line = line[:-3]
                        domain_user, uid, lmhash, nthash = line.split(':')
                        ntlm_hash = '{}:{}'.format(lmhash, nthash)
                        if '\\' in domain_user:
                            domain, user = domain_user.split('\\')
                        else:
                            user = domain_user

                        try:
                            return hash_login(connection, user, domain, ntlm_hash, cme_logger)
                        except SessionError as e:
                            cme_logger.error(u"{}\\{}:{} {}".format(domain, user, ntlm_hash, e))
                            if 'STATUS_LOGON_FAILURE' in str(e):
                                fails += 1
                                settings.gfails += 1
                            continue

                    elif line[-3] != ':::':
                        if '\\' in line:
                            domain, user_pass = line.split('\\')
                        else:
                            user_pass = line

                        if len(user_pass.split(':')) == 3:
                            hash_or_pass = ':'.join(user_pass.split(':')[1:3]).strip()

                            #Not the best way to determine of it's an NTLM hash, this needs to be changed
                            if len(hash_or_pass) == 65 and len(hash_or_pass.split(':')[0]) == 32 and len(hash_or_pass.split(':')[1]) == 32:
                                user = user_pass.split(':')[0]
                                try:
                                    return hash_login(connection, user, domain, hash_or_pass, cme_logger)
                                except SessionError as e:
                                    cme_logger.error(u"{}\\{}:{} {}".format(domain, user, hash_or_pass, e))
                                    if 'STATUS_LOGON_FAILURE' in str(e):
                                        fails += 1
                                        settings.gfails += 1
                                    continue

                        elif len(user_pass.split(':')) == 2:
                            user, passwd = user_pass.split(':')
                            try:
                                return normal_login(connection, user, passwd, domain, cme_logger)
                            except SessionError as e:
                                cme_logger.error(u"{}\\{}:{} {}".format(domain, user, passwd, e))
                                if 'STATUS_LOGON_FAILURE' in str(e):
                                    fails += 1
                                    settings.gfails += 1
                                continue

                except Exception as e:
                    cme_logger.error("Error parsing line '{}' in combo file: {}".format(line, e))
                    continue

    for user in settings.args.user:
        if os.path.exists(user):
            user_files.append(open(user, 'r'))
        else:
            usernames.append(user)

    for passwd in settings.args.passwd:
        if os.path.exists(passwd):
            pass_files.append(open(passwd, 'r'))
        else:
            passwords.append(passwd)

    for ntlm_hash in settings.args.hash:
        if os.path.exists(ntlm_hash):
            hash_files.append(open(ntlm_hash, 'r'))
        else:
            hashes.append(ntlm_hash)

    for user in usernames:

        if settings.args.fail_limit:
            if settings.args.fail_limit == fails:
                cme_logger.info('Reached login fail limit')
                raise socket.error
        
        if settings.args.gfail_limit:
            if settings.gfails >= settings.args.gfail_limit:
                cme_logger.info('Reached global login fail limit')
                raise socket.error

        if hashes:
            for ntlm_hash in hashes:
                try:
                    return hash_login(connection, user, domain, ntlm_hash, cme_logger)
                except SessionError as e:
                    cme_logger.error(u"{}\\{}:{} {}".format(domain, user, ntlm_hash, e))
                    if 'STATUS_LOGON_FAILURE' in str(e):
                        fails += 1
                        settings.gfails += 1
                    continue

        if passwords:
            for passwd in passwords:
                try:
                    return normal_login(connection, user, passwd, domain, cme_logger)
                except SessionError as e:
                    cme_logger.error(u"{}\\{}:{} {}".format(domain, user, passwd, e))
                    if 'STATUS_LOGON_FAILURE' in str(e):
                        fails += 1
                        settings.gfails += 1
                    continue

    for user_file in user_files:
        for user in user_file:

            if settings.args.fail_limit:
                if settings.args.fail_limit == fails:
                    cme_logger.info('Reached login fail limit')
                    raise socket.error
            
            if settings.args.gfail_limit:
                if settings.gfails >= settings.args.gfail_limit:
                    cme_logger.info('Reached global login fail limit')
                    raise socket.error

            user = user.strip()

            if hash_files:
                for hash_file in hash_files:
                    for ntlm_hash in hash_file:
                        try:
                            return hash_login(connection, user, domain, ntlm_hash, cme_logger)
                        except SessionError as e:
                            cme_logger.error(u"{}\\{}:{} {}".format(domain, user, ntlm_hash, e))
                            if 'STATUS_LOGON_FAILURE' in str(e):
                                fails += 1
                                settings.gfails += 1

                    hash_file.seek(0)


            if pass_files:
                for pass_file in pass_files:
                    for passwd in pass_file:
                        try:
                            return normal_login(connection, user, passwd, domain, cme_logger)
                        except SessionError as e:
                            cme_logger.error(u"{}\\{}:{} {}".format(domain, user, passwd, e))
                            if 'STATUS_LOGON_FAILURE' in str(e):
                                fails += 1
                                settings.gfails += 1

                    pass_file.seek(0)

    raise socket.error