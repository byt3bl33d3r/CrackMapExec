from logger import *
from impacket.smbconnection import SessionError
import socket
import settings
import os
import csv
import StringIO

def smart_login(host, smb, domain):
    '''
        This function should probably be called ugly_login
    ''' 
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
                        or, in the unlikely event, the plain-text password contains a ':' (pfft who am I kidding)
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
                        settings.args.user = user
                        settings.args.passwd = passwd
                        settings.args.hash = ':'.join(lmhash, nthash)
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
                    This is in case a password contains a comma (lol!), we can use '\\' to make sure it's parsed correctly
                    IMHO this is a much better (much lazier) way than writing a custom split() function
                '''
                try:
                    passwords = csv.reader(StringIO.StringIO(settings.args.passwd), delimiter=',', escapechar='\\').next()
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
                        settings.args.user = user
                        settings.args.hash = ntlm_hash
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
                        settings.args.user = user
                        settings.args.passwd = passwd
                        return smb
                    except SessionError as e:
                        print_error("{}:{} {}\\{}:{} {}".format(host, settings.args.port, domain, user, passwd, e))
                        continue

    raise socket.error #So we fail without a peep