import logging
import socket
from os.path import isfile
# from traceback import format_exc
from threading import BoundedSemaphore
from socket import gethostbyname
from functools import wraps
from cme.logger import CMEAdapter
from cme.context import Context
from cme.helpers.logger import write_log

sem = BoundedSemaphore(1)
global_failed_logins = 0
user_failed_logins = {}

def gethost_addrinfo(hostname):
    try:
        for res in socket.getaddrinfo(hostname, None, socket.AF_INET6,
                socket.SOCK_DGRAM, socket.IPPROTO_IP, socket.AI_CANONNAME):
            af, socktype, proto, canonname, sa = res
    except socket.gaierror:
        for res in socket.getaddrinfo(hostname, None, socket.AF_INET,
                socket.SOCK_DGRAM, socket.IPPROTO_IP, socket.AI_CANONNAME):
            af, socktype, proto, canonname, sa = res
    if canonname == '':
        return sa[0]
    return canonname

def requires_admin(func):
    def _decorator(self, *args, **kwargs):
        if self.admin_privs is False: return
        return func(self, *args, **kwargs)
    return wraps(func)(_decorator)


class connection(object):

    def __init__(self, args, db, host):
        self.args = args
        self.db = db
        self.hostname = host
        self.conn = None
        self.admin_privs = False
        self.logger = None
        self.password = ''
        self.username = ''
        self.kerberos = True if self.args.kerberos else False
        self.aesKey = None if not self.args.aesKey else self.args.aesKey
        self.kdcHost = None if not self.args.kdcHost else self.args.kdcHost
        self.export = None if not self.args.export else self.args.export
        self.failed_logins = 0
        self.local_ip = None

        try:
            self.host = gethost_addrinfo(self.hostname)
            if self.args.kerberos:
                self.host = self.hostname
        except Exception as e:
            logging.debug('Error resolving hostname {}: {}'.format(self.hostname, e))
            return

        self.proto_flow()

    @staticmethod
    def proto_args(std_parser, module_parser):
        return

    def proto_logger(self):
        pass

    def enum_host_info(self):
        return

    def print_host_info(info):
        return

    def create_conn_obj(self):
        return

    def check_if_admin(self):
        return

    def kerberos_login(self):
        return

    def plaintext_login(self, domain, username, password):
        return

    def hash_login(self, domain, username, ntlm_hash):
        return

    def proto_flow(self):
        if self.create_conn_obj():
            self.enum_host_info()
            self.proto_logger()
            self.print_host_info()
            # because of null session
            if self.login() or (self.username == '' and self.password == ''):
                if hasattr(self.args, 'module') and self.args.module:
                    self.call_modules()
                else:
                    self.call_cmd_args()

    def call_cmd_args(self):
        for k, v in vars(self.args).items():
            if hasattr(self, k) and hasattr(getattr(self, k), '__call__'):
                if v is not False and v is not None:
                    logging.debug('Calling {}()'.format(k))
                    r = getattr(self, k)()
                    if self.export:
                        write_log(str(r), self.export[0])

    def call_modules(self):
        module_logger = CMEAdapter(extra={
                                          'module': self.module.name.upper(),
                                          'host': self.host,
                                          'port': self.args.port,
                                          'hostname': self.hostname
                                         })

        context = Context(self.db, module_logger, self.args)
        context.localip  = self.local_ip

        if hasattr(self.module, 'on_request') or hasattr(self.module, 'has_response'):
            self.server.connection = self
            self.server.context.localip = self.local_ip

        if hasattr(self.module, 'on_login'):
            self.module.on_login(context, self)

        if self.admin_privs and hasattr(self.module, 'on_admin_login'):
            self.module.on_admin_login(context, self)

        if (not hasattr(self.module, 'on_request') and not hasattr(self.module, 'has_response')) and hasattr(self.module, 'on_shutdown'):
            self.module.on_shutdown(context, self)

    def inc_failed_login(self, username):
        global global_failed_logins
        global user_failed_logins

        if username not in user_failed_logins.keys():
            user_failed_logins[username] = 0

        user_failed_logins[username] += 1
        global_failed_logins += 1
        self.failed_logins += 1

    def over_fail_limit(self, username):
        global global_failed_logins
        global user_failed_logins

        if global_failed_logins == self.args.gfail_limit: return True

        if self.failed_logins == self.args.fail_limit: return True

        if username in user_failed_logins.keys():
            if self.args.ufail_limit == user_failed_logins[username]: return True

        return False

    def login(self):
        if self.args.kerberos:
            if self.kerberos_login(self.aesKey, self.kdcHost): return True
        else:
            for cred_id in self.args.cred_id:
                with sem:
                    if cred_id.lower() == 'all':
                        creds = self.db.get_credentials()
                    else:
                        creds = self.db.get_credentials(filterTerm=int(cred_id))

                    for cred in creds:
                        logging.debug(cred)
                        try:
                            c_id, domain, username, password, credtype, pillaged_from = cred

                            if credtype and password:

                                if not domain: domain = self.domain

                                if self.args.local_auth:
                                    domain = self.domain
                                elif self.args.domain:
                                    domain = self.args.domain

                                if credtype == 'hash' and not self.over_fail_limit(username):
                                    if self.hash_login(domain, username, password): return True

                                elif credtype == 'plaintext' and not self.over_fail_limit(username):
                                    if self.plaintext_login(domain, username, password): return True

                        except IndexError:
                            self.logger.error("Invalid database credential ID!")

            for user in self.args.username:
                if isfile(user):
                    with open(user, 'r') as user_file:
                        for usr in user_file:
                            if "\\" in usr:
                                tmp = usr
                                usr = tmp.split('\\')[1].strip()
                                self.domain = tmp.split('\\')[0]
                            if hasattr(self.args, 'hash') and self.args.hash:
                                with sem:
                                    for ntlm_hash in self.args.hash:
                                        if isfile(ntlm_hash):
                                            with open(ntlm_hash, 'r') as ntlm_hash_file:
                                                if self.args.no_bruteforce == False:
                                                    for f_hash in ntlm_hash_file:
                                                        if not self.over_fail_limit(usr.strip()):
                                                            if self.hash_login(self.domain, usr.strip(), f_hash.strip()): return True
                                                elif self.args.no_bruteforce == True:
                                                    user_file.seek(0) # HACK: this should really not be in the usr for loop
                                                    for usr, f_hash in zip(user_file, ntlm_hash_file):
                                                        if not self.over_fail_limit(usr.strip()):
                                                            if self.hash_login(self.domain, usr.strip(), f_hash.strip()): return True
                                        else: # ntlm_hash is a string
                                            if not self.over_fail_limit(usr.strip()):
                                                if self.hash_login(self.domain, usr.strip(), ntlm_hash.strip()): return True

                            elif self.args.password:
                                with sem:
                                    for password in self.args.password:
                                        if isfile(password):
                                            with open(password, 'r') as password_file:
                                                if self.args.no_bruteforce == False:
                                                    for f_pass in password_file:
                                                        if not self.over_fail_limit(usr.strip()):
                                                            if hasattr(self.args, 'domain'):
                                                                if self.plaintext_login(self.domain, usr.strip(), f_pass.strip()): return True
                                                            else:
                                                                if self.plaintext_login(usr.strip(), f_pass.strip()): return True
                                                elif self.args.no_bruteforce == True:
                                                    user_file.seek(0) # HACK: this should really not be in the usr for loop
                                                    for usr, f_pass in zip(user_file, password_file):
                                                        if not self.over_fail_limit(usr.strip()):
                                                            if hasattr(self.args, 'domain'):
                                                                if self.plaintext_login(self.domain, usr.strip(), f_pass.strip()): return True
                                                            else:
                                                                if self.plaintext_login(usr.strip(), f_pass.strip()): return True
                                        else: # password is a string
                                            if not self.over_fail_limit(usr.strip()):
                                                if hasattr(self.args, 'domain'):
                                                    if self.plaintext_login(self.domain, usr.strip(), password): return True
                                                else:
                                                    if self.plaintext_login(usr.strip(), password): return True

                else: # user is a string
                    if hasattr(self.args, 'hash') and self.args.hash:
                        with sem:
                            for ntlm_hash in self.args.hash:
                                if isfile(ntlm_hash):
                                    with open(ntlm_hash, 'r') as ntlm_hash_file:
                                        for f_hash in ntlm_hash_file:
                                            if not self.over_fail_limit(user):
                                                if self.hash_login(self.domain, user, f_hash.strip()): return True
                                else: # ntlm_hash is a string
                                    if not self.over_fail_limit(user):
                                        if self.hash_login(self.domain, user, ntlm_hash.strip()): return True

                    elif self.args.password:
                        with sem:
                            for password in self.args.password:
                                if isfile(password):
                                    with open(password, 'r') as password_file:
                                        for f_pass in password_file:
                                            if not self.over_fail_limit(user):
                                                if hasattr(self.args, 'domain'):
                                                    if self.plaintext_login(self.domain, user, f_pass.strip()): return True
                                                else:
                                                    if self.plaintext_login(user, f_pass.strip()): return True
                                else: # password is a string
                                    if not self.over_fail_limit(user):
                                        if hasattr(self.args, 'domain'):
                                            if self.plaintext_login(self.domain, user, password): return True
                                        else:
                                            if self.plaintext_login(user, password): return True

