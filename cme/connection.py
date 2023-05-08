#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import socket
from socket import AF_INET, AF_INET6, SOCK_DGRAM, IPPROTO_IP, AI_CANONNAME
from socket import getaddrinfo
from os.path import isfile
from threading import BoundedSemaphore
from functools import wraps
from time import sleep

from cme.config import pwned_label
from cme.helpers.logger import highlight
from cme.logger import cme_logger, CMEAdapter
from cme.context import Context

sem = BoundedSemaphore(1)
global_failed_logins = 0
user_failed_logins = {}


def gethost_addrinfo(hostname):
    try:
        for res in getaddrinfo(
            hostname,
            None,
            AF_INET6,
            SOCK_DGRAM,
            IPPROTO_IP,
            AI_CANONNAME,
        ):
            af, socktype, proto, canonname, sa = res
    except socket.gaierror:
        for res in getaddrinfo(
            hostname,
            None,
            AF_INET,
            SOCK_DGRAM,
            IPPROTO_IP,
            AI_CANONNAME,
        ):
            af, socktype, proto, canonname, sa = res
    if canonname == "":
        return sa[0]
    return canonname


def requires_admin(func):
    def _decorator(self, *args, **kwargs):
        if self.admin_privs is False:
            return
        return func(self, *args, **kwargs)

    return wraps(func)(_decorator)


class connection(object):
    def __init__(self, args, db, host):
        self.domain = None
        self.args = args
        self.db = db
        self.hostname = host
        self.conn = None
        self.admin_privs = False
        self.password = ""
        self.username = ""
        self.kerberos = True if self.args.kerberos or self.args.use_kcache else False
        self.aesKey = None if not self.args.aesKey else self.args.aesKey
        self.kdcHost = None if not self.args.kdcHost else self.args.kdcHost
        self.use_kcache = None if not self.args.use_kcache else self.args.use_kcache
        self.failed_logins = 0
        self.local_ip = None
        self.logger = cme_logger

        try:
            self.host = gethost_addrinfo(self.hostname)
            if self.args.kerberos:
                self.host = self.hostname
        except Exception as e:
            self.logger.info(f"Error resolving hostname {self.hostname}: {e}")
            return

        if args.jitter:
            jitter = args.jitter
            if "-" in jitter:
                start, end = jitter.split("-")
                jitter = (int(start), int(end))
            else:
                jitter = (0, int(jitter))

            value = random.choice(range(jitter[0], jitter[1]))
            self.logger.debug(f"Doin' the jitterbug for {value} second(s)")
            sleep(value)

        try:
            self.proto_flow()
        except Exception as e:
            self.logger.exception(f"Exception while calling proto_flow() on target {self.host}: {e}")

    @staticmethod
    def proto_args(std_parser, module_parser):
        return

    def proto_logger(self):
        pass

    def enum_host_info(self):
        return

    def print_host_info(self):
        return

    def create_conn_obj(self):
        return

    def check_if_admin(self):
        return

    def kerberos_login(
        self,
        domain,
        username,
        password="",
        ntlm_hash="",
        aesKey="",
        kdcHost="",
        useCache=False,
    ):
        return

    def plaintext_login(self, domain, username, password):
        return

    def hash_login(self, domain, username, ntlm_hash):
        return

    def proto_flow(self):
        self.logger.debug(f"Kicking off proto_flow")
        self.proto_logger()
        if self.create_conn_obj():
            self.enum_host_info()
            if self.print_host_info():
                # because of null session
                if self.login() or (self.username == "" and self.password == ""):
                    if hasattr(self.args, "module") and self.args.module:
                        self.call_modules()
                    else:
                        self.call_cmd_args()

    def call_cmd_args(self):
        for k, v in vars(self.args).items():
            if hasattr(self, k) and hasattr(getattr(self, k), "__call__"):
                if v is not False and v is not None:
                    self.logger.debug(f"Calling {k}()")
                    r = getattr(self, k)()

    def call_modules(self):
        for module in self.module:
            self.logger.debug(f"Loading module {module.name} - {module}")
            module_logger = CMEAdapter(
                extra={
                    "module_name": module.name.upper(),
                    "host": self.host,
                    "port": self.args.port,
                    "hostname": self.hostname,
                },
            )

            self.logger.debug(f"Loading context for module {module.name} - {module}")
            context = Context(self.db, module_logger, self.args)
            context.localip = self.local_ip

            if hasattr(module, "on_request") or hasattr(module, "has_response"):
                self.logger.debug(f"Module {module.name} has on_request or has_response methods")
                self.server.connection = self
                self.server.context.localip = self.local_ip

            if hasattr(module, "on_login"):
                self.logger.debug(f"Module {module.name} has on_login method")
                module.on_login(context, self)

            if self.admin_privs and hasattr(module, "on_admin_login"):
                self.logger.debug(f"Module {module.name} has on_admin_login method")
                module.on_admin_login(context, self)

            if (not hasattr(module, "on_request") and not hasattr(module, "has_response")) and hasattr(module, "on_shutdown"):
                self.logger.debug(f"Module {module.name} has on_shutdown method")
                module.on_shutdown(context, self)

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

        if global_failed_logins == self.args.gfail_limit:
            return True

        if self.failed_logins == self.args.fail_limit:
            return True

        if username in user_failed_logins.keys():
            if self.args.ufail_limit == user_failed_logins[username]:
                return True

        return False

    def login(self):
        for cred_id in self.args.cred_id:
            with sem:
                if cred_id.lower() == "all":
                    creds = self.db.get_credentials()
                else:
                    creds = self.db.get_credentials(filter_term=int(cred_id))

                for cred in creds:
                    self.logger.debug(cred)
                    try:
                        if self.protocol == "SSH":
                            c_id, username, password, cred_type = cred
                            if cred_type == "key":
                                key_data = self.db.get_keys(cred_id=cred_id)[0].data
                                if self.plaintext_login(username, password, private_key=key_data):
                                    return True
                        else:
                            # will probably need to add additional checks here for each protocol, but this was initially
                            # for SMB
                            (
                                c_id,
                                domain,
                                username,
                                password,
                                cred_type,
                                pillaged_from,
                            ) = cred

                        if cred_type and password:
                            if not domain:
                                domain = self.domain

                            if self.args.local_auth:
                                domain = self.domain
                            elif self.args.domain:
                                domain = self.args.domain

                            if cred_type == "hash" and not self.over_fail_limit(username):
                                if self.args.kerberos:
                                    if self.kerberos_login(
                                        domain,
                                        username,
                                        "",
                                        password,
                                        "",
                                        self.kdcHost,
                                        False,
                                    ):
                                        return True
                                elif self.hash_login(domain, username, password):
                                    return True
                            elif cred_type == "plaintext" and not self.over_fail_limit(username):
                                if self.args.kerberos:
                                    if self.kerberos_login(
                                        domain,
                                        username,
                                        password,
                                        "",
                                        "",
                                        self.kdcHost,
                                        False,
                                    ):
                                        return True
                                elif self.plaintext_login(domain, username, password):
                                    return True
                    except IndexError:
                        self.logger.fail("Invalid database credential ID!")
        if self.args.use_kcache:
            with sem:
                username = self.args.username[0] if len(self.args.username) else ""
                password = self.args.password[0] if len(self.args.password) else ""
                self.kerberos_login(self.domain, username, password, "", "", self.kdcHost, True)
                return True
        for user in self.args.username:
            if isfile(user):
                with open(user, "r") as user_file:
                    for usr in user_file:
                        if "\\" in usr:
                            tmp = usr
                            usr = tmp.split("\\")[1].strip()
                            self.domain = tmp.split("\\")[0]
                        if hasattr(self.args, "hash") and self.args.hash:
                            with sem:
                                for ntlm_hash in self.args.hash:
                                    if isfile(ntlm_hash):
                                        with open(ntlm_hash, "r") as ntlm_hash_file:
                                            if not self.args.no_bruteforce:
                                                for f_hash in ntlm_hash_file:
                                                    if not self.over_fail_limit(usr.strip()):
                                                        if self.args.kerberos:
                                                            if self.kerberos_login(
                                                                self.domain,
                                                                usr.strip(),
                                                                "",
                                                                f_hash.strip(),
                                                                "",
                                                                self.kdcHost,
                                                                False,
                                                            ):
                                                                return True
                                                        elif self.hash_login(
                                                            self.domain,
                                                            usr.strip(),
                                                            f_hash.strip(),
                                                        ):
                                                            return True
                                            elif self.args.no_bruteforce:
                                                user_file.seek(0)  # HACK: this should really not be in the usr for loop
                                                for usr, f_hash in zip(user_file, ntlm_hash_file):
                                                    if not self.over_fail_limit(usr.strip()):
                                                        if self.args.kerberos:
                                                            if self.kerberos_login(
                                                                self.domain,
                                                                usr.strip(),
                                                                "",
                                                                f_hash.strip(),
                                                                "",
                                                                self.kdcHost,
                                                                False,
                                                            ):
                                                                return True
                                                        elif self.hash_login(
                                                            self.domain,
                                                            usr.strip(),
                                                            f_hash.strip(),
                                                        ):
                                                            return True
                                    else:  # ntlm_hash is a string
                                        if not self.over_fail_limit(usr.strip()):
                                            if self.args.kerberos:
                                                if self.kerberos_login(
                                                    self.domain,
                                                    usr.strip(),
                                                    "",
                                                    ntlm_hash.strip(),
                                                    "",
                                                    self.kdcHost,
                                                    False,
                                                ):
                                                    return True
                                            elif self.hash_login(
                                                self.domain,
                                                usr.strip(),
                                                ntlm_hash.strip(),
                                            ):
                                                return True
                        elif self.args.password:
                            with sem:
                                for password in self.args.password:
                                    if isfile(password):
                                        with open(password, "r") as password_file:
                                            if not self.args.no_bruteforce:
                                                for f_pass in password_file:
                                                    if not self.over_fail_limit(usr.strip()):
                                                        if hasattr(self.args, "domain"):
                                                            if self.args.kerberos:
                                                                if self.kerberos_login(
                                                                    self.domain,
                                                                    usr.strip(),
                                                                    f_pass.strip(),
                                                                    "",
                                                                    "",
                                                                    self.kdcHost,
                                                                    False,
                                                                ):
                                                                    return True
                                                            elif self.plaintext_login(
                                                                self.domain,
                                                                usr.strip(),
                                                                f_pass.strip(),
                                                            ):
                                                                return True
                                                        else:
                                                            if self.plaintext_login(
                                                                usr.strip(),
                                                                f_pass.strip(),
                                                            ):
                                                                return True
                                            elif self.args.no_bruteforce:
                                                user_file.seek(0)  # HACK: this should really not be in the usr for loop
                                                for usr, f_pass in zip(user_file, password_file):
                                                    if not self.over_fail_limit(usr.strip()):
                                                        if hasattr(self.args, "domain"):
                                                            if self.args.kerberos:
                                                                if self.kerberos_login(
                                                                    self.domain,
                                                                    usr.strip(),
                                                                    f_pass.strip(),
                                                                    "",
                                                                    "",
                                                                    self.kdcHost,
                                                                    False,
                                                                ):
                                                                    return True
                                                            elif self.plaintext_login(
                                                                self.domain,
                                                                usr.strip(),
                                                                f_pass.strip(),
                                                            ):
                                                                return True
                                                        else:
                                                            if self.plaintext_login(
                                                                usr.strip(),
                                                                f_pass.strip(),
                                                            ):
                                                                return True
                                    else:  # password is a string
                                        if not self.over_fail_limit(usr.strip()):
                                            if hasattr(self.args, "domain"):
                                                if self.args.kerberos:
                                                    if self.kerberos_login(
                                                        self.domain,
                                                        usr.strip(),
                                                        password,
                                                        "",
                                                        "",
                                                        self.kdcHost,
                                                        False,
                                                    ):
                                                        return True
                                                elif self.plaintext_login(self.domain, usr.strip(), password):
                                                    return True
                                            else:
                                                if self.plaintext_login(usr.strip(), password):
                                                    return True
            else:  # user is a string
                if hasattr(self.args, "hash") and self.args.hash:
                    with sem:
                        for ntlm_hash in self.args.hash:
                            if isfile(ntlm_hash):
                                with open(ntlm_hash, "r") as ntlm_hash_file:
                                    for f_hash in ntlm_hash_file:
                                        if not self.over_fail_limit(user):
                                            if self.args.kerberos:
                                                if self.kerberos_login(
                                                    self.domain,
                                                    user,
                                                    "",
                                                    ntlm_hash.strip(),
                                                    "",
                                                    self.kdcHost,
                                                    False,
                                                ):
                                                    return True
                                            elif self.hash_login(self.domain, user, f_hash.strip()):
                                                return True
                            else:  # ntlm_hash is a string
                                if not self.over_fail_limit(user):
                                    if self.args.kerberos:
                                        if self.kerberos_login(
                                            self.domain,
                                            user,
                                            "",
                                            ntlm_hash.strip(),
                                            "",
                                            self.kdcHost,
                                            False,
                                        ):
                                            return True
                                    elif self.hash_login(self.domain, user, ntlm_hash.strip()):
                                        return True
                elif self.args.password:
                    with sem:
                        for password in self.args.password:
                            if isfile(password):
                                with open(password, "r") as password_file:
                                    for f_pass in password_file:
                                        if not self.over_fail_limit(user):
                                            if hasattr(self.args, "domain"):
                                                if self.args.kerberos:
                                                    if self.kerberos_login(
                                                        self.domain,
                                                        user,
                                                        f_pass.strip(),
                                                        "",
                                                        "",
                                                        self.kdcHost,
                                                        False,
                                                    ):
                                                        return True
                                                elif self.plaintext_login(self.domain, user, f_pass.strip()):
                                                    return True
                                            else:
                                                if self.plaintext_login(user, f_pass.strip()):
                                                    return True
                            else:  # password is a string
                                if not self.over_fail_limit(user):
                                    if hasattr(self.args, "domain"):
                                        if self.args.kerberos:
                                            if self.kerberos_login(
                                                self.domain,
                                                user,
                                                password,
                                                "",
                                                "",
                                                self.kdcHost,
                                                False,
                                            ):
                                                return True
                                        elif self.plaintext_login(self.domain, user, password):
                                            return True
                                    else:
                                        if self.plaintext_login(user, password):
                                            return True
                elif self.args.aesKey:
                    with sem:
                        for aesKey in self.args.aesKey:
                            if not self.over_fail_limit(user):
                                if self.kerberos_login(
                                    self.domain,
                                    user,
                                    "",
                                    "",
                                    aesKey.strip(),
                                    self.kdcHost,
                                    False,
                                ):
                                    return True

    def mark_pwned(self):
        return highlight(f"({pwned_label})" if self.admin_privs else "")
