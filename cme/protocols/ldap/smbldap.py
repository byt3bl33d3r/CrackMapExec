import logging
import random
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.ldap import ldap as ldap_impacket
from cme.logger import CMEAdapter

class LDAPConnect:

    def __init__(self, host, port, hostname):
        self.proto_logger(host, port, hostname)

    def proto_logger(self, host, port, hostname):
        self.logger = CMEAdapter(extra={
                                        'protocol': 'LDAP',
                                        'host': host,
                                        'port': port,
                                        'hostname': hostname
                                        })

    def plaintext_login(self, domain, username, password, ntlm_hash):

        lmhash = ''
        nthash = ''
        

        #This checks to see if we didn't provide the LM Hash
        if ntlm_hash and ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        elif ntlm_hash:
            nthash = ntlm_hash

        # Create the baseDN
        baseDN = ''
        domainParts = domain.split('.')
        for i in domainParts:
            baseDN += 'dc=%s,' % i
        # Remove last ','
        baseDN = baseDN[:-1]

        try:
            ldapConnection = ldap_impacket.LDAPConnection('ldap://%s' % domain, baseDN, domain)
            ldapConnection.login(username, password, domain, lmhash, nthash)

            # Connect to LDAP
            out = u'{}{}:{}'.format('{}\\'.format(domain),
                                                username,
                                                password if password else ntlm_hash)
            self.logger.extra['protocol'] = "LDAP"
            self.logger.extra['port'] = "389"
            # self.logger.success(out)

            return ldapConnection

        except ldap_impacket.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                try:
                    ldapConnection = ldap_impacket.LDAPConnection('ldaps://%s' % domain, baseDN, domain)
                    ldapConnection.login(username, password, domain, lmhash, nthash)
                    self.logger.extra['protocol'] = "LDAPS"
                    self.logger.extra['port'] = "636"
                    # self.logger.success(out)
                    return ldapConnection
                except ldap_impacket.LDAPSessionError as e:
                    errorCode = str(e).split()[-2][:-1]
                    self.logger.error(u'{}\\{}:{}'.format(domain, 
                                                    username, 
                                                    password))
            else:
                errorCode = str(e).split()[-2][:-1]
                self.logger.error(u'{}\\{}:{}'.format(domain, 
                                                 username, 
                                                 password))
            return False

        except OSError as e:
            self.logger.error(u'{}\\{}:{} {}'.format(domain, 
                                                 username, 
                                                 password,
                                                 "Error connecting to the domain, please add option --kdcHost with the FQDN of the domain controller"))
            return False


    def hash_login(self, domain, username, ntlm_hash):
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

        if self.kdcHost is not None:
            target = self.kdcHost
        else:
            target = domain
            self.kdcHost = domain

        # Create the baseDN
        self.baseDN = ''
        domainParts = self.kdcHost.split('.')
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        if self.hash == '' and self.args.asreproast:
            hash_TGT = KerberosAttacks(self).getTGT_asroast(self.username)
            if hash_TGT:
                self.logger.highlight(u'{}'.format(hash_TGT))
                with open(self.args.asreproast, 'a+') as hash_asreproast:
                    hash_asreproast.write(hash_TGT + '\n')
            return False

        # Connect to LDAP
        try:
            self.ldapConnection = ldap_impacket.LDAPConnection('ldap://%s' % target, self.baseDN, self.kdcHost)
            self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()
            out = u'{}{}:{} {}'.format('{}\\'.format(domain),
                                    username,
                                    nthash,
                                    highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else ''))
            self.logger.extra['protocol'] = "LDAP"
            self.logger.extra['port'] = "389"
            # self.logger.success(out)

            if not self.args.continue_on_success:
                return True
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                try:
                    # We need to try SSL
                    self.ldapConnection = ldap_impacket.LDAPConnection('ldaps://%s' % target, self.baseDN, self.kdcHost)
                    self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
                    self.logger.extra['protocol'] = "LDAPS"
                    self.logger.extra['port'] = "636"
                    # self.logger.success(out)
                except ldap_impacket.LDAPSessionError as e:
                    errorCode = str(e).split()[-2][:-1]
                    self.logger.error(u'{}\\{}:{} {}'.format(self.domain, 
                                                    self.username, 
                                                    self.password,
                                                    ldap_error_status[errorCode] if errorCode in ldap_error_status else ''),
                                                    color='magenta' if errorCode in ldap_error_status else 'red')
            else:
                errorCode = str(e).split()[-2][:-1]
                self.logger.error(u'{}\\{}:{} {}'.format(self.domain, 
                                                 self.username, 
                                                 self.password,
                                                 ldap_error_status[errorCode] if errorCode in ldap_error_status else ''),
                                                 color='magenta' if errorCode in ldap_error_status else 'red')
            return False
        except OSError as e:
            self.logger.error(u'{}\\{}:{} {}'.format(self.domain, 
                                                 self.username, 
                                                 self.nthash,
                                                 "Error connecting to the domain, please add option --kdcHost with the FQDN of the domain controller"))
            return False