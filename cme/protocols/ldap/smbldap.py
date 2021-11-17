import logging
import random
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.ldap import ldap as ldap_impacket
from cme.logger import CMEAdapter


ldap_error_status = {
    "533":"STATUS_ACCOUNT_DISABLED",
    "701":"STATUS_ACCOUNT_EXPIRED",
    "531":"STATUS_ACCOUNT_RESTRICTION",
    "530":"STATUS_INVALID_LOGON_HOURS",
    "532":"STATUS_PASSWORD_EXPIRED",
    "773":"STATUS_PASSWORD_MUST_CHANGE",
    "775":"USER_ACCOUNT_LOCKED",
    "50":"LDAP_INSUFFICIENT_ACCESS"
}


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
                    self.logger.error(u'{}\\{}:{} {}'.format(domain, 
                                                    username, 
                                                    password if password else ntlm_hash,
                                                    ldap_error_status[errorCode] if errorCode in ldap_error_status else ''),
                                                    color='magenta' if errorCode in ldap_error_status else 'red')
            else:
                errorCode = str(e).split()[-2][:-1]
                self.logger.error(u'{}\\{}:{} {}'.format(domain, 
                                                username, 
                                                password if password else ntlm_hash,
                                                ldap_error_status[errorCode] if errorCode in ldap_error_status else ''),
                                                color='magenta' if errorCode in ldap_error_status else 'red')
            return False

        except OSError as e:
            self.logger.error(u'{}\\{}:{} {}'.format(domain, 
                                                 username, 
                                                 password if password else ntlm_hash,
                                                 "Error connecting to the domain, please add option --kdcHost with the FQDN of the domain controller"))
            return False

