import re

from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldap import LDAPSearchError

class CMEModule:
    '''
    Find PKI Enrollment Services in Active Directory.

    Module by Tobias Neitzel (@qtc_de)
    '''
    name = 'adcs'
    description = 'Find PKI Enrollment Services in Active Directory'
    supported_protocols = ['ldap']
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        The module does not support any module specific options. Instead, just configure
        some attributes that are required throughout the script.
        '''
        self.context = context
        self.regex = re.compile('(https?://.+)')

    def on_login(self, context, connection):
        '''
        On a successful LDAP login we perform a search for all PKI Enrollment Services.
        '''
        search_filter = '(objectClass=pKIEnrollmentService)'

        context.log.debug("Starting LDAP search with search filter '{}'".format(search_filter))

        try:
            sc = ldap.SimplePagedResultsControl()
            resp = connection.ldapConnection.search(searchFilter=search_filter,
                                        attributes=['dNSHostName', 'msPKI-Enrollment-Servers'],
                                        sizeLimit=0, searchControls=[sc],
                                        perRecordCallback=self.process_record,
                                        searchBase='CN=Configuration,' + connection.ldapConnection._baseDN)

        except LDAPSearchError as e:
            context.log.error('Obtained unexpected exception: {}'.format(str(e)))

    def process_record(self, item):
        '''
        Function that is called to process the items obtain by the LDAP search.
        '''
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return

        urls = []
        host_name = None

        try:

            for attribute in item['attributes']:

                if str(attribute['type']) == 'dNSHostName':
                    host_name = attribute['vals'][0].asOctets().decode('utf-8')

                elif str(attribute['type']) == 'msPKI-Enrollment-Servers':

                    values = attribute['vals']

                    for value in values:

                        value = value.asOctets().decode('utf-8')
                        match = self.regex.search(value)

                        if match:
                            urls.append(match.group(1))

        except Exception as e:
            entry = host_name or 'item'
            self.context.log.error("Skipping {}, cannot process LDAP entry due to error: '{}'".format(entry, str(e)))

        if host_name:
            self.context.log.highlight('Found PKI Enrollment Server: {}'.format(host_name))

        for url in urls:
            self.context.log.highlight('Found PKI Enrollment WebService: {}'.format(url))
