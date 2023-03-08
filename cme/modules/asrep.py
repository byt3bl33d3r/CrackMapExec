#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket

class CMEModule:
    '''
        Extract all users who have AS-REP Roasting rights
        Module by @Shad0wC0ntr0ller
    '''
    name = 'asreproast'
    description = 'Extract all users who have AS-REP Roasting rights'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
    # Get the base DN for the domain
        domain_dn = ','.join(['DC=' + dc for dc in connection.domain.split('.')])

        # Search for AS-REP roasting vulnerable users
        search_filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
        attributes = ['cn', 'objectSid', 'distinguishedName', 'userAccountControl', 'servicePrincipalName']

        try:
            context.log.debug('Search Filter=%s' % search_filter)
            resp = connection.ldapConnection.search(searchBase=domain_dn, searchFilter=search_filter, attributes=attributes, sizeLimit=0)
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                context.log.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement paged queries
                resp = e.getAnswers()
                pass
            else:
                context.log.debug(e)
                return False

        users = []
        context.log.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            cn = ''
            sid = ''
            dn = ''
            uac = ''
            spn = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'cn':
                        cn = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'objectSid':
                        sid = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'distinguishedName':
                        dn = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'userAccountControl':
                        uac = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'servicePrincipalName':
                        spn = ', '.join(str(val) for val in attribute['vals'])

                if cn != '' and sid != '' and dn != '' and spn != '':
                    users.append((cn, sid, dn, uac, spn))
            except Exception as e:
                context.log.debug('Cannot process user due to error %s' % str(e))
                pass

        if len(users) > 0:
            context.log.success('Found the following AS-REP roasting vulnerable users:')
            for user in users:
                context.log.highlight('User: {} '.format(user[0]))
        else:
            context.log.info('No AS-REP roasting vulnerable users found')

        return True


