#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
import os

class CMEModule:
    '''
        Extract all Trust Relationships and Trusting Direction
        Module by @Shad0wC0ntr0ller
    '''
    name = 'enum_trusts'
    description = 'Extract all Trust Relationships and Trusting Direction'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
    # Get the base DN for the domain
        domain_dn = ','.join(['DC=' + dc for dc in connection.domain.split('.')])

        # Search for all trust relationships
        search_filter = '(&(objectClass=trustedDomain))'
        attributes = ['flatName', 'trustPartner', 'trustDirection']
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

        trusts = []
        context.log.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            flat_name = ''
            trust_partner = ''
            trust_direction = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'flatName':
                        flat_name = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'trustPartner':
                        trust_partner = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'trustDirection':
                        if str(attribute['vals'][0]) == '1':
                            trust_direction = 'Inbound'
                        elif str(attribute['vals'][0]) == '2':
                            trust_direction = 'Outbound'
                        elif str(attribute['vals'][0]) == '3':
                            trust_direction = 'Bidirectional'
                if flat_name != '' and trust_partner != '' and trust_direction != '':
                    trusts.append((flat_name, trust_partner, trust_direction))
            except Exception as e:
                context.log.debug('Cannot process trust relationship due to error %s' % str(e))
                pass

        if len(trusts) > 0:
            context.log.success('Found the following trust relationships:')
            for trust in trusts:
                context.log.highlight('{} -> {}'.format(trust[1], trust[2]))

        else:
            context.log.info('No trust relationships found')

        return True



