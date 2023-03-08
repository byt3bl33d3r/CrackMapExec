#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
import os

class CMEModule:
    '''
        Retrieve all users who are members of the "Domain Admins" group
        Module by @Shad0wC0ntr0ller
    '''
    name = 'enum_da'
    description = 'Retrieve all users who are members of the "Domain Admins" group'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        # Get the base DN for the domain
        domain_dn = ','.join(['DC=' + dc for dc in connection.domain.split('.')])

        # Search for all users who are members of the Domain Admins group
        search_filter = '(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,{0}))'.format(domain_dn)
        attributes = ['sAMAccountName']
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

        domain_admins = []
        context.log.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            username = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        username = str(attribute['vals'][0])
                if username != '':
                    domain_admins.append(username)
            except Exception as e:
                context.log.debug('Cannot process user due to error %s' % str(e))
                pass

        if len(domain_admins) > 0:
            context.log.success('Found the following domain admins:')
            for username in domain_admins:
                context.log.highlight('{} -> Domain Admin'.format(username))

        else:
            context.log.info('No domain admins found')

        return True

