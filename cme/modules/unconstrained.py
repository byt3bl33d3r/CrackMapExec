#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
import os

class CMEModule:
    '''
        Extract all users or computers who are configured with unconstrained delegation
        and where they are allowed to delegate to
    '''
    name = 'ud'
    description = 'Extract all users or computers who are configured with unconstrained delegation'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        # Get the base DN for the domain
        domain_dn = ','.join(['DC=' + dc for dc in connection.domain.split('.')])

        # Search for all user and computer accounts with msDS-AllowedToDelegateTo attribute
        search_filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
        attributes = ['sAMAccountName', 'servicePrincipalName']
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

        unconstrained_delegation = []
        context.log.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            sAMAccountName = ''
            spns = []
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'servicePrincipalName':
                        for val in attribute['vals']:
                            spns.append(str(val))
                if sAMAccountName != '' and len(spns) > 0:
                    unconstrained_delegation.append((sAMAccountName, spns))
            except Exception as e:
                context.log.debug('Cannot process account due to error %s' % str(e))
                pass

        if len(unconstrained_delegation) > 0:
            context.log.success('Found the following accounts/computers with unconstrained delegation enabled:')
            with open('/tmp/unconstrained_delegation.txt', 'w') as f:
                for account in unconstrained_delegation:
                    hostname = None
                    for spn in account[1]:
                        if 'HOST' in spn:
                            hostname = spn.split('/')[1].split('.')[0]
                            break
                    if hostname:
                        context.log.highlight(hostname)
                        f.write(hostname + '\n')
        else:
            context.log.info('No accounts/computers with unconstrained delegation found')
        return True

