#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
import os

class CMEModule:
    '''
        Extract all users or computers who are configured with constrained delegation
        and where they are allowed to delegate to
    '''
    name = 'constrained-delegation'
    description = 'Extract all users or computers who are configured with constrained delegation'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        # Get the base DN for the domain
        domain_dn = ','.join(['DC=' + dc for dc in connection.domain.split('.')])

        # Search for all user and computer accounts with msDS-AllowedToDelegateTo attribute
        search_filter = '(&(objectClass=user)(msDS-AllowedToDelegateTo=*))'
        attributes = ['sAMAccountName', 'msDS-AllowedToDelegateTo']
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

        constrained_delegation = []
        context.log.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            sAMAccountName = ''
            allowed_to_delegate_to = []
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'msDS-AllowedToDelegateTo':
                        for val in attribute['vals']:
                            allowed_to_delegate_to.append(str(val))
                if sAMAccountName != '' and len(allowed_to_delegate_to) > 0:
                    constrained_delegation.append((sAMAccountName, allowed_to_delegate_to))
            except Exception as e:
                context.log.debug('Cannot process account due to error %s' % str(e))
                pass

        if len(constrained_delegation) > 0:
            context.log.success('Found the following accounts/computers with constrained delegation enabled:')
            allowed_to_delegate_to_list = []
            for account in constrained_delegation:
                context.log.highlight('{}\t{}'.format(account[0], account[1]))

                # Search for the SPNs that the account is allowed to delegate to
                search_filter = '(&(objectClass=user)(sAMAccountName={})(msDS-AllowedToDelegateTo=*))'.format(account[0])
                attributes = ['msDS-AllowedToDelegateTo']
                try:
                    resp = connection.ldapConnection.search(searchBase=domain_dn, searchFilter=search_filter, attributes=attributes, sizeLimit=0)
                except ldap_impacket.LDAPSearchError as e:
                    context.log.debug(e)
                    return False

                if len(resp) > 0:
                    for item in resp:
                        if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                            continue
                        try:
                            for attribute in item['attributes']:
                                if str(attribute['type']) == 'msDS-AllowedToDelegateTo':
                                    spns = attribute['vals']
                            if spns:
                                allowed_to_delegate_to_list.extend(spns)
                        except Exception as e:
                            context.log.debug('Cannot process constrained delegation object due to error %s' % str(e))
                            pass




                       



