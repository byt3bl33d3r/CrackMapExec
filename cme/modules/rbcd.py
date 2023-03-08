#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
import os

class CMEModule:
    '''
        Extract all accounts that have Resource-Based Constrained Delegation enabled
    '''
    name = 'rbcd'
    description = 'Extract all accounts that have Resource-Based Constrained Delegation enabled'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
    # Get the base DN for the domain
        domain_dn = ','.join(['DC=' + dc for dc in connection.domain.split('.')])

        # Search for all user and computer accounts with Resource-Based Constrained Delegation enabled
        search_filter = '(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        attributes = ['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
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

        rbcd_accounts = []
        context.log.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            sAMAccountName = ''
            spns = []
            allowed_to_delegate_to = []
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'msDS-AllowedToActOnBehalfOfOtherIdentity':
                        for val in attribute['vals']:
                            spn_data = val.asOctets()
                            spn = spn_data.decode('utf-16-le')
                            spns.append(spn)
                            try:
                                domain = val.getComponentByName('domainName').getComponent().asOctets().decode()
                                username = val.getComponentByName('userName').getComponent().asOctets().decode()
                                allowed_to_delegate_to.append(f"{username}@{domain}")
                            except:
                                pass
                if sAMAccountName != '' and len(spns) > 0:
                    rbcd_accounts.append((sAMAccountName, spns, allowed_to_delegate_to))
            except Exception as e:
                context.log.debug('Cannot process account due to error %s' % str(e))
                pass

        
        if len(rbcd_accounts) > 0:
            context.log.success('Found the following accounts/computers with Resource-Based Constrained Delegation enabled:')
            with open('/tmp/rbcd_accounts.txt', 'w') as f:
                for account in rbcd_accounts:
                    context.log.highlight(account[0])
                    f.write('{}\n'.format(account[0]))
                    if len(account[2]) > 0:
                        context.log.highlight('  Allowed to delegate to:')
                        for atdt in account[2]:
                            context.log.highlight('    ' + atdt)

        else:
            context.log.info('No accounts/computers with Resource-Based Constrained Delegation found')

        return True



