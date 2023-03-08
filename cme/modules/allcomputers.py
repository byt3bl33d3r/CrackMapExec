#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
import os

class CMEModule:
    '''
        Retrieve all enabled computers and save the full hostname to a file called allcomputers.txt in the /tmp/ directory
        Module by @Shad0wC0ntr0ller
    '''
    name = 'enum_computers'
    description = 'Retrieve all enabled computers and save the full hostname to a file called allcomputers.txt in the /tmp/ directory'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        # Get the base DN for the domain
        domain_dn = ','.join(['DC=' + dc for dc in connection.domain.split('.')])

        # Search for all enabled computers
        search_filter = '(objectClass=computer)'
        attributes = ['dNSHostName']
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

        computers = []
        context.log.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            hostname = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'dNSHostName':
                        hostname = str(attribute['vals'][0])
                if hostname != '' and hostname not in computers:
                    computers.append(hostname)
            except Exception as e:
                context.log.debug('Cannot process computer due to error %s' % str(e))
                pass

        if len(computers) > 0:
            # Save the full hostname to a file called allcomputers.txt in the /tmp/ directory
            with open('/tmp/allcomputers.txt', 'w') as f:
                for computer in computers:
                    f.write(computer + '\n')
            context.log.success('Found %d enabled computers. Full hostname saved to /tmp/allcomputers.txt' % len(computers))

        else:
            context.log.info('No enabled computers found')

        return True

