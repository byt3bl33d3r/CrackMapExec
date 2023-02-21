#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
import os

class CMEModule:
    '''
        Extract obsolete operating systems from LDAP
        Module by @Shad0wC0ntr0ller
    '''
    name = 'obsolete'
    description = 'Extract all obsolete operating systems from LDAP'
    supported_protocols = ['ldap']
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
    
        search_filter = "(&(objectclass=computer)(|(operatingSystem=*Windows 6*)(operatingSystem=*Windows 2000*)(operatingSystem=*Windows XP*)(operatingSystem=*Windows Vista*)(operatingSystem=*Windows 7*)(operatingSystem=*Windows 8*)(operatingSystem=*Windows 8.1*)(operatingSystem=*Windows Server 2003*)(operatingSystem=*Windows Server 2008*)))"
        attributes = ['name', 'operatingSystem']

        try:
            context.log.debug('Search Filter=%s' % search_filter)
            resp = connection.ldapConnection.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                context.log.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement paged queries
                resp = e.getAnswers()
                pass
            else:
                context.log.debug(e)
                return False

        answers = []
        context.log.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            name = ''
            os = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'name':
                        name = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'operatingSystem':
                        os = str(attribute['vals'][0])
                if name != '' and os != '':
                    answers.append([name, os])
            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug('Skipping item, cannot process due to error %s' % str(e))
                pass

        if len(answers) > 0:
            context.log.success('Found the following obsolete operating systems:')
            for answer in answers:
                context.log.highlight(u'Obsolete System: {} : {}'.format(answer[0], answer[1]))
                
                filename = '/tmp/obsoletehosts.txt'
                with open(filename, 'a') as f:
                    f.write(answer[0] + '\n')

        return True

