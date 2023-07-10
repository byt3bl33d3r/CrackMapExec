#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import sys
sys.setrecursionlimit(10000)

class CMEModule:
    '''
      Module by CyberCelt

      Initial module:
        https://github.com/Cyb3rC3lt/CrackMapExec-Modules
    '''
    
    name = 'COMP-DESC'
    description = 'Retrieves computers containing the specified description'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        '''
        COMP-DESC: Specify COMP-DESC to call the module
        DESC: Specify the DESC option to enter your description text to search for
        Usage: cme ldap $DC-IP -u Username -p Password -M COMP-DESC -o DESC="server"
               cme ldap $DC-IP -u Username -p Password -M COMP-DESC -o DESC="XP"
        '''

        self.DESC = ''

        if 'DESC' in module_options:
            self.DESC = module_options['DESC']
        else:
            context.log.error('DESC option is required!')
            exit(1)

    def on_login(self, context, connection):

        # Building the search filter
        searchFilter = "(&(objectCategory=computer)(operatingSystem=*"+self.DESC+"*))"

        try:
            context.log.debug('Search Filter=%s' % searchFilter)
            resp = connection.ldapConnection.search(searchFilter=searchFilter,
                                        attributes=['dNSHostName','operatingSystem'],
                                        sizeLimit=0)
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                context.log.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                resp = e.getAnswers()
                pass
            else:
                logging.debug(e)
                return False

        answers = []
        context.log.debug('Total no. of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            dNSHostName =  ''
            operatingSystem = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'dNSHostName':
                        dNSHostName = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'operatingSystem':
                        operatingSystem = attribute['vals'][0]
                if dNSHostName != '' and operatingSystem != '':
                    answers.append([dNSHostName,operatingSystem])
            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug('Skipping item, cannot process due to error %s' % str(e))
                pass
        if len(answers) > 0:
            context.log.success('Found the following computers: ')
            for answer in answers:
                try:
                 IP = socket.gethostbyname(answer[0])
                 context.log.highlight(u'{} ({}) ({})'.format(answer[0],answer[1],IP))
                 context.log.debug('IP found')
                except socket.gaierror as e:
                 context.log.debug('Missing IP')
                 context.log.highlight(u'{} ({}) ({})'.format(answer[0],answer[1],"No IP Found"))
        else:
            context.log.success('Unable to find any computers with the description "' + self.DESC + '"')
