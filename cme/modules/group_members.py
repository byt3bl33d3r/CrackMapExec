#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket

class CMEModule:
    '''
      Module by CyberCelt: @Cyb3rC3lt

      Initial module:
        https://github.com/Cyb3rC3lt/CrackMapExec-Modules
    '''

    name = 'group-mem'
    description = 'Retrieves all the members within a Group'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    primaryGroupID = ''
    answers = []

    def options(self, context, module_options):
        '''
        group-mem: Specify group-mem to call the module
        GROUP: Specify the GROUP option to query for that group's members
        Usage: cme ldap $DC-IP -u Username -p Password -M group-mem -o GROUP="domain admins"
               cme ldap $DC-IP -u Username -p Password -M group-mem -o GROUP="domain controllers"
        '''

        self.GROUP = ''

        if 'GROUP' in module_options:
            self.GROUP = module_options['GROUP']
        else:
            context.log.error('GROUP option is required!')
            exit(1)

    def on_login(self, context, connection):

        #First look up the SID of the group passed in
        searchFilter = "(&(objectCategory=group)(cn=" + self.GROUP + "))"
        attribute = "objectSid"

        searchResult = doSearch(self, context, connection, searchFilter, attribute)
        #If no SID for the Group is returned exit the program
        if searchResult is None:
            context.log.success('Unable to find any members of the "' + self.GROUP + '" group')
            return True

        # Convert the binary SID to a primaryGroupID string to be used further
        sidString = connection.sid_to_str(searchResult).split("-")
        self.primaryGroupID = sidString[-1]

        #Look up the groups DN
        searchFilter = "(&(objectCategory=group)(cn=" + self.GROUP + "))"
        attribute = "distinguishedName"
        distinguishedName = (doSearch(self, context, connection, searchFilter, attribute)).decode("utf-8")

        # Carry out the search
        searchFilter = "(|(memberOf="+distinguishedName+")(primaryGroupID="+self.primaryGroupID+"))"
        attribute = "sAMAccountName"
        searchResult = doSearch(self, context, connection, searchFilter, attribute)

        if len(self.answers) > 0:
            context.log.success('Found the following members of the ' + self.GROUP + ' group:')
            for answer in self.answers:
                context.log.highlight(u'{}'.format(answer[0]))

# Carry out an LDAP search for the Group with the supplied Group name
def doSearch(self,context, connection,searchFilter,attributeName):
    try:
        context.log.debug('Search Filter=%s' % searchFilter)
        resp = connection.ldapConnection.search(searchFilter=searchFilter,
                                                attributes=[attributeName],
                                                sizeLimit=0)
        context.log.debug('Total no. of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            attributeValue = '';
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == attributeName:
                        if attributeName == "objectSid":
                             attributeValue = bytes(attribute['vals'][0])
                             return attributeValue;
                        elif attributeName == "distinguishedName":
                             attributeValue = bytes(attribute['vals'][0])
                             return attributeValue;
                        else:
                             attributeValue = str(attribute['vals'][0])
                    if attributeValue is not None:
                        self.answers.append([attributeValue])
            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug('Skipping item, cannot process due to error %s' % str(e))
                pass
    except Exception as e:
        context.log.debug("Exception:", e)
        return False
