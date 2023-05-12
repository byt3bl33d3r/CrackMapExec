#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct
import sys
sys.setrecursionlimit(10000)
from binascii import b2a_hex

class CMEModule:
    '''
      Module by CyberCelt

      Initial module:
        https://github.com/Cyb3rC3lt/CrackMapExec-Modules
    '''

    name = 'GROUP-MEM'
    description = 'Retrieves all the members within a Group'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    primaryGroupID = ''

    def options(self, context, module_options):
        '''
        GROUP - Specify the Group option to query for its members
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
            return True

        # Convert the binary SID to a primaryGroupID string to be used further
        sidString = sid_to_str(searchResult).split("-")
        self.primaryGroupID = sidString[-1]

        #Look up the groups DN
        searchFilter = "(&(objectCategory=group)(cn=" + self.GROUP + "))"
        attribute = "distinguishedName"

        distinguishedName = (doSearch(self, context, connection, searchFilter, attribute)).decode("utf-8")

        # If the primaryGroupID relates to Domain Users or Guests use this unique filter
        if self.primaryGroupID == "513" or self.primaryGroupID == "514":
            searchFilter = "(|(memberOf="+distinguishedName+")(primaryGroupID="+self.primaryGroupID+"))"
            #searchFilter = "(|(memberOf=cn=Users)(primaryGroupID=" + self.primaryGroupID + "))"
            attribute = "sAMAccountName"
            searchResult = doSearch(self, context, connection, searchFilter, attribute)

        # Else If the primaryGroupID belongs to another group use the normal lookup
        else:
            searchFilter = "(&(objectCategory=user)(memberOf="+distinguishedName+"))"
            attribute = "sAMAccountName"
            searchResult = doSearch(self, context, connection, searchFilter, attribute)

def doSearch(self,context, connection,searchFilter,attributeName):
    try:
        context.log.debug('Search Filter=%s' % searchFilter)
        resp = connection.ldapConnection.search(searchFilter=searchFilter,
                                                attributes=[attributeName],
                                                sizeLimit=0)
        answers = []
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
                        answers.append([attributeValue])
            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug('Skipping item, cannot process due to error %s' % str(e))
                pass
        if len(answers) > 0:
            context.log.success('Found the following members of the ' + self.GROUP + ' group:')
            for answer in answers:
                context.log.highlight(u'{}'.format(answer[0]))
        else:
            # If no results at this stage and the group name is correct, check for machine accounts
            if self.primaryGroupID != '':
             searchFilter = "(primaryGroupID="+self.primaryGroupID+")"
             attribute = "dNSHostName"
             doSearch(self, context, connection, searchFilter, attribute)
            else:
                context.log.success('Unable to find any members of the ' + self.GROUP + ' group')

    except ldap_impacket.LDAPSearchError as e:
        logging.debug(e)
        return False

def sid_to_str(sid):
    try:
        # Python 3
        if str is not bytes:
            # revision
            revision = int(sid[0])
            # count of sub authorities
            sub_authorities = int(sid[1])
            # big endian
            identifier_authority = int.from_bytes(sid[2:8], byteorder='big')
            # If true then it is represented in hex
            if identifier_authority >= 2 ** 32:
                identifier_authority = hex(identifier_authority)

            # loop over the count of small endians
            sub_authority = '-' + '-'.join([str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder='little')) for i in range(sub_authorities)])
        # Python 2
        else:
            revision = int(b2a_hex(sid[0]))
            sub_authorities = int(b2a_hex(sid[1]))
            identifier_authority = int(b2a_hex(sid[2:8]), 16)
            if identifier_authority >= 2 ** 32:
                identifier_authority = hex(identifier_authority)

            sub_authority = '-' + '-'.join([str(int(b2a_hex(sid[11 + (i * 4): 7 + (i * 4): -1]), 16)) for i in range(sub_authorities)])
        objectSid = 'S-' + str(revision) + '-' + str(identifier_authority) + sub_authority

        return objectSid
    except Exception:
        pass

    return sid
