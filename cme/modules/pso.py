#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
from math import fabs
import re


class CMEModule:
    '''
        Created by fplazar and wanetty
        Module by @gm_eduard and @ferranplaza 
        Based on: https://github.com/juliourena/CrackMapExec/blob/master/cme/modules/get_description.py
    '''

    name = 'pso'
    description = "Query to get PSO from LDAP"
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = True
    
    pso_fields = [
        "cn",
        "msDS-PasswordReversibleEncryptionEnabled",
        "msDS-PasswordSettingsPrecedence",
        "msDS-MinimumPasswordLength",
        "msDS-PasswordHistoryLength",
        "msDS-PasswordComplexityEnabled",
        "msDS-LockoutObservationWindow",
        "msDS-LockoutDuration",
        "msDS-LockoutThreshold",
        "msDS-MinimumPasswordAge",
        "msDS-MaximumPasswordAge",
        "msDS-PSOAppliesTo",
    ]

    def options(self, context, module_options):
        '''
        No options available.
        '''
        pass
    
    def convert_time_field(self, field, value):
        time_fields = {
            "msDS-LockoutObservationWindow": (60, "mins"),
            "msDS-MinimumPasswordAge": (86400, "days"),
            "msDS-MaximumPasswordAge": (86400, "days"),
            "msDS-LockoutDuration": (60, "mins")
        }

        if field in time_fields.keys():
            value = f"{int((fabs(float(value)) / (10000000 * time_fields[field][0])))} {time_fields[field][1]}"
        
        return value
    
    def on_login(self, context, connection):
        '''Concurrent. Required if on_admin_login is not present. This gets called on each authenticated connection'''
        # Building the search filter
        searchFilter = "(objectClass=msDS-PasswordSettings)"

        try:
            context.log.debug('Search Filter=%s' % searchFilter)
            resp = connection.ldapConnection.search(searchFilter=searchFilter,
                                                    attributes=self.pso_fields,
                                                    sizeLimit=0)
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                context.log.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            else:
                logging.debug(e)
                return False

        pso_list = []

        context.log.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue

            pso_info = {}

            try:
                for attribute in item['attributes']:
                    attr_name = str(attribute['type'])
                    if attr_name in self.pso_fields:
                        pso_info[attr_name] = attribute['vals'][0]._value.decode('utf-8')

                pso_list.append(pso_info)

            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug('Skipping item, cannot process due to error %s' % str(e))
                pass
        if len(pso_list) > 0:
            context.log.success('Password Settings Objects (PSO) found:')
            for pso in pso_list:
                for field in self.pso_fields:
                    if field in pso:
                        value = self.convert_time_field(field, pso[field])
                        context.log.highlight(u'{}: {}'.format(field, value))
                context.log.highlight('-----')

        else:
            context.log.info('No Password Settings Objects (PSO) found.')
