#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class CMEModule:
    '''
        Extract all Trust Relationships, Trusting Direction, and Trust Transitivity
        Module by Brandon Fisher @shad0wcntr0ller
    '''
    name = 'enum_trusts'
    description = 'Extract all Trust Relationships, Trusting Direction, and Trust Transitivity'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        domain_dn = ','.join(['DC=' + dc for dc in connection.domain.split('.')])
        search_filter = '(&(objectClass=trustedDomain))'
        attributes = ['flatName', 'trustPartner', 'trustDirection', 'trustAttributes'] 

        context.log.debug(f'Search Filter={search_filter}')
        resp = connection.ldapConnection.search(searchBase=domain_dn, searchFilter=search_filter, attributes=attributes, sizeLimit=0)

        trusts = []
        context.log.debug(f'Total of records returned {len(resp)}')
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            flat_name = ''
            trust_partner = ''
            trust_direction = ''
            trust_transitive = [] 
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'flatName':
                        flat_name = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'trustPartner':
                        trust_partner = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'trustDirection':
                        if str(attribute['vals'][0]) == '1':
                            trust_direction = 'Inbound'
                        elif str(attribute['vals'][0]) == '2':
                            trust_direction = 'Outbound'
                        elif str(attribute['vals'][0]) == '3':
                            trust_direction = 'Bidirectional'
                    elif str(attribute['type']) == 'trustAttributes': 
                        trust_attributes_value = int(attribute['vals'][0])
                        if trust_attributes_value & 0x1:
                            trust_transitive.append('Non-Transitive')
                        if trust_attributes_value & 0x2:
                            trust_transitive.append('Uplevel-Only')
                        if trust_attributes_value & 0x4:
                            trust_transitive.append('Quarantined Domain')
                        if trust_attributes_value & 0x8:
                            trust_transitive.append('Forest Transitive')
                        if trust_attributes_value & 0x10:
                            trust_transitive.append('Cross Organization')
                        if trust_attributes_value & 0x20:
                            trust_transitive.append('Within Forest')
                        if trust_attributes_value & 0x40:
                            trust_transitive.append('Treat as External')
                        if trust_attributes_value & 0x80:
                            trust_transitive.append('Uses RC4 Encryption')
                        if trust_attributes_value & 0x100:
                            trust_transitive.append('Cross Organization No TGT Delegation')
                        if trust_attributes_value & 0x2000:
                            trust_transitive.append('PAM Trust')
                        if not trust_transitive:
                            trust_transitive.append('Other')
                trust_transitive = ', '.join(trust_transitive)

                if flat_name and trust_partner and trust_direction and trust_transitive:
                    trusts.append((flat_name, trust_partner, trust_direction, trust_transitive))
            except Exception as e:
                context.log.debug(f'Cannot process trust relationship due to error {e}')
                pass

        if trusts:
            context.log.success('Found the following trust relationships:')
            for trust in trusts:
                context.log.highlight(f'{trust[1]} -> {trust[2]} -> {trust[3]}')
        else:
            context.log.display('No trust relationships found')

        return True

