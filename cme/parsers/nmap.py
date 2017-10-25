import xmltodict

# Ideally i'd like to be able to pull this info out dynamically from each protocol object but i'm a lazy bastard
protocol_dict = {
    'smb': {'ports': [445, 139], 'services': ['netbios-ssn', 'microsoft-ds']},
    'mssql': {'ports': [1433], 'services': ['ms-sql-s']},
    'ssh': {'ports': [22], 'services': ['ssh']},
    'winrm': {'ports': [5986, 5985], 'services': ['wsman']},
    'http': {'ports': [80, 443, 8443, 8008, 8080, 8081], 'services': ['http', 'ssl/https']}
}


def parse_nmap_xml(nmap_output_file, protocol):
    targets = []

    with open(nmap_output_file, 'r') as file_handle:
        scan_output = xmltodict.parse(file_handle.read())

    for host in scan_output['nmaprun']['host']:
        if host['address'][0]['@addrtype'] != 'ipv4':
            continue

        ip = host['address'][0]['@addr']
        for port in host['ports']['port']:
            if port['state']['@state'] == 'open':
                if 'service' in port and (port['service']['@name'] in protocol_dict[protocol]['services']):
                    if ip not in targets:
                        targets.append(ip)
                elif port['@portid'] in protocol_dict[protocol]['ports']:
                    if ip not in targets:
                        targets.append(ip)

    return targets
