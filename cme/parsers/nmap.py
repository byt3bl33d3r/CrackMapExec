#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from libnmap.parser import NmapParser
from cme.logger import cme_logger

# right now we are only referencing the port numbers, not the service name, but this should be sufficient for 99% cases
protocol_dict = {
    "ftp": {
        "ports": [21],
        "services": ["ftp"]
    },
    "ssh": {
        "ports": [22, 2222],
        "services": ["ssh"]
    },
    "smb": {
        "ports": [139, 445],
        "services": ["netbios-ssn", "microsoft-ds"]
    },
    "ldap": {
        "ports": [389, 636],
        "services": ["ldap", "ldaps"]
    },
    "mssql": {
        "ports": [1433],
        "services": ["ms-sql-s"]
    },
    "rdp": {
        "ports": [3389],
        "services": ["ms-wbt-server"]
    },
    "winrm": {
        "ports": [5985, 5986],
        "services": ["wsman"]
    },
    "vnc": {
        "ports": [5900, 5901, 5902, 5903, 5904, 5905, 5906],
        "services": ["vnc"]
    },
}


def parse_nmap_xml(nmap_output_file, protocol):
    nmap_report = NmapParser.parse_fromfile(nmap_output_file)
    targets = []

    for host in nmap_report.hosts:
        for port, proto in host.get_open_ports():
            if port in protocol_dict[protocol]["ports"]:
                targets.append(host.ipv4)
                break
    cme_logger.debug(f"Targets parsed from Nmap scan: {targets}")

    return targets
