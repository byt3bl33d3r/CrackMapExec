#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import xmltodict

# Ideally i'd like to be able to pull this info out dynamically from each protocol object but i'm a lazy bastard
protocol_dict = {
    "smb": {"ports": [445, 139], "services": ["smb", "cifs"]},
    "mssql": {"ports": [1433], "services": ["mssql"]},
    "ssh": {"ports": [22], "services": ["ssh"]},
    "winrm": {"ports": [5986, 5985], "services": ["www", "https?"]},
    "http": {"ports": [80, 443, 8443, 8008, 8080, 8081], "services": ["www", "https?"]},
}


def parse_nessus_file(nessus_file, protocol):
    targets = []

    def handle_nessus_file(path, item):
        # Must return True otherwise xmltodict will throw a ParsingIterrupted() exception
        # https://github.com/martinblech/xmltodict/blob/master/xmltodict.py#L219

        if any("ReportHost" and "ReportItem" in values for values in path):
            item = dict(path)
            ip = item["ReportHost"]["name"]
            if ip in targets:
                return True

            port = item["ReportItem"]["port"]
            svc_name = item["ReportItem"]["svc_name"]

            if port in protocol_dict[protocol]["ports"]:
                targets.append(ip)
            if svc_name in protocol_dict[protocol]["services"]:
                targets.append(ip)

            return True
        else:
            return True

    with open(nessus_file, "r") as file_handle:
        xmltodict.parse(file_handle, item_depth=4, item_callback=handle_nessus_file)

    return targets
