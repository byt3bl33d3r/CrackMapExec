#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Credit to https://airbus-cyber-security.com/fr/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/
# Airbus CERT
# module by @mpgn_x64

from ipaddress import ip_address
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from impacket.dcerpc.v5.dcomrt import IObjectExporter


class CMEModule:
    name = "ioxidresolver"
    description = "This module helps you to identify hosts that have additional active interfaces"
    supported_protocols = ["smb", "wmi"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """ """

    def on_login(self, context, connection):
        authLevel = RPC_C_AUTHN_LEVEL_NONE

        stringBinding = r"ncacn_ip_tcp:%s" % connection.host
        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        portmap = rpctransport.get_dce_rpc()
        portmap.set_auth_level(authLevel)
        portmap.connect()

        objExporter = IObjectExporter(portmap)
        bindings = objExporter.ServerAlive2()

        context.log.debug("[*] Retrieving network interface of " + connection.host)

        # NetworkAddr = bindings[0]['aNetworkAddr']
        for binding in bindings:
            NetworkAddr = binding["aNetworkAddr"]
            try:
                ip_address(NetworkAddr[:-1])
                context.log.highlight("Address: " + NetworkAddr)
            except Exception as e:
                context.log.debug(e)
