#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/rpcdump.py
from impacket import uuid
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpch import (
    RPC_PROXY_INVALID_RPC_PORT_ERR,
    RPC_PROXY_CONN_A1_0X6BA_ERR,
    RPC_PROXY_CONN_A1_404_ERR,
    RPC_PROXY_RPC_OUT_DATA_404_ERR,
)

KNOWN_PROTOCOLS = {
    135: {"bindstr": r"ncacn_ip_tcp:%s[135]"},
    445: {"bindstr": r"ncacn_np:%s[\pipe\epmapper]"},
}


class CMEModule:
    """
    For printnightmare: detect if print spooler is enabled or not. Then use @cube0x0's project https://github.com/cube0x0/CVE-2021-1675 or Mimikatz from Benjamin Delpy
    Module by @mpgn_x64
    """

    name = "spooler"
    description = "Detect if print spooler is enabled or not"
    supported_protocols = ["smb", "wmi"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.__string_binding = None
        self.port = None

    def options(self, context, module_options):
        """
        PORT    Port to check (defaults to 135)
        """
        self.port = 135
        if "PORT" in module_options:
            self.port = int(module_options["PORT"])

    def on_login(self, context, connection):
        entries = []
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        self.__stringbinding = KNOWN_PROTOCOLS[self.port]["bindstr"] % connection.host
        context.log.debug("StringBinding %s" % self.__stringbinding)
        rpctransport = transport.DCERPCTransportFactory(self.__stringbinding)
        rpctransport.set_credentials(connection.username, connection.password, connection.domain, lmhash, nthash)
        rpctransport.setRemoteHost(connection.host if not connection.kerberos else connection.hostname + "." + connection.domain)
        rpctransport.set_dport(self.port)

        if connection.kerberos:
            rpctransport.set_kerberos(connection.kerberos, connection.kdcHost)

        try:
            entries = self.__fetch_list(rpctransport)
        except Exception as e:
            error_text = "Protocol failed: %s" % e
            context.log.critical(error_text)

            if RPC_PROXY_INVALID_RPC_PORT_ERR in error_text or RPC_PROXY_RPC_OUT_DATA_404_ERR in error_text or RPC_PROXY_CONN_A1_404_ERR in error_text or RPC_PROXY_CONN_A1_0X6BA_ERR in error_text:
                context.log.critical("This usually means the target does not allow " "to connect to its epmapper using RpcProxy.")
                return

        # Display results.
        endpoints = {}
        # Let's group the UUIDS
        for entry in entries:
            binding = epm.PrintStringBinding(entry["tower"]["Floors"])
            tmp_uuid = str(entry["tower"]["Floors"][0])
            if (tmp_uuid in endpoints) is not True:
                endpoints[tmp_uuid] = {}
                endpoints[tmp_uuid]["Bindings"] = list()
            if uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmp_uuid))[:18] in epm.KNOWN_UUIDS:
                endpoints[tmp_uuid]["EXE"] = epm.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmp_uuid))[:18]]
            else:
                endpoints[tmp_uuid]["EXE"] = "N/A"
            endpoints[tmp_uuid]["annotation"] = entry["annotation"][:-1].decode("utf-8")
            endpoints[tmp_uuid]["Bindings"].append(binding)

            if tmp_uuid[:36] in epm.KNOWN_PROTOCOLS:
                endpoints[tmp_uuid]["Protocol"] = epm.KNOWN_PROTOCOLS[tmp_uuid[:36]]
            else:
                endpoints[tmp_uuid]["Protocol"] = "N/A"

        for endpoint in list(endpoints.keys()):
            if "MS-RPRN" in endpoints[endpoint]["Protocol"]:
                context.log.debug("Protocol: %s " % endpoints[endpoint]["Protocol"])
                context.log.debug("Provider: %s " % endpoints[endpoint]["EXE"])
                context.log.debug("UUID    : %s %s" % (endpoint, endpoints[endpoint]["annotation"]))
                context.log.debug("Bindings: ")
                for binding in endpoints[endpoint]["Bindings"]:
                    context.log.debug("          %s" % binding)
                context.log.debug("")
                context.log.highlight("Spooler service enabled")
                try:
                    host = context.db.get_hosts(connection.host)[0]
                    context.db.add_host(
                        host.ip,
                        host.hostname,
                        host.domain,
                        host.os,
                        host.smbv1,
                        host.signing,
                        spooler=True,
                    )
                except Exception as e:
                    context.log.debug(f"Error updating spooler status in database")
                break

        if entries:
            num = len(entries)
            if 1 == num:
                context.log.debug(f"[Spooler] Received one endpoint")
            else:
                context.log.debug(f"[Spooler] Received {num} endpoints")
        else:
            context.log.debug(f"[Spooler] No endpoints found")

    def __fetch_list(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        resp = epm.hept_lookup(None, dce=dce)
        dce.disconnect()
        return resp
