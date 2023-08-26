#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# All credit to @an0n_r0
# project : https://github.com/tothi/serviceDetector

from impacket.dcerpc.v5 import lsat, lsad
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, RPC_UNICODE_STRING
from impacket.dcerpc.v5 import transport
import pathlib


class CMEModule:
    """
    Uses LsarLookupNames and NamedPipes to gather information on all endpoint protection solutions installed on the the remote host(s)
    Module by @mpgn_x64
    """

    name = "enum_av"
    description = "Gathers information on all endpoint protection solutions installed on the the remote host(s) via LsarLookupNames (no privilege needed)"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """ """
        pass

    def on_login(self, context, connection):
        success = 0
        results = {}
        target = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
        context.log.debug("Detecting installed services on {} using LsarLookupNames()...".format(target))

        try:
            lsa = LsaLookupNames(
                connection.domain,
                connection.username,
                connection.password,
                target,
                connection.kerberos,
                connection.domain,
                connection.lmhash,
                connection.nthash,
                connection.aesKey,
            )
            dce, rpctransport = lsa.connect()
            policyHandle = lsa.open_policy(dce)

            for i, product in enumerate(conf["products"]):
                for service in product["services"]:
                    try:
                        lsa.LsarLookupNames(dce, policyHandle, service["name"])
                        context.log.info(f"Detected installed service on {connection.host}: {product['name']} {service['description']}")
                        if product["name"] not in results:
                            results[product["name"]] = {"services": []}
                        results[product["name"]]["services"].append(service)
                    except Exception as e:
                        pass
            success += 1
        except Exception as e:
            context.log.fail(str(e))

        context.log.info(f"Detecting running processes on {connection.host} by enumerating pipes...")
        try:
            for f in connection.conn.listPath("IPC$", "\\*"):
                fl = f.get_longname()
                for i, product in enumerate(conf["products"]):
                    for pipe in product["pipes"]:
                        if pathlib.PurePath(fl).match(pipe["name"]):
                            context.log.debug(f"{product['name']} running claim found on {connection.host} by existing pipe {fl} (likely processes: {pipe['processes']})")
                            if product["name"] not in results:
                                results[product["name"]] = {}
                            if "pipes" not in results[product["name"]]:
                                results[product["name"]]["pipes"] = []
                            results[product["name"]]["pipes"].append(pipe)
            success += 1
        except Exception as e:
            context.log.debug(str(e))

        self.dump_results(results, connection.hostname, success, context)

    def dump_results(self, results, remoteName, success, context):
        # out1 = "On host {} found".format(remoteName)
        out1 = ""
        for item in results:
            out = out1
            if "services" in results[item]:
                out += f"{item} INSTALLED"
                if "pipes" in results[item]:
                    out += " and it seems to be RUNNING"
                # else:
                #     for product in conf['products']:
                #         if (item == product['name']) and (len(product['pipes']) == 0):
                #             out += " (NamedPipe for this service was not provided in config)"
            elif "pipes" in results[item]:
                out += f" {item} RUNNING"
            context.log.highlight(out)
        if (len(results) < 1) and (success > 1):
            out = out1 + " NOTHING!"
            context.log.highlight(out)


class LsaLookupNames:
    timeout = None
    authn_level = None
    protocol = None
    transfer_syntax = None
    machine_account = False

    iface_uuid = lsat.MSRPC_UUID_LSAT
    authn = True

    def __init__(
        self,
        domain="",
        username="",
        password="",
        remote_name="",
        k=False,
        kdcHost="",
        lmhash="",
        nthash="",
        aesKey="",
    ):
        self.domain = domain
        self.username = username
        self.password = password
        self.remoteName = remote_name
        self.string_binding = rf"ncacn_np:{remote_name}[\PIPE\lsarpc]"
        self.doKerberos = k
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.dcHost = kdcHost

    def connect(self, string_binding=None, iface_uuid=None):
        """Obtains a RPC Transport and a DCE interface according to the bindings and
        transfer syntax specified.
        :return: tuple of DCE/RPC and RPC Transport objects
        :rtype: (DCERPC_v5, DCERPCTransport)
        """
        string_binding = string_binding or self.string_binding
        if not string_binding:
            raise NotImplemented("String binding must be defined")

        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        # Set timeout if defined
        if self.timeout:
            rpc_transport.set_connect_timeout(self.timeout)

        # Authenticate if specified
        if self.authn and hasattr(rpc_transport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey)

        if self.doKerberos:
            rpc_transport.set_kerberos(self.doKerberos, kdcHost=self.dcHost)

        # Gets the DCE RPC object
        dce = rpc_transport.get_dce_rpc()

        # Set the authentication level
        if self.authn_level:
            dce.set_auth_level(self.authn_level)

        # Connect
        dce.connect()

        # Bind if specified
        iface_uuid = iface_uuid or self.iface_uuid
        if iface_uuid and self.transfer_syntax:
            dce.bind(iface_uuid, transfer_syntax=self.transfer_syntax)
        elif iface_uuid:
            dce.bind(iface_uuid)

        return dce, rpc_transport

    def open_policy(self, dce):
        request = lsad.LsarOpenPolicy2()
        request["SystemName"] = NULL
        request["ObjectAttributes"]["RootDirectory"] = NULL
        request["ObjectAttributes"]["ObjectName"] = NULL
        request["ObjectAttributes"]["SecurityDescriptor"] = NULL
        request["ObjectAttributes"]["SecurityQualityOfService"] = NULL
        request["DesiredAccess"] = MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES
        resp = dce.request(request)
        return resp["PolicyHandle"]

    def LsarLookupNames(self, dce, policyHandle, service):
        request = lsat.LsarLookupNames()
        request["PolicyHandle"] = policyHandle
        request["Count"] = 1
        name1 = RPC_UNICODE_STRING()
        name1["Data"] = "NT Service\{}".format(service)
        request["Names"].append(name1)
        request["TranslatedSids"]["Sids"] = NULL
        request["LookupLevel"] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        resp = dce.request(request)
        return resp


conf = {
    "products": [
        {
            "name": "Bitdefender",
            "services": [
                {
                    "name": "bdredline_agent",
                    "description": "Bitdefender Agent RedLine Service",
                },
                {"name": "BDAuxSrv", "description": "Bitdefender Auxiliary Service"},
                {
                    "name": "UPDATESRV",
                    "description": "Bitdefender Desktop Update Service",
                },
                {"name": "VSSERV", "description": "Bitdefender Virus Shield"},
                {"name": "bdredline", "description": "Bitdefender RedLine Service"},
                {"name": "EPRedline", "description": "Bitdefender Endpoint Redline Service"},
                {"name": "EPUpdateService", "description": "Bitdefender Endpoint Update Service"},
                {"name": "EPSecurityService", "description": "Bitdefender Endpoint Security Service"},
                {"name": "EPProtectedService", "description": "Bitdefender Endpoint Protected Service"},
                {"name": "EPIntegrationService", "description": "Bitdefender Endpoint Integration Service"},
            ],
            "pipes": [
                {
                    "name": "\\bdConnector\\ServiceControl\\EPSecurityService.exe",
                    "processes": ["EPConsole.exe"],
                },
                {
                    "name": "etw_sensor_pipe_ppl",
                    "processes": ["EPProtectedService.exe"],
                },
                {
                    "name": "local\\msgbus\\antitracker.low\\*",
                    "processes": ["bdagent.exe"],
                },
                {
                    "name": "local\\msgbus\\aspam.actions.low\\*",
                    "processes": ["bdagent.exe"],
                },
                {
                    "name": "local\\msgbus\\bd.process.broker.pipe",
                    "processes": ["bdagent.exe", "bdservicehost.exe", "updatesrv.exe"],
                },
                {"name": "local\\msgbus\\bdagent*", "processes": ["bdagent.exe"]},
                {
                    "name": "local\\msgbus\\bdauxsrv",
                    "processes": ["bdagent.exe", "bdntwrk.exe"],
                },
            ],
        },
        {
            "name": "Windows Defender",
            "services": [
                {
                    "name": "WinDefend",
                    "description": "Windows Defender Antivirus Service",
                },
                {
                    "name": "Sense",
                    "description": "Windows Defender Advanced Threat Protection Service",
                },
                {
                    "name": "WdNisSvc",
                    "description": "Windows Defender Antivirus Network Inspection Service",
                },
            ],
            "pipes": [],
        },
        {
            "name": "ESET",
            "services": [
                {"name": "ekm", "description": "ESET"},
                {"name": "epfw", "description": "ESET"},
                {"name": "epfwlwf", "description": "ESET"},
                {"name": "epfwwfp", "description": "ESET"},
                {"name": "EraAgentSvc", "description": "ESET"},
            ],
            "pipes": [{"name": "nod_scriptmon_pipe", "processes": [""]}],
        },
        {
            "name": "CrowdStrike",
            "services": [
                {
                    "name": "CSFalconService",
                    "description": "CrowdStrike Falcon Sensor Service",
                }
            ],
            "pipes": [
                {
                    "name": "CrowdStrike\\{*",
                    "processes": ["CSFalconContainer.exe", "CSFalconService.exe"],
                }
            ],
        },
        {
            "name": "SentinelOne",
            "services": [
                {
                    "name": "SentinelAgent",
                    "description": "SentinelOne Endpoint Protection Agent",
                },
                {
                    "name": "SentinelStaticEngine",
                    "description": "Manage static engines for SentinelOne Endpoint Protection",
                },
                {
                    "name": "LogProcessorService",
                    "description": "Manage logs for SentinelOne Endpoint Protection",
                },
            ],
            "pipes": [
                {"name": "SentinelAgentWorkerCert.*", "processes": [""]},
                {"name": "DFIScanner.Etw.*", "processes": ["SentinelStaticEngine.exe"]},
                {"name": "DFIScanner.Inline.*", "processes": ["SentinelAgent.exe"]},
            ],
        },
        {
            "name": "Carbon Black App Control",
            "services": [{"name": "Parity", "description": "Carbon Black App Control Agent"}],
            "pipes": [],
        },
        {
            "name": "Cybereason",
            "services": [
                {
                    "name": "CybereasonActiveProbe",
                    "description": "Cybereason Active Probe",
                },
                {"name": "CybereasonCRS", "description": "Cybereason Anti-Ransomware"},
                {
                    "name": "CybereasonBlocki",
                    "description": "Cybereason Execution Prevention",
                },
            ],
            "pipes": [
                {
                    "name": "CybereasonAPConsoleMinionHostIpc_*",
                    "processes": ["minionhost.exe"],
                },
                {
                    "name": "CybereasonAPServerProxyIpc_*",
                    "processes": ["minionhost.exe"],
                },
            ],
        },
        {
            "name": "Kaspersky Security for Windows Server",
            "services": [
                {
                    "name": "kavfsslp",
                    "description": "Kaspersky Security Exploit Prevention Service",
                },
                
                {
                    "name": "KAVFS",
                    "description": "Kaspersky Security Service",
                },

                {
                    "name": "KAVFSGT",
                    "description": "Kaspersky Security Management Service",
                },
                
                {
                    "name": "klnagent",
                    "description": "Kaspersky Security Center",
                },
            ],
            "pipes": [
                {
                    "name": "Exploit_Blocker",
                    "processes": ["kavfswh.exe"],
                },
                
            ],
        },  
        {
            "name": "Trend Micro Endpoint Security",
            "services": [
                {
                    "name": "Trend Micro Endpoint Basecamp",
                    "description": "Trend Micro Endpoint Basecamp",
                },
                
                {
                    "name": "TMBMServer",
                    "description": "Trend Micro Unauthorized Change Prevention Service",
                },

                {
                    "name": "Trend Micro Web Service Communicator",
                    "description": "Trend Micro Web Service Communicator",
                },
                
                {
                    "name": "TMiACAgentSvc",
                    "description": "Trend Micro Application Control Service (Agent)",
                },
                {                
                    "name": "CETASvc",
                    "description": "Trend Micro Cloud Endpoint Telemetry Service",
                },
                {
                                
                    "name": "iVPAgent",
                    "description": "Trend Micro Vulnerability Protection Service (Agent)",
                }                 
            ],
            "pipes": [
                {
                    "name": "IPC_XBC_XBC_AGENT_PIPE_*",
                    "processes": ["EndpointBasecamp.exe"],
                },
                {
                    "name": "iacagent_*",
                    "processes": ["TMiACAgentSvc.exe"],
                },
                {
                    "name": "OIPC_LWCS_PIPE_*",
                    "processes": ["TmListen.exe"],
                },
                {
                    "name": "Log_ServerNamePipe",
                    "processes": ["LogServer.exe"],
                },
                {
                    "name": "OIPC_NTRTSCAN_PIPE_*",
                    "processes": ["Ntrtscan.exe"],
                },
            ],
        },  
        {
            "name": "Symantec Endpoint Protection",
            "services": [
                {
                    "name": "SepMasterService",
                    "description": "Symantec Endpoint Protection",
                },
                {
                    "name": "SepScanService",
                    "description": "Symantec Endpoint Protection Scan Services",
                },
                {"name": "SNAC", "description": "Symantec Network Access Control"},
            ],
            "pipes": [],
        },
        {
            "name": "Sophos Intercept X",
            "services": [
                {
                "name": "SntpService",
                "description": "Sophos Network Threat Protection"
                },
                {
                "name": "Sophos Endpoint Defense Service",
                "description": "Sophos Endpoint Defense Service"
                },
                {
                "name": "Sophos File Scanner Service",
                "description": "Sophos File Scanner Service"
                },
                {
                "name": "Sophos Health Service",
                "description": "Sophos Health Service"
                },
                {
                "name": "Sophos Live Query",
                "description": "Sophos Live Query"
                },
                {
                "name": "Sophos Managed Threat Response",
                "description": "Sophos Managed Threat Response"
                },
                {
                "name": "Sophos MCS Agent",
                "description": "Sophos MCS Agent"
                },
                {
                "name": "Sophos MCS Client",
                "description": "Sophos MCS Client"
                },
                {
                "name": "Sophos System Protection Service",
                "description": "Sophos System Protection Service"
                }
            ],
            "pipes": [
                {"name": "SophosUI", "processes": [""]},
                {"name": "SophosEventStore", "processes": [""]},
                {"name": "sophos_deviceencryption", "processes": [""]},
                {"name": "sophoslivequery_*", "processes": [""]},
            ],
        },
        {
            "name": "G DATA Security Client",
            "services": [
                {
                    "name": "AVKWCtl",
                    "description": "Anti-virus Kit Window Control",
                },
                {
                    "name": "AVKProxy", 
                    "description": "G Data AntiVirus Proxy Service"
                },
                {
                    "name": "GDScan",
                    "description": "GDSG Data AntiVirus Scan Service",
                },
            ],
            "pipes": [
                {
                    "name": "exploitProtectionIPC",
                    "processes": ["AVKWCtlx64.exe"],
                },
            ],
        },
        {
            "name": "Panda Adaptive Defense 360",
            "services": [
                {
                    "name": "PandaAetherAgent",
                    "description": "Panda Endpoint Agent",
                },
                {
                    "name": "PSUAService", 
                    "description": "Panda Product Service"
                },
                {
                    "name": "NanoServiceMain",
                    "description": "Panda Cloud Antivirus Service",
                },
            ],
            "pipes": [
                {
                    "name": "NNS_API_IPC_SRV_ENDPOINT",
                    "processes": ["PSANHost.exe"],
                },
                {
                    "name": "PSANMSrvcPpal",
                    "processes": ["PSUAService.exe"],
                },
            ],
        }
        
    ]
}
