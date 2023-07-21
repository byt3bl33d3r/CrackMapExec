#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from impacket import system_errors
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.structure import Structure
from impacket.dcerpc.v5 import transport, rprn
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRSTRUCT, NDRUNION, NULL
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, ULONG, WSTR
from impacket.dcerpc.v5.rprn import checkNullString, STRING_HANDLE, PBYTE_ARRAY

KNOWN_PROTOCOLS = {
    135: {"bindstr": r"ncacn_ip_tcp:%s[135]"},
    445: {"bindstr": r"ncacn_np:%s[\pipe\epmapper]"},
}


class CMEModule:
    """
    Check if vulnerable to printnightmare
    Module by @mpgn_x64 based on https://github.com/ly4k/PrintNightmare
    """

    name = "printnightmare"
    description = "Check if host vulnerable to printnightmare"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.__string_binding = None
        self.port = None

    def options(self, context, module_options):
        """
        PORT    Port to check (defaults to 445)
        """
        self.port = 445
        if "PORT" in module_options:
            self.port = int(module_options["PORT"])

    def on_login(self, context, connection):
        # Connect and bind to MS-RPRN (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/848b8334-134a-4d02-aea4-03b673d6c515)
        stringbinding = r"ncacn_np:%s[\PIPE\spoolss]" % connection.host

        context.log.info("Binding to %s" % (repr(stringbinding)))

        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        rpctransport.set_credentials(
            connection.username,
            connection.password,
            connection.domain,
            connection.lmhash,
            connection.nthash,
            connection.aesKey,
        )

        rpctransport.set_kerberos(connection.kerberos, kdcHost=connection.kdcHost)

        rpctransport.setRemoteHost(connection.host)
        rpctransport.set_dport(self.port)

        try:
            dce = rpctransport.get_dce_rpc()
            # Connect to spoolss named pipe
            dce.connect()
            # Bind to MSRPC MS-RPRN UUID: 12345678-1234-ABCD-EF00-0123456789AB
            dce.bind(rprn.MSRPC_UUID_RPRN)
        except Exception as e:
            context.log.fail("Failed to bind: %s" % e)
            sys.exit(1)

        flags = APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY | APD_INSTALL_WARNED_DRIVER

        driver_container = DRIVER_CONTAINER()
        driver_container["Level"] = 2
        driver_container["DriverInfo"]["tag"] = 2
        driver_container["DriverInfo"]["Level2"]["cVersion"] = 0
        driver_container["DriverInfo"]["Level2"]["pName"] = NULL
        driver_container["DriverInfo"]["Level2"]["pEnvironment"] = NULL
        driver_container["DriverInfo"]["Level2"]["pDriverPath"] = NULL
        driver_container["DriverInfo"]["Level2"]["pDataFile"] = NULL
        driver_container["DriverInfo"]["Level2"]["pConfigFile"] = NULL
        driver_container["DriverInfo"]["Level2"]["pConfigFile"] = NULL

        try:
            hRpcAddPrinterDriverEx(
                dce,
                pName=NULL,
                pDriverContainer=driver_container,
                dwFileCopyFlags=flags,
            )
        except DCERPCSessionError as e:
            # RPC_E_ACCESS_DENIED is returned on patched systems, when
            # a non-administrative user tries to create a new printer
            # driver
            if e.error_code == RPC_E_ACCESS_DENIED:
                context.log.info("Not vulnerable :'(")
                return False
            # If vulnerable, 'ERROR_INVALID_PARAMETER' will be returned
            if e.error_code == system_errors.ERROR_INVALID_PARAMETER:
                context.log.highlight("Vulnerable, next step https://github.com/ly4k/PrintNightmare")
                return True
            raise e
        context.log.highlight("Vulnerable, next step https://github.com/ly4k/PrintNightmare")
        return True


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return "RPRN SessionError: code: 0x%x - %s - %s" % (
                self.error_code,
                error_msg_short,
                error_msg_verbose,
            )
        else:
            return "RPRN SessionError: unknown error code: 0x%x" % self.error_code


################################################################################
# CONSTANTS
################################################################################
# MS-RPRN - 3.1.4.4.8
APD_COPY_ALL_FILES = 0x00000004
APD_COPY_FROM_DIRECTORY = 0x00000010
APD_INSTALL_WARNED_DRIVER = 0x00008000

# MS-RPRN - 3.1.4.4.7
DPD_DELETE_UNUSED_FILES = 0x00000001

# https://docs.microsoft.com/en-us/windows/win32/com/com-error-codes-3
RPC_E_ACCESS_DENIED = 0x8001011B
system_errors.ERROR_MESSAGES[RPC_E_ACCESS_DENIED] = (
    "RPC_E_ACCESS_DENIED",
    "Access is denied.",
)


################################################################################
# STRUCTURES
################################################################################
# MS-RPRN - 2.2.1.5.1
class DRIVER_INFO_1(NDRSTRUCT):
    structure = (("pName", STRING_HANDLE),)


class PDRIVER_INFO_1(NDRPOINTER):
    referent = (("Data", DRIVER_INFO_1),)


# MS-RPRN - 2.2.1.5.2
class DRIVER_INFO_2(NDRSTRUCT):
    structure = (
        ("cVersion", DWORD),
        ("pName", LPWSTR),
        ("pEnvironment", LPWSTR),
        ("pDriverPath", LPWSTR),
        ("pDataFile", LPWSTR),
        ("pConfigFile", LPWSTR),
    )


class PDRIVER_INFO_2(NDRPOINTER):
    referent = (("Data", DRIVER_INFO_2),)


class DRIVER_INFO_2_BLOB(Structure):
    structure = (
        ("cVersion", "<L"),
        ("NameOffset", "<L"),
        ("EnvironmentOffset", "<L"),
        ("DriverPathOffset", "<L"),
        ("DataFileOffset", "<L"),
        ("ConfigFileOffset", "<L"),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data=data)

    def fromString(self, data, offset=0):
        Structure.fromString(self, data)

        name = data[self["NameOffset"] + offset :].decode("utf-16-le")
        name_len = name.find("\0")
        self["Name"] = checkNullString(name[:name_len])

        self["ConfigFile"] = data[self["ConfigFileOffset"] + offset : self["DataFileOffset"] + offset].decode("utf-16-le")
        self["DataFile"] = data[self["DataFileOffset"] + offset : self["DriverPathOffset"] + offset].decode("utf-16-le")
        self["DriverPath"] = data[self["DriverPathOffset"] + offset : self["EnvironmentOffset"] + offset].decode("utf-16-le")
        self["Environment"] = data[self["EnvironmentOffset"] + offset : self["NameOffset"] + offset].decode("utf-16-le")


class DRIVER_INFO_2_ARRAY(Structure):
    def __init__(self, data=None, pcReturned=None):
        Structure.__init__(self, data=data)
        self["drivers"] = list()
        remaining = data
        if data is not None:
            for _ in range(pcReturned):
                attr = DRIVER_INFO_2_BLOB(remaining)
                self["drivers"].append(attr)
                remaining = remaining[len(attr) :]


class DRIVER_INFO_UNION(NDRUNION):
    commonHdr = (("tag", ULONG),)
    union = {1: ("pNotUsed", PDRIVER_INFO_1), 2: ("Level2", PDRIVER_INFO_2)}


# MS-RPRN - 3.1.4.1.8.3
class DRIVER_CONTAINER(NDRSTRUCT):
    structure = (("Level", DWORD), ("DriverInfo", DRIVER_INFO_UNION))


################################################################################
# RPC CALLS
################################################################################
# MS-RPRN - 3.1.4.4.2
class RpcEnumPrinterDrivers(NDRCALL):
    opnum = 10
    structure = (
        ("pName", STRING_HANDLE),
        ("pEnvironment", LPWSTR),
        ("Level", DWORD),
        ("pDrivers", PBYTE_ARRAY),
        ("cbBuf", DWORD),
    )


class RpcEnumPrinterDriversResponse(NDRCALL):
    structure = (
        ("pDrivers", PBYTE_ARRAY),
        ("pcbNeeded", DWORD),
        ("pcReturned", DWORD),
        ("ErrorCode", ULONG),
    )


# MS-RPRN - 3.1.4.4.8
class RpcAddPrinterDriverEx(NDRCALL):
    opnum = 89
    structure = (
        ("pName", STRING_HANDLE),
        ("pDriverContainer", DRIVER_CONTAINER),
        ("dwFileCopyFlags", DWORD),
    )


class RpcAddPrinterDriverExResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


# MS-RPRN - 3.1.4.4.7
class RpcDeletePrinterDriverEx(NDRCALL):
    opnum = 84
    structure = (
        ("pName", STRING_HANDLE),
        ("pEnvironment", WSTR),
        ("pDriverName", WSTR),
        ("dwDeleteFlag", DWORD),
        ("dwVersionNum", DWORD),
    )


class RpcDeletePrinterDriverExResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
    10: (RpcEnumPrinterDrivers, RpcEnumPrinterDriversResponse),
    84: (RpcDeletePrinterDriverEx, RpcDeletePrinterDriverExResponse),
    89: (RpcAddPrinterDriverEx, RpcAddPrinterDriverExResponse),
}


################################################################################
# HELPER FUNCTIONS
################################################################################
def hRpcAddPrinterDriverEx(dce, pName, pDriverContainer, dwFileCopyFlags):
    request = RpcAddPrinterDriverEx()

    request["pName"] = checkNullString(pName)
    request["pDriverContainer"] = pDriverContainer
    request["dwFileCopyFlags"] = dwFileCopyFlags

    return dce.request(request)
