#Stolen from Impacket

import logging
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.dcerpc.v5 import transport, samr 
from impacket.dcerpc.v5.samr import DCERPCSessionError
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket import ntlm

class UserSamrDump:

    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
    }

    def __init__(self, connection):
        self.logger = connection.logger
        self.addr = connection.host
        self.protocol = connection.args.port
        self.username = connection.username
        self.password = connection.password
        self.domain = connection.domain
        self.hash = connection.hash
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = None
        self.doKerberos = False
        self.protocols = UserSamrDump.KNOWN_PROTOCOLS.keys()
        self.users = []

        if self.hash is not None:
            if self.hash.find(':') != -1:
                self.lmhash, self.nthash = self.hash.split(':')
            else:
                self.nthash = self.hash
        
        if self.password is None:
            self.password = ''

    def dump(self):

        # Try all requested protocols until one works.
        for protocol in self.protocols:
            try:
                protodef = UserSamrDump.KNOWN_PROTOCOLS[protocol]
                port = protodef[1]
            except KeyError:
                logging.debug("Invalid Protocol '{}'".format(protocol))
            logging.debug("Trying protocol {}".format(protocol))
            rpctransport = transport.SMBTransport(self.addr, port, r'\samr', self.username, self.password, self.domain, 
                                                  self.lmhash, self.nthash, self.aesKey, doKerberos = self.doKerberos)
            try:
                self.fetchList(rpctransport)
            except Exception as e:
                logging.debug('Protocol failed: {}'.format(e))
        return self.users

    def fetchList(self, rpctransport):
        dce = DCERPC_v5(rpctransport)
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        # Setup Connection
        resp = samr.hSamrConnect2(dce)
        if resp['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle=resp['ServerHandle'],
                                                      enumerationContext=0,
                                                      preferedMaximumLength=500)
        if resp2['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp3 = samr.hSamrLookupDomainInSamServer(dce, serverHandle=resp['ServerHandle'],
                                                  name=resp2['Buffer']['Buffer'][0]['Name'])
        if resp3['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp4 = samr.hSamrOpenDomain(dce, serverHandle=resp['ServerHandle'],
                                     desiredAccess=samr.MAXIMUM_ALLOWED,
                                     domainId=resp3['DomainId'])
        if resp4['ErrorCode'] != 0:
            raise Exception('Connect error')

        self.__domains = resp2['Buffer']['Buffer']
        domainHandle = resp4['DomainHandle']
        # End Setup

        status = STATUS_MORE_ENTRIES
        enumerationContext = 0
        while status == STATUS_MORE_ENTRIES:
            try:
                resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext = enumerationContext)
            except DCERPCException as e:
                if str(e).find('STATUS_MORE_ENTRIES') < 0:
                    self.logger.error('Error enumerating domain user(s)')
                    break 
                resp = e.get_packet()
            self.logger.success('Enumerated domain user(s)')
            for user in resp['Buffer']['Buffer']:
                r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],samr.USER_INFORMATION_CLASS.UserAllInformation)
                (username, uid, info_user) = (user['Name'], user['RelativeId'], info['Buffer']['All'])
                self.logger.highlight('{}\\{:<30} {}'.format(self.domain, user['Name'], info_user['AdminComment']))
                self.users.append(user['Name'])
                samr.hSamrCloseHandle(dce, r['UserHandle'])

            enumerationContext = resp['EnumerationContext'] 
            status = resp['ErrorCode']

        dce.disconnect()
