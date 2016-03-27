#!/usr/bin/python
# Copyright (c) 2003-2015 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: DCE/RPC SAMR dumper.
#
# Author:
#  Javier Kohen <jkohen@coresecurity.com>
#  Alberto Solino (@agsolino)
#
# Reference for:
#  DCE/RPC for SAMR

import logging

from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException

class ListUsersException(Exception):
    pass

class SAMRDump:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
        }

    def __init__(self, logger, protocol, connection):

        self.__username = connection.username
        self.__addr = connection.host
        self.__password = connection.password
        self.__domain = connection.domain
        self.__hash = connection.hash
        self.__protocol = protocol
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__doKerberos = False
        self.__logger = logger

        if self.__hash is not None:
            self.__lmhash, self.__nthash = self.__hash.split(':')
        
        if self.__password is None:
            self.__password = ''

    def enum(self):
        """Dumps the list of users and shares registered present at
        addr. Addr is a valid host name or IP address.
        """

        logging.info('Retrieving endpoint list from %s' % self.__addr)

        # Try all requested protocols until one works.
        entries = []

        protodef = SAMRDump.KNOWN_PROTOCOLS['{}/SMB'.format(self.__protocol)]
        port = protodef[1]

        logging.info("Trying protocol %s..." % self.__protocol)
        rpctransport = transport.SMBTransport(self.__addr, port, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)

        try:
            entries = self.__fetchList(rpctransport)
        except Exception, e:
            logging.critical(str(e))

        # Display results.

        self.__logger.success('Dumping users')
        for entry in entries:
            (username, uid, user) = entry
            base = "%s (%d)" % (username, uid)
            self.__logger.highlight(u'{}/FullName: {}'.format(base, user['FullName']))
            self.__logger.highlight(u'{}/UserComment: {}' .format(base, user['UserComment']))
            self.__logger.highlight(u'{}/PrimaryGroupId: {}'.format(base, user['PrimaryGroupId']))
            self.__logger.highlight(u'{}/BadPasswordCount: {}'.format(base, user['BadPasswordCount']))
            self.__logger.highlight(u'{}/LogonCount: {}'.format(base, user['LogonCount']))

        if entries:
            num = len(entries)
            if 1 == num:
                logging.info('Received one entry.')
            else:
                logging.info('Received %d entries.' % num)
        else:
            logging.info('No entries received.')


    def __fetchList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        entries = []

        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        try:
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle'] 

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']

            logging.info('Found domain(s):')
            for domain in domains:
                logging.info(" . %s" % domain['Name'])

            logging.info("Looking up users in domain %s" % domains[0]['Name'])

            resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle,domains[0]['Name'] )

            resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
            domainHandle = resp['DomainHandle']

            status = STATUS_MORE_ENTRIES
            enumerationContext = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext = enumerationContext)
                except DCERPCException as e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise 
                    resp = e.get_packet()

                for user in resp['Buffer']['Buffer']:
                    r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                    logging.info(u"Found user: %s, uid = %d" % (user['Name'], user['RelativeId']))
                    info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],samr.USER_INFORMATION_CLASS.UserAllInformation)
                    entry = (user['Name'], user['RelativeId'], info['Buffer']['All'])
                    entries.append(entry)
                    samr.hSamrCloseHandle(dce, r['UserHandle'])

                enumerationContext = resp['EnumerationContext'] 
                status = resp['ErrorCode']

        except ListUsersException, e:
            logging.critical("Error listing users: %s" % e)

        dce.disconnect()

        return entries