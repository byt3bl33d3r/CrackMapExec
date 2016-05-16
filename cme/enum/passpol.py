import sys
import codecs
import logging

from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from time import strftime, gmtime

class PassPolDump:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
        }

    def __init__(self, logger, protocol, connection):
        self.logger = logger
        self.addr = connection.host
        self.protocol = protocol
        self.username = connection.username
        self.password = connection.password
        self.domain = connection.domain
        self.hash = connection.hash
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = None
        self.doKerberos = False
        
        if self.hash is not None:
            self.lmhash, self.nthash = self.hash.split(':')
        
        if self.password is None:
            self.password = ''

    def enum(self):

        #logging.info('Retrieving endpoint list from %s' % addr)

        entries = []

        protodef = PassPolDump.KNOWN_PROTOCOLS['{}/SMB'.format(self.protocol)]
        port = protodef[1]

        logging.info("Trying protocol %s..." % self.protocol)
        rpctransport = transport.SMBTransport(self.addr, port, r'\samr', self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, doKerberos = self.doKerberos)

        dce = rpctransport.get_dce_rpc()
        dce.connect()

        dce.bind(samr.MSRPC_UUID_SAMR)

        resp = samr.hSamrConnect(dce)
        serverHandle = resp['ServerHandle'] 

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
        domains = resp['Buffer']['Buffer']

        resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])

        resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
        domainHandle = resp['DomainHandle']

        self.logger.success('Dumping password policy')
        self.get_pass_pol(self.addr, rpctransport, dce, domainHandle)

    def convert(self, low, high, no_zero):

        if low == 0 and hex(high) == "-0x80000000":
            return "Not Set"
        if low == 0 and high == 0:
            return "None"
        if no_zero: # make sure we have a +ve vale for the unsined int
            if (low != 0):
                high = 0 - (high+1)
            else:
                high = 0 - (high)
            low = 0 - low
        tmp = low + (high)*16**8 # convert to 64bit int
        tmp *= (1e-7) #  convert to seconds
        try:
            minutes = int(strftime("%M", gmtime(tmp)))  # do the conversion to human readable format
        except ValueError, e:
            return "BAD TIME:"
        hours = int(strftime("%H", gmtime(tmp)))
        days = int(strftime("%j", gmtime(tmp)))-1
        time = ""
        if days > 1:
         time = str(days) + " days "
        elif days == 1:
            time = str(days) + " day "
        if hours > 1:
            time += str(hours) + " hours "
        elif hours == 1:
            time = str(days) + " hour " 
        if minutes > 1:
            time += str(minutes) + " minutes"
        elif minutes == 1:
            time = str(days) + " minute "
        return time

    def get_pass_pol(self, host, rpctransport, dce, domainHandle):

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)

        min_pass_len = resp['Buffer']['Password']['MinPasswordLength']

        pass_hst_len = resp['Buffer']['Password']['PasswordHistoryLength']

        self.logger.highlight('Minimum password length: {}'.format(min_pass_len))
        self.logger.highlight('Password history length: {}'.format(pass_hst_len))

        max_pass_age = self.convert(resp['Buffer']['Password']['MaxPasswordAge']['LowPart'], 
                                    resp['Buffer']['Password']['MaxPasswordAge']['HighPart'],
                                    1)

        min_pass_age = self.convert(resp['Buffer']['Password']['MinPasswordAge']['LowPart'], 
                                    resp['Buffer']['Password']['MinPasswordAge']['HighPart'],
                                    1)

        self.logger.highlight('Maximum password age: {}'.format(max_pass_age))
        self.logger.highlight('Minimum password age: {}'.format(min_pass_age))

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)

        lock_threshold = int(resp['Buffer']['Lockout']['LockoutThreshold'])

        self.logger.highlight("Account lockout threshold: {}".format(lock_threshold))

        lock_duration = None
        if lock_threshold != 0: lock_duration = int(resp['Buffer']['Lockout']['LockoutDuration']) / -600000000

        self.logger.highlight("Account lockout duration: {}".format(lock_duration))