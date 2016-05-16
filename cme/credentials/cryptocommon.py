from struct import pack

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