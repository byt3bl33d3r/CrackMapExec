from impacket import tds
from impacket.tds import SQLErrorException, TDS_LOGINACK_TOKEN, TDS_ERROR_TOKEN, TDS_ENVCHANGE_TOKEN, TDS_INFO_TOKEN, \
    TDS_ENVCHANGE_VARCHAR, TDS_ENVCHANGE_DATABASE, TDS_ENVCHANGE_LANGUAGE, TDS_ENVCHANGE_CHARSET, TDS_ENVCHANGE_PACKETSIZE

#We hook these functions in the tds library to use CME's logger instead of printing the output to stdout
#The whole tds library in impacket needs a good overhaul to preserve my sanity

def printRowsCME(self):
    if self.lastError is True:
        return
    out = ''
    self.processColMeta()
    #self.printColumnsHeader()
    for row in self.rows:
        for col in self.colMeta:
            if row[col['Name']] != 'NULL': 
                out += col['Format'] % row[col['Name']] + self.COL_SEPARATOR + '\n' 

    return out    

def printRepliesCME(self):
    for keys in self.replies.keys():
        for i, key in enumerate(self.replies[keys]):
            if key['TokenType'] == TDS_ERROR_TOKEN:
                error =  "ERROR(%s): Line %d: %s" % (key['ServerName'].decode('utf-16le'), key['LineNumber'], key['MsgText'].decode('utf-16le'))                                      
                self.lastError = SQLErrorException("ERROR: Line %d: %s" % (key['LineNumber'], key['MsgText'].decode('utf-16le')))
                self._MSSQL__rowsPrinter.error(error)

            elif key['TokenType'] == TDS_INFO_TOKEN:
                self._MSSQL__rowsPrinter.info("INFO(%s): Line %d: %s" % (key['ServerName'].decode('utf-16le'), key['LineNumber'], key['MsgText'].decode('utf-16le')))

            elif key['TokenType'] == TDS_LOGINACK_TOKEN:
                self._MSSQL__rowsPrinter.info("ACK: Result: %s - %s (%d%d %d%d) " % (key['Interface'], key['ProgName'].decode('utf-16le'), key['MajorVer'], key['MinorVer'], key['BuildNumHi'], key['BuildNumLow']))

            elif key['TokenType'] == TDS_ENVCHANGE_TOKEN:
                if key['Type'] in (TDS_ENVCHANGE_DATABASE, TDS_ENVCHANGE_LANGUAGE, TDS_ENVCHANGE_CHARSET, TDS_ENVCHANGE_PACKETSIZE):
                    record = TDS_ENVCHANGE_VARCHAR(key['Data'])
                    if record['OldValue'] == '':
                        record['OldValue'] = 'None'.encode('utf-16le')
                    elif record['NewValue'] == '':
                        record['NewValue'] = 'None'.encode('utf-16le')
                    if key['Type'] == TDS_ENVCHANGE_DATABASE:
                        _type = 'DATABASE'
                    elif key['Type'] == TDS_ENVCHANGE_LANGUAGE:
                        _type = 'LANGUAGE'
                    elif key['Type'] == TDS_ENVCHANGE_CHARSET:
                        _type = 'CHARSET'
                    elif key['Type'] == TDS_ENVCHANGE_PACKETSIZE:
                        _type = 'PACKETSIZE'
                    else:
                        _type = "%d" % key['Type']                 
                    self._MSSQL__rowsPrinter.info("ENVCHANGE(%s): Old Value: %s, New Value: %s" % (_type,record['OldValue'].decode('utf-16le'), record['NewValue'].decode('utf-16le')))

tds.MSSQL.printReplies = printRepliesCME
tds.MSSQL.printRows = printRowsCME