# Work in progress

import threading
import ConfigParser
import logging
import impacket.smb3structs as smb2
from impacket import smbserver, smb
from impacket.smbserver import SRVSServer


class CMESMBServer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global', 'server_name', 'server_name')
        smbConfig.set('global', 'server_os', 'UNIX')
        smbConfig.set('global', 'server_domain', 'WORKGROUP')
        smbConfig.set('global', 'log_file', '')
        smbConfig.set('global', 'credentials_file', '')

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$', 'comment', 'Logon server share')
        smbConfig.set('IPC$', 'read only', 'yes')
        smbConfig.set('IPC$', 'share type', '3')
        smbConfig.set('IPC$', 'path', '')

        # NETLOGON always needed
        smbConfig.add_section('NETLOGON')
        smbConfig.set('NETLOGON','comment','Logon server share')
        smbConfig.set('NETLOGON','read only','no')
        smbConfig.set('NETLOGON','share type','0')
        smbConfig.set('NETLOGON','path','')

        # SYSVOL always needed
        smbConfig.add_section('SYSVOL')
        smbConfig.set('SYSVOL','comment','')
        smbConfig.set('SYSVOL','read only','no')
        smbConfig.set('SYSVOL','share type','0')
        smbConfig.set('SYSVOL','path','')

        smbConfig.add_section('CME')
        smbConfig.set('CME', 'comment', '')
        smbConfig.set('CME', 'read only', 'no')
        smbConfig.set('CME', 'share type', '0')
        smbConfig.set('CME', 'path', '/tmp')

        # Enable SMB2 support
        #smbConfig.set("global", "SMB2Support", "True")

        self.server = smbserver.SMBSERVER(('0.0.0.0', 445), config_parser=smbConfig)
        self.server.processConfigFile()

        self.origsmbComWrite = self.server.hookSmbCommand(smb.SMB.SMB_COM_WRITE, self.smbComWrite)
        self.origsmbComWriteAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_WRITE_ANDX, self.smbComWriteAndX)
        self.origsmbComRead = self.server.hookSmbCommand(smb.SMB.SMB_COM_READ, self.smbComRead)
        self.origsmbComReadAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_READ_ANDX, self.smbComReadAndX)

        self.origsmb2Write = self.server.hookSmb2Command(smb2.SMB2_WRITE, self.smb2Write)
        self.origsmb2Read = self.server.hookSmb2Command(smb2.SMB2_READ, self.smb2Read)

        # Now we have to register the MS-SRVS server. This specially important for
        # Windows 7+ and Mavericks clients since they WONT (specially OSX)
        # ask for shares using MS-RAP.

        self.__srvsServer = SRVSServer()
        self.__srvsServer.daemon = True
        self.server.registerNamedPipe('srvsvc', ('127.0.0.1', self.__srvsServer.getListenPort()))

    def smbComWrite(self, connId, smbServer, SMBCommand, recvPacket):
        logging.debug('smbComWrite', dir(connId))
        return self.origsmbComWrite(connId, smbServer, SMBCommand, recvPacket)

    def smbComWriteAndX(self, connId, smbServer, SMBCommand, recvPacket):
        logging.debug('smbComWriteAndX', dir(connId))
        return self.origsmbComWriteAndX(connId, smbServer, SMBCommand, recvPacket)

    def smbComRead(self, connId, smbServer, SMBCommand, recvPacket):
        logging.debug('smbComRead', dir(connId))
        return self.origsmbComRead(connId, smbServer, SMBCommand, recvPacket)

    def smbComReadAndX(self, connId, smbServer, SMBCommand, recvPacket):
        logging.debug('smbComReadAndX', dir(connId))
        return self.origsmbComReadAndX(connId, smbServer, SMBCommand, recvPacket)

    def smb2Read(self, connId, smbServer, recvPacket):
        logging.debug('smb2Read', dir(connId))
        #connData = smbServer.getConnectionData(connId)
        #connData['MS15011']['StopConnection'] = True
        #smbServer.setConnectionData(connId, connData)
        return self.origsmb2Read(connId, smbServer, recvPacket)

    def smb2Write(self, connId, smbServer, recvPacket):
        logging.debug('smb2Write', dir(connId))
        #connData = smbServer.getConnectionData(connId)
        #connData['MS15011']['StopConnection'] = True
        #smbServer.setConnectionData(connId, connData)
        return self.origsmb2Write(connId, smbServer, recvPacket)

