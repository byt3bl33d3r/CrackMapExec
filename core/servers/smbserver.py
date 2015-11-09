from impacket import smbserver
from threading import Thread
import core.settings as settings
import ConfigParser
import random
import logging

class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.smb = None
        self.daemon = True

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file', 'logs/smbserver.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        smbConfig.add_section('TMP')
        smbConfig.set('TMP','comment','')
        smbConfig.set('TMP','read only','no')
        smbConfig.set('TMP','share type','0')
        smbConfig.set('TMP','path', 'hosted')

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        self.smb.processConfigFile()
        logging.info('SMB server ready')
        self.smb.serve_forever()

    def stop(self):
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()
