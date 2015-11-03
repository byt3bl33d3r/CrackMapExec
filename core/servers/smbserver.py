from impacket.smbserver import SMBSERVER, SRVSServer, WKSTServer
import ConfigParser
import random

class SMBserver:

    def __init__(self, listenAddress='0.0.0.0', listenPort=445):

        self.smbConfig = ConfigParser.ConfigParser()
        self.smbConfig.add_section('global')
        self.smbConfig.set('global','server_name',''.join([random.choice(string.letters) for _ in range(8)]))
        self.smbConfig.set('global','server_os',''.join([random.choice(string.letters) for _ in range(8)]))
        self.smbConfig.set('global','server_domain',''.join([random.choice(string.letters) for _ in range(8)]))
        self.smbConfig.set('global','log_file',str(''))
        self.smbConfig.set('global','rpc_apis','yes')
        self.smbConfig.set('global','credentials_file',str(''))
        self.smbConfig.set('global', 'challenge', str('A'*8))
        self.smbConfig.set("global", 'SMB2Support', 'False')

        # IPC always needed
        self.smbConfig.add_section('IPC$')
        self.smbConfig.set('IPC$','comment',str(''))
        self.smbConfig.set('IPC$','read only','yes')
        self.smbConfig.set('IPC$','share type','3')
        self.smbConfig.set('IPC$','path',str(''))

        self.smbConfig.add_section('TMP')
        self.smbConfig.set('TMP','comment',str(''))
        self.smbConfig.set('TMP','read only','no')
        self.smbConfig.set('TMP','share type','0')
        self.smbConfig.set('TMP','path', 'hosted')

        if args.path:
            self.smbConfig.add_section('TMP2')
            self.smbConfig.set('TMP2','comment',str(''))
            self.smbConfig.set('TMP2','read only','yes')
            self.smbConfig.set('TMP2','share type','0')
            self.smbConfig.set('TMP2','path', args.path)

        self.server = SMBSERVER((listenAddress,listenPort), config_parser=self.smbConfig)
        self.server.processConfigFile()

        # Now we have to register the MS-SRVS server. This specially important for 
        # Windows 7+ and Mavericks clients since they WONT (specially OSX) 
        # ask for shares using MS-RAP.

        self.srvsServer = SRVSServer()
        self.srvsServer.daemon = True
        self.wkstServer = WKSTServer()
        self.wkstServer.daemon = True
        self.server.registerNamedPipe('srvsvc',('127.0.0.1',self.srvsServer.getListenPort()))
        self.server.registerNamedPipe('wkssvc',('127.0.0.1',self.wkstServer.getListenPort()))
        self.srvsServer.setServerConfig(self.smbConfig)
        self.srvsServer.processConfigFile()

    def serve_forever(self):
        self.srvsServer.start()
        self.wkstServer.start()
        self.server.serve_forever()