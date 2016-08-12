from impacket.dcerpc.v5 import transport, srvs, wkst
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dtypes import NULL

class RPCQUERY():
    def __init__(self, connection):
        self.logger = connection.logger
        self.connection = connection
        self.host = connection.host
        self.username = connection.username
        self.password = connection.password
        self.domain = connection.domain
        self.hash = connection.hash
        self.nthash = ''
        self.lmhash = ''
        self.local_ip = None
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
        if self.password is None:
            self.password = ''
        if self.hash:
            self.lmhash, self.nthash = self.hash.split(':')

    def connect(self, service):

        if service == 'wkssvc':
            stringBinding = r'ncacn_np:{}[\PIPE\wkssvc]'.format(self.host)
        elif service == 'srvsvc':
            stringBinding = r'ncacn_np:{}[\PIPE\srvsvc]'.format(self.host)

        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

        dce = rpctransport.get_dce_rpc()
        dce.connect()

        if service == 'wkssvc':
            dce.bind(wkst.MSRPC_UUID_WKST, transfer_syntax = self.ts)
        elif service == 'srvsvc':
            dce.bind(srvs.MSRPC_UUID_SRVS, transfer_syntax = self.ts)

        self.local_ip = rpctransport.get_smb_server().get_socket().getsockname()[0]
        return dce, rpctransport

    def enum_lusers(self):
        dce, rpctransport = self.connect('wkssvc')

        try:
            resp = wkst.hNetrWkstaUserEnum(dce, 1)
            lusers =  resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']
        except Exception:
            return

        self.logger.success("Enumerating logged on users")
        for user in lusers:
            self.logger.highlight(u'Username: {}\\{} {}'.format(user['wkui1_logon_domain'],
                                                                user['wkui1_username'],
                                                                'LogonServer: {}'.format(user['wkui1_logon_server']) if user['wkui1_logon_server'] != '\x00' else ''))

    def enum_sessions(self):
        dce, rpctransport = self.connect('srvsvc')
        
        try:
            level = 502
            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, level)
            sessions  = resp['InfoStruct']['SessionInfo']['Level502']['Buffer']
        except Exception:
            pass

        try:
            level = 0
            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, level)
            sessions  = resp['InfoStruct']['SessionInfo']['Level0']['Buffer']
        except Exception:
            return

        self.logger.success("Enumerating active sessions")
        for session in sessions:
            if level == 502:
                if session['sesi502_cname'][:-1] != self.local_ip:
                    self.logger.highlight(u'\\\\{} {} [opens:{} time:{} idle:{}]'.format(session['sesi502_cname'], 
                                                                                        session['sesi502_username'],
                                                                                        session['sesi502_num_opens'],
                                                                                        session['sesi502_time'],
                                                                                        session['sesi502_idle_time']))

            elif level == 0:
                if session['sesi0_cname'][:-1] != self.local_ip:
                    self.logger.highlight(u'\\\\{}'.format(session['sesi0_cname']))

    def enum_disks(self):
        dce, rpctransport = self.connect('srvsvc')

        try:
            resp = srvs.hNetrServerDiskEnum(dce, 1)
        except Exception:
            pass

        try:
            resp = srvs.hNetrServerDiskEnum(dce, 0)
        except Exception:
            return

        self.logger.success("Enumerating disks")
        for disk in resp['DiskInfoStruct']['Buffer']:
            for dname in disk.fields.keys():
                if disk[dname] != '\x00':
                    self.logger.highlight(disk[dname])