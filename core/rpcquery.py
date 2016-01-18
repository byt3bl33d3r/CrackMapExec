import logging
from impacket.dcerpc.v5 import transport, srvs, wkst
from impacket.dcerpc.v5.dtypes import NULL
import settings

class RPCQUERY():
    def __init__(self, logger, username, password, domain='', hashes=None):
        self.__logger = logger
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__local_ip = None
        self.__ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
        if self.__password is None:
            self.__password = ''
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

        self.__local_ip = rpctransport.get_smb_server().get_socket().getsockname()[0]
        return dce, rpctransport

    def enum_lusers(self, host):
        dce, rpctransport = self.connect(host, 'wkssvc')
        resp = wkst.hNetrWkstaUserEnum(dce, 1)
        lusers =  resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']

        self.__logger.success("Enumerating logged on users")
        for user in lusers:
            self.__logger.results(u'{}\\{} {} {}'.format(user['wkui1_logon_domain'],
                                                         user['wkui1_username'],
                                                         user['wkui1_logon_server'],
                                                         user['wkui1_oth_domains']))

    def enum_sessions(self, host):
        dce, rpctransport = self.connect(host, 'srvsvc')
        level = 502
        try:
            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, level)
            sessions  = resp['InfoStruct']['SessionInfo']['Level502']['Buffer']
        except Exception:
            level = 0
            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, level)
            sessions  = resp['InfoStruct']['SessionInfo']['Level0']['Buffer']

        self.__logger.success("Enumerating active sessions")
        for session in sessions:
            if level == 502:
                if session['sesi502_cname'][:-1] != self.__local_ip:
                    self.__logger.results('\\\\{} {} [opens:{} time:{} idle:{}]'.format(session['sesi502_cname'], 
                                                                                        session['sesi502_username'],
                                                                                        session['sesi502_num_opens'],
                                                                                        session['sesi502_time'],
                                                                                        session['sesi502_idle_time']))

            elif level == 0:
                if session['sesi0_cname'][:-1] != self.__local_ip:
                    self.__logger.results('\\\\{}'.format(session['sesi0_cname']))

    def enum_disks(self, host):
        dce, rpctransport = self.connect(host, 'srvsvc')
        try:
            resp = srvs.hNetrServerDiskEnum(dce, 1)
        except Exception:
            resp = srvs.hNetrServerDiskEnum(dce, 0)

        self.__logger.success("Enumerating disks")
        for disk in resp['DiskInfoStruct']['Buffer']:
            for dname in disk.fields.keys():
                if disk[dname] != '\x00':
                    self.__logger.results(disk[dname])