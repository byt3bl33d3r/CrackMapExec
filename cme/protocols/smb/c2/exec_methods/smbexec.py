import logging
from gevent import sleep
from cme.helpers.misc import gen_random_string
from impacket.dcerpc.v5 import transport, scmr


class SMBEXEC(object):
    def __init__(self, target, username, password, domain, lmhash, nthash, connection=None):
        self.connection = connection
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.serviceName = gen_random_string(8)
        self.aesKey = None
        self.doKerberos = False
        self.shell = '%COMSPEC% /Q /C '
        self.rpctransport = None
        self.scmr = None
        self.conn = None

        stringbinding = 'ncacn_np:%s[\pipe\svcctl]' % self.target
        logging.debug('StringBinding {}'.format(stringbinding))
        self.rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.rpctransport.set_dport(445)

        if hasattr(self.rpctransport, 'setRemoteHost'):
            self.rpctransport.setRemoteHost(self.target)
        if hasattr(self.rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            self.rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
        #rpctransport.set_kerberos(self.doKerberos, self.kdcHost)

        self.scmr = self.rpctransport.get_dce_rpc()
        self.scmr.connect()

        self.scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.scmr)
        self.scHandle = resp['lpScHandle']

    def execute_command(self, data):

        command = self.shell + data

        logging.debug('Command to execute: ' + command)

        resp = scmr.hRCreateServiceW(self.scmr, self.scHandle, self.serviceName, self.serviceName, lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        logging.debug('Remote service {} created.'.format(self.serviceName))
        service = resp['lpServiceHandle']

        while True:
            try:
                scmr.hRStartServiceW(self.scmr, service)
                logging.debug('Remote service {} started.'.format(self.serviceName))
                break
            except Exception as e:
                if str(e).find("ERROR_SERVICE_REQUEST_TIMEOUT") != -1:
                    logging.debug('Remote service {} started.'.format(self.serviceName))
                    break
                else:
                    logging.debug('Failed to start remote service {}: {}'.format(self.serviceName, e))
                    sleep(4)

        try:
            self.scmr = self.rpctransport.get_dce_rpc()
            self.scmr.connect()
            self.scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.scmr)
            self.scHandle = resp['lpScHandle']
            resp = scmr.hROpenServiceW(self.scmr, self.scHandle, self.serviceName)
            service = resp['lpServiceHandle']
            scmr.hRDeleteService(self.scmr, service)
            logging.debug('Remote service {} deleted.'.format(self.serviceName))
            #scmr.hRControlService(self.scmr, service, scmr.SERVICE_CONTROL_STOP)
            scmr.hRCloseServiceHandle(self.scmr, service)
        except Exception as e:
            logging.debug("Error deleting service {}: {}".format(self.serviceName, e))
