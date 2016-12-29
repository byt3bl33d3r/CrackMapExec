import BaseHTTPServer
import threading
import ssl
import os
import sys
import logging
from getpass import getuser
from BaseHTTPServer import BaseHTTPRequestHandler
from logging import getLogger
from gevent import sleep
from cme.helpers import highlight
from cme.logger import CMEAdapter

class RequestHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        server_logger = CMEAdapter(getLogger('CME'), {'module': self.server.module.name.upper(), 'host': self.client_address[0]})
        server_logger.info("- - %s" % (format%args))

    def do_GET(self):
        if hasattr(self.server.module, 'on_request'):
            server_logger = CMEAdapter(getLogger('CME'), {'module': self.server.module.name.upper(), 'host': self.client_address[0]})
            self.server.context.log = server_logger
            self.server.module.on_request(self.server.context, self)

    def do_POST(self):
        if hasattr(self.server.module, 'on_response'):
            server_logger = CMEAdapter(getLogger('CME'), {'module': self.server.module.name.upper(), 'host': self.client_address[0]})
            self.server.context.log = server_logger
            self.server.module.on_response(self.server.context, self)

    def stop_tracking_host(self):
        '''
            This gets called when a module has finshed executing, removes the host from the connection tracker list
        '''
        try:
            self.server.hosts.remove(self.client_address[0])
        except ValueError:
            pass

class CMEServer(threading.Thread):

    def __init__(self, module, context, logger, srv_host, port, server_type='https'):

        if port <= 1024 and os.geteuid() != 0:
            logger.error("I'm sorry {}, I'm afraid I can't let you do that".format(getuser()))
            sys.exit(1)

        try:
            threading.Thread.__init__(self)

            self.server = BaseHTTPServer.HTTPServer((srv_host, int(port)), RequestHandler)
            self.server.hosts   = []
            self.server.module  = module
            self.server.context = context
            self.server.log     = context.log
            self.cert_path      = os.path.join(os.path.expanduser('~/.cme'), 'cme.pem')

            logging.debug('CME server type: ' + server_type)
            if server_type == 'https':
                self.server.socket = ssl.wrap_socket(self.server.socket, certfile=self.cert_path, server_side=True)

        except Exception as e:
            errno, message = e.args
            if errno == 98 and message == 'Address already in use':
                logger.error('Error starting CME server: the port is already in use, try specifying a diffrent port using --server-port')
            else:
                logger.error('Error starting CME server: {}'.format(message))

            sys.exit(1)

    def base_server(self):
        return self.server

    def run(self):
        try:
            self.server.serve_forever()
        except:
            pass

    def shutdown(self):
        try:
            while len(self.server.hosts) > 0:
                self.server.log.info('Waiting on {} host(s)'.format(highlight(len(self.server.hosts))))
                sleep(15)
        except KeyboardInterrupt:
            pass

        # shut down the server/socket
        self.server.shutdown()
        self.server.socket.close()
        self.server.server_close()
        self._Thread__stop()

        # make sure all the threads are killed
        for thread in threading.enumerate():
            if thread.isAlive():
                try:
                    thread._Thread__stop()
                except:
                    pass
