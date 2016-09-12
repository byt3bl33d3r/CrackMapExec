import BaseHTTPServer
import threading
import ssl
import os
import sys
from BaseHTTPServer import BaseHTTPRequestHandler
from logging import getLogger
from gevent import sleep
from cme.helpers import highlight
from cme.logger import CMEAdapter
from cme.cmeserver import CMEServer

class RequestHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        module = self.server.host_chain[self.client_address[0]][0]
        server_logger = CMEAdapter(getLogger('CME'), {'module': module.name.upper(), 'host': self.client_address[0]})
        server_logger.info("- - %s" % (format%args))

    def do_GET(self):
        current_module = self.server.host_chain[self.client_address[0]][0]

        if hasattr(current_module, 'on_request'):

            module_list = self.server.host_chain[self.client_address[0]][:]
            module_list.reverse()

            final_launcher = module_list[0].launcher(self.server.context, None if not hasattr(module_list[0], 'command') else module_list[0].command)
            if len(module_list) > 2:
                for module in module_list:
                    if module == current_module or module == module_list[0]:
                        continue

                    server_logger = CMEAdapter(getLogger('CME'), {'module': module.name.upper(), 'host': self.client_address[0]})
                    self.server.context.log = server_logger
                    
                    final_launcher = module.launcher(self.server.context, final_launcher)

            server_logger = CMEAdapter(getLogger('CME'), {'module': current_module.name.upper(), 'host': self.client_address[0]})
            self.server.context.log = server_logger

            if current_module == module_list[0]: final_launcher = None if not hasattr(module_list[0], 'command') else module_list[0].command

            launcher = current_module.launcher(self.server.context, final_launcher)
            payload  = current_module.payload(self.server.context, final_launcher)

            current_module.on_request(self.server.context, self, launcher, payload)

            if not hasattr(current_module, 'on_response'):
                try:
                    del self.server.host_chain[self.client_address[0]][0]
                except KeyError or IndexError:
                    pass

    def do_POST(self):
        self.server.log.debug(self.server.host_chain)
        module = self.server.host_chain[self.client_address[0]][0]

        if hasattr(module, 'on_response'):
            server_logger = CMEAdapter(getLogger('CME'), {'module': module.name.upper(), 'host': self.client_address[0]})
            self.server.context.log = server_logger
            module.on_response(self.server.context, self)

            try:
                del self.server.host_chain[self.client_address[0]][0]
            except KeyError or IndexError:
                pass

    def stop_tracking_host(self):
        '''
            This gets called when a module has finshed executing, removes the host from the connection tracker list
        '''
        if len(self.server.host_chain[self.client_address[0]]) == 1:
            try:
                self.server.hosts.remove(self.client_address[0])
                del self.server.host_chain[self.client_address[0]]
            except ValueError:
                pass

class CMEChainServer(CMEServer):

    def __init__(self, chain_list, context, logger, srv_host, port, server_type='https'):

        try:
            threading.Thread.__init__(self)

            self.server = BaseHTTPServer.HTTPServer((srv_host, int(port)), RequestHandler)
            self.server.hosts   = []
            self.server.host_chain = {}
            self.server.chain_list = chain_list
            self.server.context = context
            self.server.log     = context.log
            self.cert_path      = os.path.join(os.path.expanduser('~/.cme'), 'cme.pem')

            if server_type == 'https':
                self.server.socket = ssl.wrap_socket(self.server.socket, certfile=self.cert_path, server_side=True)

        except Exception as e:
            errno, message = e.args
            if errno == 98 and message == 'Address already in use':
                logger.error('Error starting HTTP(S) server: the port is already in use, try specifying a diffrent port using --server-port')
            else:
                logger.error('Error starting HTTP(S) server: {}'.format(message))

            sys.exit(1)

    def track_host(self, host_ip):
        self.server.hosts.append(host_ip)
        self.server.host_chain[host_ip] = [module['object'] for module in self.server.chain_list]