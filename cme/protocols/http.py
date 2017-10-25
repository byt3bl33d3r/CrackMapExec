import requests
import os
from gevent.pool import Pool
from gevent.socket import gethostbyname
from urlparse import urlparse
from datetime import datetime
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
from cme.connection import *
from cme.helpers.http import *
from requests import ConnectionError, ConnectTimeout, ReadTimeout
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from splinter import Browser
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

# The following disables the warning on an invalid cert and allows any SSL/TLS cipher to be used
# I'm basically guessing this is the way to specify to allow all ciphers since I can't find any docs about it, if it don't worky holla at me
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':ANY:ALL'
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class http(connection):

    def __init__(self, args, db, host):
        self.args = args
        self.db = db
        self.hostname = host
        self.url = None
        self.transport = None
        self.port = None

        if self.hostname.startswith('http://') or self.hostname.startswith('https://'):
            port_dict = {'http': 80, 'https': 443}
            self.url = self.hostname

            self.transport, netloc,_,_,_,_ = urlparse(self.url)
            self.port = port_dict[self.transport]

            self.hostname = netloc
            if ':' in netloc:
                self.hostname, self.port = netloc.split(':')

        try:
            self.host = gethostbyname(self.hostname)
        except Exception as e:
            logging.debug('Error resolving hostname {}: {}'.format(self.hostname, e))
            return

        self.proto_flow()

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        http_parser = parser.add_parser('http', help="own stuff using HTTP", parents=[std_parser, module_parser])
        http_parser.add_argument('--port', nargs='*', default=[80, 443, 8443, 8008, 8080, 8081], help='http ports to connect to (default: 80, 443, 8443, 8008, 8080, 8081)')
        http_parser.add_argument('--transports', choices=['http', 'https'], default=['http', 'https'], help='force connection over http or https (default: all)')
        http_parser.add_argument('--screenshot', action='store_true', help='take a screenshot of the loaded webpage')

        return parser

    def proto_flow(self):
        if self.url:
            single_connection(self, self.transport, self.port)
        else:
            pool = Pool(len(self.args.transports) * len(self.args.port))
            jobs = []
            for transport in self.args.transports:
                for port in self.args.port:
                    jobs.append(pool.spawn(single_connection, self, transport, port))

            for job in jobs:
                job.join()

class single_connection(connection):

    def __init__(self, http, transport, port):
        self.http = http
        self.db   = http.db
        self.host = http.host
        self.url  = http.url
        self.args = http.args
        self.port = port
        self.transport = transport
        self.hostname  = http.hostname
        self.server_headers = None
        self.conn = None

        self.proto_flow()

    def proto_logger(self):
        self.logger = CMEAdapter(extra={'protocol': 'HTTP',
                                        'host': self.host,
                                        'port': self.port,
                                        'hostname': self.hostname})

    def print_host_info(self):
        self.logger.info('{} (Server: {}) (Page Title: {})'.format(self.conn.url,
                                                                   self.server_headers['Server'] if 'Server' in self.server_headers.keys() else None,
                                                                   self.conn.title.strip() if self.conn.title else None))

    def create_conn_obj(self):
        user_agent = get_desktop_uagent()
        if self.url:
            url = self.url
        else:
            url = '{}://{}:{}/'.format(self.transport, self.hostname, self.port)

        try:
            r = requests.get(url, timeout=10, headers={'User-Agent': user_agent})
            self.server_headers = r.headers
        except ConnectTimeout, ReadTimeout:
            return False
        except Exception as e:
            if str(e).find('Read timed out') == -1:
                logging.debug('Error connecting to {}://{}:{} :{}'.format(self.transport, self.hostname, self.port, e))
            return False

        self.db.add_host(self.host, self.hostname, self.port)

        capabilities = DesiredCapabilities.PHANTOMJS
        capabilities['phantomjs.page.settings.userAgent'] = user_agent
        #capabilities['phantomjs.page.settings.resourceTimeout'] = 10 * 1000
        capabilities['phantomjs.page.settings.userName'] = 'none'
        capabilities['phantomjs.page.settings.password'] = 'none'

        self.conn = Browser('phantomjs', service_args=['--ignore-ssl-errors=true', '--web-security=no', '--ssl-protocol=any'],
                            service_log_path=os.path.expanduser('~/.cme/logs/ghostdriver.log'), desired_capabilities=capabilities)

        self.conn.driver.set_window_size(1200, 675)
        self.conn.visit(url)
        return True

    def screenshot(self):
        screen_output = os.path.join(os.path.expanduser('~/.cme/logs/'), '{}:{}_{}'.format(self.hostname, self.port, datetime.now().strftime("%Y-%m-%d_%H%M%S")))
        self.conn.screenshot(name=screen_output)
        self.logger.success('Screenshot stored at {}.png'.format(screen_output))
