import requests
import os
from gevent.pool import Pool
from datetime import datetime
from sys import exit
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
from cme.connection import *
from cme.helpers.http import *
from requests import ConnectionError, ConnectTimeout, ReadTimeout
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# The following disables the warning on an invalid cert and allows any SSL/TLS cipher to be used
# I'm basically guessing this is the way to specify to allow all ciphers since I can't find any docs about it, if it don't worky holla at me
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':ANY:ALL'
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from splinter import Browser
    from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
except ImportError:
    print highlight('[!] HTTP protocol requires splinter and phantomjs', 'red')
    exit(1)

class http(connection):

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        http_parser = parser.add_parser('http', help="own stuff using HTTP", parents=[std_parser, module_parser])
        http_parser.add_argument('--ports', nargs='*', default=[80, 443, 8443, 8008, 8080, 8081], help='http ports to connect to (default: 80, 443, 8443, 8008, 8080, 8081)')
        http_parser.add_argument('--transports', nargs='+', choices=['http', 'https'], default=['http', 'https'], help='force connection over http or https (default: all)')
        http_parser.add_argument('--screenshot', action='store_true', help='take a screenshot of the loaded webpage')

        return parser

    def proto_flow(self):

        def start(self, transport, port):
            conn = self.create_conn_obj(transport, port)
            if conn:
                self.proto_logger(transport, port)
                self.print_host_info(conn)
                self.call_cmd_args(conn, transport, port)

        pool = Pool(len(self.args.transports) * len(self.args.ports))
        jobs = []
        for transport in self.args.transports:
            for port in self.args.ports:
                jobs.append(pool.spawn(start, self, transport, port))

        for job in jobs:
            job.join()

    def call_cmd_args(self, conn, transport, port):
        for k, v in vars(self.args).iteritems():
            if hasattr(self, k) and hasattr(getattr(self, k), '__call__'):
                if v is not False and v is not None:
                    logging.debug('Calling {}()'.format(k))
                    getattr(self, k)(conn, transport, port)

    def proto_logger(self, transport, port):
        self.logger = CMEAdapter(extra={'protocol': 'HTTP',
                                        'host': self.host,
                                        'port': port,
                                        'hostname': self.hostname})

    def print_host_info(self, conn):
        self.logger.info('{} (Title: {})'.format(conn.url, conn.title.strip()))

    def create_conn_obj(self, transport, port):
        user_agent = get_desktop_uagent()
        url = '{}://{}:{}/'.format(transport, self.hostname, port)
        try:
            r = requests.get(url, timeout=10, headers={'User-Agent': user_agent})
        except ConnectTimeout, ReadTimeout:
            return False
        except Exception as e:
            if str(e).find('Read timed out') == -1:
                logging.debug('Error connecting to {}://{}:{} :{}'.format(transport, self.hostname, port, e))
            return False

        capabilities = DesiredCapabilities.PHANTOMJS
        capabilities['phantomjs.page.settings.userAgent'] = user_agent
        #capabilities['phantomjs.page.settings.resourceTimeout'] = 10 * 1000
        capabilities['phantomjs.page.settings.userName'] = 'none'
        capabilities['phantomjs.page.settings.password'] = 'none'

        conn = Browser('phantomjs', service_args=['--ignore-ssl-errors=true', '--web-security=no', '--ssl-protocol=any'],
                            service_log_path=os.path.expanduser('~/.cme/logs/ghostdriver.log'), desired_capabilities=capabilities)

        conn.driver.set_window_size(1200, 675)
        conn.visit(url)
        return conn

    def screenshot(self, conn, transport, port):
        screen_output = os.path.join(os.path.expanduser('~/.cme/logs/'), '{}:{}_{}'.format(self.hostname, port, datetime.now().strftime("%Y-%m-%d_%H%M%S")))
        conn.screenshot(name=screen_output)
        self.logger.success('Screenshot stored at {}.png'.format(screen_output))
