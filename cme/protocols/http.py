import requests
import bs4
from socket import gethostbyname
from requests import ConnectionError, ConnectTimeout, ReadTimeout
from cme.logger import CMEAdapter
from cme.connection import *

class http(connection):

    def __init__(self, args, db, host):
        self.page_title = None

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        http_parser = parser.add_parser('http', help="own stuff using HTTP(S)", parents=[std_parser])
        http_parser.add_argument('--ports', nargs='*', default=[80, 443, 8443, 8080, 8008, 8081], help='HTTP(S) ports')
        http_parser.add_argument('--transports', nargs='+', choices=['http', 'https'], default=['http', 'https'], help='force connection')

        return parser

    def proto_flow(self):
        for transport in self.args.transports:
            for port in self.args.ports:
                self.enum_host_info(transport, port)
                self.proto_logger(port)
                self.print_host_info()
                #if self.login():
                    #elif self.module is None and self.chain_list is None:
        self.call_cmd_args()

    def proto_logger(self, port):
        self.logger = CMEAdapter(extra={'protocol': 'HTTP',
                                        'host': gethostbyname(self.host),
                                        'port': port,
                                        'hostname': None})

    def enum_host_info(self, transport, port):
        try:
            self.conn = requests.get('{}://{}:{}/'.format(transport, self.host, port), timeout=10)
            html = bs4.BeautifulSoup(self.conn.text, "html.parser")
            self.page_title = html.title.text
        except ConnectTimeout, ReadTimeout:
            pass
        except Exception as e:
            if str(e).find('Read timed out') == -1:
                logging.debug('Error connecting to {}://{}:{} :{}'.format(transport, self.host, port, e))

    def print_host_info(self):
        self.logger.info("Title: '{}'".format(self.page_title.strip()))
