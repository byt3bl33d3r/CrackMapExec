import os, struct

from six import indexbytes
from datetime import datetime
from cme.config import process_secret
from cme.connection import *
from cme.logger import CMEAdapter
from cme.protocols.wmi.wmiexec_regout import WMIEXEC_REGOUT

from impacket import ntlm
from impacket.uuid import uuidtup_to_bin
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, MSRPC_BIND, MSRPCBind, CtxItem, MSRPCHeader, SEC_TRAILER, MSRPCBindAck
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login, IID_IWbemLevel1Login, WBEM_FLAG_FORWARD_ONLY, IWbemLevel1Login

MSRPC_UUID_PORTMAP = uuidtup_to_bin(('E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0'))

class wmi(connection):

    def __init__(self, args, db, host):
        self.domain = None
        self.hash = ''
        self.lmhash = ''
        self.nthash = ''
        self.server_os = None

        connection.__init__(self, args, db, host)
    
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
        self.logger = CMEAdapter(extra={'protocol': 'WMI',
                                        'host': self.host,
                                        'port': self.args.port,
                                        'hostname': self.hostname})
    
    def create_conn_obj(self):
        try:
            rpctansport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:{0}[{1}]'.format(self.host, str(self.args.port)))
            rpctansport.set_credentials(username="", password="", domain="", lmhash="", nthash="")
            rpctansport.set_connect_timeout(int(self.args.rpc_timeout))
            dce = rpctansport.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.connect()
            dce.bind(MSRPC_UUID_PORTMAP)
            dce.disconnect()
        except Exception as e:
            return False
        else:
            self.conn = rpctansport
            return True
    
    def enum_host_info(self):
        # All code pick from DumpNTLNInfo.py
        ntlmChallenge = None
        
        bind = MSRPCBind()
        item = CtxItem()
        item['AbstractSyntax'] = epm.MSRPC_UUID_PORTMAP
        item['TransferSyntax'] = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))
        item['ContextID'] = 0
        item['TransItems'] = 1
        bind.addCtxItem(item)

        packet = MSRPCHeader()
        packet['type'] = MSRPC_BIND
        packet['pduData'] = bind.getData()
        packet['call_id'] = 1

        auth = ntlm.getNTLMSSPType1('', '', signingRequired=True, use_ntlmv2=True)
        sec_trailer = SEC_TRAILER()
        sec_trailer['auth_type']   = RPC_C_AUTHN_WINNT
        sec_trailer['auth_level']  = RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
        sec_trailer['auth_ctx_id'] = 0 + 79231 
        pad = (4 - (len(packet.get_packet()) % 4)) % 4
        if pad != 0:
            packet['pduData'] += b'\xFF'*pad
            sec_trailer['auth_pad_len']=pad
        packet['sec_trailer'] = sec_trailer
        packet['auth_data'] = auth

        self.conn.connect()
        self.conn.send(packet.get_packet())
        buffer = self.conn.recv()

        if buffer != 0:
            response = MSRPCHeader(buffer)
            bindResp = MSRPCBindAck(response.getData())

            ntlmChallenge = ntlm.NTLMAuthChallenge(bindResp['auth_data'])

            if ntlmChallenge['TargetInfoFields_len'] > 0:
                av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']])
                if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1] is not None:
                    try:
                        self.hostname = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                    except:
                        self.hostname = self.host
                if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1] is not None:
                    try:
                        self.domain = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode('utf-16le')
                    except:
                        self.domain = self.args.domain
                if 'Version' in ntlmChallenge.fields:
                    version = ntlmChallenge['Version']
                    if len(version) >= 4:
                        self.server_os = "Windows NT %d.%d Build %d" % (indexbytes(version,0), indexbytes(version,1), struct.unpack('<H',version[2:4])[0])
        else:
            self.hostname = self.host
            if not self.doamin:
                self.domain = self.args.hostname
            if self.args.domain:
                self.domain = self.args.domain
        
        self.logger.extra["hostname"] = self.hostname

        self.output_filename = os.path.expanduser(f"~/.cme/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))

    def print_host_info(self):
        self.logger.extra['protocol'] = "RPC"
        self.logger.extra['port'] = "135"
        self.logger.display(u"{} (name:{}) (domain:{})".format(self.server_os,
                                                        self.hostname,
                                                        self.domain))
        return True

    def check_if_admin(self):
        try:
            dcom = DCOMConnection(self.conn.getRemoteHost(), self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True, kdcHost=self.kdcHost)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        except Exception as e:
            try:
                dcom.disconnect()
            except:
                pass

            if "access_denied" in str(e).lower():
                self.admin_privs = False
            else:
                pass
        else:
            dcom.disconnect()
            self.logger.extra['protocol'] = "WMI"
            self.admin_privs = True
        return

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        lmhash = ''
        nthash = ''
        self.password = password
        self.username = username
        self.domain = domain
        if password == "":
            if ntlm_hash.find(':') != -1:
                lmhash, nthash = ntlm_hash.split(':')
            else:
                nthash = ntlm_hash
        try:
            self.conn.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)
            self.conn.set_kerberos(True, kdcHost)
            dce = self.conn.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(MSRPC_UUID_PORTMAP)
        except Exception as e:
            dce.disconnect()
            self.logger.fail(f"Got error while RPC login: {str(e)}")
        else:
            try:
                # Get data from rpc connection if got vaild creds
                entry_handle = epm.ept_lookup_handle_t()
                request = epm.ept_lookup()
                request['inquiry_type'] = 0x0
                request['object'] = NULL
                request['Ifid'] = NULL
                request['vers_option'] = 0x1
                request['entry_handle'] = entry_handle
                request['max_ents'] = 1
                resp = dce.request(request)
            except  Exception as e:
                dce.disconnect()
                self.logger.fail((f"{self.domain}\\{self.username}:{process_secret(self.password)} ({str(e)})"), color=("red" if "access_denied" in str(e).lower() else "magenta"))
                return False
            else:
                self.check_if_admin()
                dce.disconnect()
                out = f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}"
                if self.username == "" and self.password == "":
                    out += "(Default allow anonymous login)"
                self.logger.success(out)
                return True

    def plaintext_login(self, domain, username, password):
        self.password = password
        self.username = username
        self.domain = domain
        try:
            self.conn.set_credentials(username=self.username, password=self.password, domain=self.domain, lmhash=self.lmhash, nthash=self.nthash)
            dce = self.conn.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(MSRPC_UUID_PORTMAP)
        except Exception as e:
            dce.disconnect()
            self.logger.fail(f"Got error while RPC login: {str(e)}")
        else:
            try:
                # Get data from rpc connection if got vaild creds
                entry_handle = epm.ept_lookup_handle_t()
                request = epm.ept_lookup()
                request['inquiry_type'] = 0x0
                request['object'] = NULL
                request['Ifid'] = NULL
                request['vers_option'] = 0x1
                request['entry_handle'] = entry_handle
                request['max_ents'] = 1
                resp = dce.request(request)
            except  Exception as e:
                dce.disconnect()
                self.logger.fail((f"{self.domain}\\{self.username}:{process_secret(self.password)} ({str(e)})"), color=("red" if "access_denied" in str(e).lower() else "magenta"))
                return False
            else:
                self.check_if_admin()
                dce.disconnect()
                out = f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}"
                if self.username == "" and self.password == "":
                    out += "(Default allow anonymous login)"
                self.logger.success(out)
                return True
    
    def hash_login(self, domain, username, ntlm_hash):
        self.username = username
        lmhash = ''
        nthash = ''
        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash
        try:
            self.conn.set_credentials(username=self.username, password=self.password, domain=self.domain, lmhash=lmhash, nthash=nthash)
            dce = self.conn.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(MSRPC_UUID_PORTMAP)
        except Exception as e:
            dce.disconnect()
            self.logger.fail(f"Got error while RPC login: {str(e)}")
        else:
            try:
                # Get data from rpc connection if got vaild creds
                entry_handle = epm.ept_lookup_handle_t()
                request = epm.ept_lookup()
                request['inquiry_type'] = 0x0
                request['object'] = NULL
                request['Ifid'] = NULL
                request['vers_option'] = 0x1
                request['entry_handle'] = entry_handle
                request['max_ents'] = 1
                resp = dce.request(request)
            except  Exception as e:
                dce.disconnect()
                self.logger.fail((f"{self.domain}\\{self.username}:{process_secret(nthash)} ({str(e)})"), color=("red" if "access_denied" in str(e).lower() else "magenta"))
                return False
            else:
                self.check_if_admin()
                dce.disconnect()
                out = f"{domain}\\{self.username}:{process_secret(nthash)} {self.mark_pwned()}"
                if self.username == "" and self.password == "":
                    out += "(Default allow anonymous login)"
                self.logger.success(out)
                return True

    # It's very complex to use wmi from rpctansport "convert" to dcom, so let we use dcom directly. 
    @requires_admin
    def wmi_query(self):
        WQL = self.args.wmi_query
        if not WQL:
            self.logger.fail("Missing WQL syntax in wmi query!")
            return False
        self.logger.success('Executing WQL: {}'.format(WQL))
        try:
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login,IID_IWbemLevel1Login)
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices= iWbemLevel1Login.NTLMLogin(self.args.namespace , NULL, NULL)
            iWbemLevel1Login.RemRelease()
            iEnumWbemClassObject = iWbemServices.ExecQuery(WQL.strip('\n'))
        except Exception as e:
            self.logger.fail('Execute WQL error: {}'.format(e))
            iWbemServices.RemRelease()
            dcom.disconnect()
        else:
            records = []
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
            iWbemServices.RemRelease()
            dcom.disconnect()
            return records

    @requires_admin
    def execute(self):
        command = self.args.execute
        if not command:
            self.logger.fail("Missing command in wmiexec!")
            return False
        try:
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
            win32Process, _ = iWbemServices.GetObject('Win32_Process')
            executor = WMIEXEC_REGOUT(win32Process, iWbemServices, self.host, self.logger, self.args.interval_time)
            executor.execute_remote(command)
            dcom.disconnect()
        except Exception as e:
            self.logger.fail('Execute command error: {}'.format(e))
            iWbemServices.RemRelease()
            dcom.disconnect()