#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import os
from datetime import datetime
from os import getenv
from termcolor import colored

from impacket.krb5.ccache import CCache

from cme.connection import *
from cme.helpers.bloodhound import add_user_bh
from cme.logger import CMEAdapter
from cme.config import host_info_colors
from cme.config import process_secret

from aardwolf.connection import RDPConnection
from aardwolf.commons.queuedata.constants import VIDEO_FORMAT
from aardwolf.commons.iosettings import RDPIOSettings
from aardwolf.commons.target import RDPTarget
from aardwolf.protocol.x224.constants import SUPP_PROTOCOLS
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.common.constants import asyauthSecret
from asysocks.unicomm.common.target import UniTarget, UniProto

class rdp(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.iosettings = RDPIOSettings()
        self.iosettings.channels = []
        self.iosettings.video_out_format = VIDEO_FORMAT.RAW
        self.iosettings.clipboard_use_pyperclip = False
        self.protoflags_nla = [
            SUPP_PROTOCOLS.SSL | SUPP_PROTOCOLS.RDP,
            SUPP_PROTOCOLS.SSL,
            SUPP_PROTOCOLS.RDP,
        ]
        self.protoflags = [
            SUPP_PROTOCOLS.SSL | SUPP_PROTOCOLS.RDP,
            SUPP_PROTOCOLS.SSL,
            SUPP_PROTOCOLS.RDP,
            SUPP_PROTOCOLS.SSL | SUPP_PROTOCOLS.HYBRID,
            SUPP_PROTOCOLS.SSL | SUPP_PROTOCOLS.HYBRID_EX,
        ]
        width, height = args.res.upper().split("X")
        height = int(height)
        width = int(width)
        self.iosettings.video_width = width
        self.iosettings.video_height = height
        # servers dont support 8 any more :/
        self.iosettings.video_bpp_min = 15
        self.iosettings.video_bpp_max = 32
        # PIL produces incorrect picture for some reason?! TODO: check bug
        self.iosettings.video_out_format = VIDEO_FORMAT.PNG  #
        self.output_filename = None
        self.domain = None
        self.server_os = None
        self.url = None
        self.nla = True
        self.hybrid = False
        self.target = None
        self.auth = None

        self.rdp_error_status = {
            "0xc0000071": "STATUS_PASSWORD_EXPIRED",
            "0xc0000234": "STATUS_ACCOUNT_LOCKED_OUT",
            "0xc0000072": "STATUS_ACCOUNT_DISABLED",
            "0xc0000193": "STATUS_ACCOUNT_EXPIRED",
            "0xc000006E": "STATUS_ACCOUNT_RESTRICTION",
            "0xc000006F": "STATUS_INVALID_LOGON_HOURS",
            "0xc0000070": "STATUS_INVALID_WORKSTATION",
            "0xc000015B": "STATUS_LOGON_TYPE_NOT_GRANTED",
            "0xc0000224": "STATUS_PASSWORD_MUST_CHANGE",
            "0xc0000022": "STATUS_ACCESS_DENIED",
            "0xc000006d": "STATUS_LOGON_FAILURE",
            "0xc000006a": "STATUS_WRONG_PASSWORD ",
            "KDC_ERR_CLIENT_REVOKED": "KDC_ERR_CLIENT_REVOKED",
            "KDC_ERR_PREAUTH_FAILED": "KDC_ERR_PREAUTH_FAILED",
        }

        connection.__init__(self, args, db, host)

    # def proto_flow(self):
    #     if self.create_conn_obj():
    #         self.proto_logger()
    #         self.print_host_info()
    #         if self.login() or (self.username == '' and self.password == ''):
    #             if hasattr(self.args, 'module') and self.args.module:
    #                 self.call_modules()
    #             else:
    #                 self.call_cmd_args()

    def proto_logger(self):
        self.logger = CMEAdapter(
            extra={
                "protocol": "RDP",
                "host": self.host,
                "port": self.args.port,
                "hostname": self.hostname,
            }
        )

    def print_host_info(self):
        nla = colored(f"nla:{self.nla}", host_info_colors[3], attrs=['bold']) if self.nla else colored(f"nla:{self.nla}", host_info_colors[2], attrs=['bold'])
        if self.domain is None:
            self.logger.display("Probably old, doesn't not support HYBRID or HYBRID_EX" f" ({nla})")
        else:
            self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.domain})" f" ({nla})")
        return True

    def create_conn_obj(self):
        self.target = RDPTarget(ip=self.host, domain="FAKE", port=self.args.port, timeout=self.args.rdp_timeout)
        self.auth = NTLMCredential(secret="pass", username="user", domain="FAKE", stype=asyauthSecret.PASS)

        self.check_nla()

        for proto in reversed(self.protoflags):
            try:
                self.iosettings.supported_protocols = proto
                self.conn = RDPConnection(
                    iosettings=self.iosettings,
                    target=self.target,
                    credentials=self.auth,
                )
                asyncio.run(self.connect_rdp())
            except OSError as e:
                if "Errno 104" not in str(e):
                    return False
            except Exception as e:
                if "TCPSocket" in str(e):
                    return False
                if "Reason:" not in str(e):
                    try:
                        info_domain = self.conn.get_extra_info()
                    except:
                        pass
                    else:
                        self.domain = info_domain["dnsdomainname"]
                        self.hostname = info_domain["computername"]
                        self.server_os = info_domain["os_guess"] + " Build " + str(info_domain["os_build"])
                        self.logger.extra["hostname"] = self.hostname
                        self.output_filename = os.path.expanduser(f"~/.cme/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))
                    break

        if self.args.domain:
            self.domain = self.args.domain

        if self.args.local_auth:
            self.domain = self.hostname

        self.target = RDPTarget(
            ip=self.host,
            hostname=self.hostname,
            port=self.args.port,
            domain=self.domain,
            dc_ip=self.domain,
            timeout=self.args.rdp_timeout,
        )

        return True

    def check_nla(self):
        for proto in self.protoflags_nla:
            try:
                self.iosettings.supported_protocols = proto
                self.conn = RDPConnection(
                    iosettings=self.iosettings,
                    target=self.target,
                    credentials=self.auth,
                )
                asyncio.run(self.connect_rdp())
                if str(proto) == "SUPP_PROTOCOLS.RDP" or str(proto) == "SUPP_PROTOCOLS.SSL" or str(proto) == "SUPP_PROTOCOLS.SSL|SUPP_PROTOCOLS.RDP":
                    self.nla = False
                    return
            except Exception as e:
                pass

    async def connect_rdp(self):
        _, err = await asyncio.wait_for(self.conn.connect(), timeout=self.args.rdp_timeout)
        if err is not None:
            raise err

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        try:
            lmhash = ""
            nthash = ""
            # This checks to see if we didn't provide the LM Hash
            if ntlm_hash.find(":") != -1:
                lmhash, nthash = ntlm_hash.split(":")
                self.hash = nthash
            else:
                nthash = ntlm_hash
                self.hash = ntlm_hash
            if lmhash:
                self.lmhash = lmhash
            if nthash:
                self.nthash = nthash

            if not all("" == s for s in [nthash, password, aesKey]):
                kerb_pass = next(s for s in [nthash, password, aesKey] if s)
            else:
                kerb_pass = ""

            fqdn_host = self.hostname + "." + self.domain
            password = password if password else nthash

            if useCache:
                stype = asyauthSecret.CCACHE
                if not password:
                    password = getenv("KRB5CCNAME") if not password else password
                    if "/" in password:
                        self.logger.fail("Kerberos ticket need to be on the local directory")
                        return False
                    ccache = CCache.loadFile(getenv("KRB5CCNAME"))
                    ticketCreds = ccache.credentials[0]
                    username = ticketCreds["client"].prettyPrint().decode().split("@")[0]
            else:
                stype = asyauthSecret.PASS if not nthash else asyauthSecret.NT

            kerberos_target = UniTarget(
                self.domain,
                88,
                UniProto.CLIENT_TCP,
                proxies=None,
                dns=None,
                dc_ip=self.domain,
                domain=self.domain
            )
            self.auth = KerberosCredential(
                target=kerberos_target,
                secret=password,
                username=username,
                domain=domain,
                stype=stype,
            )
            self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)
            asyncio.run(self.connect_rdp())

            self.admin_privs = True
            self.logger.success(
                "{}\\{}{} {}".format(
                    domain,
                    username,
                    (
                        # Show what was used between cleartext, nthash, aesKey and ccache
                        " from ccache"
                        if useCache
                        else ":%s" % (process_secret(kerb_pass))
                    ),
                    self.mark_pwned(),
                )
            )
            if not self.args.local_auth:
                add_user_bh(username, domain, self.logger, self.config)
            return True

        except Exception as e:
            if "KDC_ERR" in str(e):
                reason = None
                for word in self.rdp_error_status.keys():
                    if word in str(e):
                        reason = self.rdp_error_status[word]
                self.logger.fail(
                    (f"{domain}\\{username}{' from ccache' if useCache else ':%s' % (process_secret(kerb_pass))} {f'({reason})' if reason else str(e)}"),
                    color=("magenta" if ((reason or "CredSSP" in str(e)) and reason != "KDC_ERR_C_PRINCIPAL_UNKNOWN") else "red"),
                )
            elif "Authentication failed!" in str(e):
                self.logger.success(f"{domain}\\{username}:{(process_secret(password))} {self.mark_pwned()}")
            elif "No such file" in str(e):
                self.logger.fail(e)
            else:
                reason = None
                for word in self.rdp_error_status.keys():
                    if word in str(e):
                        reason = self.rdp_error_status[word]
                if "cannot unpack non-iterable NoneType object" == str(e):
                    reason = "User valid but cannot connect"
                self.logger.fail(
                    (f"{domain}\\{username}{' from ccache' if useCache else ':%s' % (process_secret(kerb_pass))} {f'({reason})' if reason else ''}"),
                    color=("magenta" if ((reason or "CredSSP" in str(e)) and reason != "STATUS_LOGON_FAILURE") else "red"),
                )
            return False

    def plaintext_login(self, domain, username, password):
        try:
            self.auth = NTLMCredential(
                secret=password,
                username=username,
                domain=domain,
                stype=asyauthSecret.PASS,
            )
            self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)
            asyncio.run(self.connect_rdp())

            self.admin_privs = True
            self.logger.success(f"{domain}\\{username}:{process_secret(password)} {self.mark_pwned()}")
            if not self.args.local_auth:
                add_user_bh(username, domain, self.logger, self.config)
            return True
        except Exception as e:
            if "Authentication failed!" in str(e):
                self.logger.success(f"{domain}\\{username}:{process_secret(password)} {self.mark_pwned()}")
            else:
                reason = None
                for word in self.rdp_error_status.keys():
                    if word in str(e):
                        reason = self.rdp_error_status[word]
                if "cannot unpack non-iterable NoneType object" == str(e):
                    reason = "User valid but cannot connect"
                self.logger.fail(
                    (f"{domain}\\{username}:{process_secret(password)} {f'({reason})' if reason else ''}"),
                    color=("magenta" if ((reason or "CredSSP" in str(e)) and reason != "STATUS_LOGON_FAILURE") else "red"),
                )
            return False

    def hash_login(self, domain, username, ntlm_hash):
        try:
            self.auth = NTLMCredential(
                secret=ntlm_hash,
                username=username,
                domain=domain,
                stype=asyauthSecret.NT,
            )
            self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)
            asyncio.run(self.connect_rdp())

            self.admin_privs = True
            self.logger.success(f"{self.domain}\\{username}:{process_secret(ntlm_hash)} {self.mark_pwned()}")
            if not self.args.local_auth:
                add_user_bh(username, domain, self.logger, self.config)
            return True
        except Exception as e:
            if "Authentication failed!" in str(e):
                self.logger.success(f"{domain}\\{username}:{process_secret(ntlm_hash)} {self.mark_pwned()}")
            else:
                reason = None
                for word in self.rdp_error_status.keys():
                    if word in str(e):
                        reason = self.rdp_error_status[word]
                if "cannot unpack non-iterable NoneType object" == str(e):
                    reason = "User valid but cannot connect"

                self.logger.fail(
                    (f"{domain}\\{username}:{process_secret(ntlm_hash)} {f'({reason})' if reason else ''}"),
                    color=("magenta" if ((reason or "CredSSP" in str(e)) and reason != "STATUS_LOGON_FAILURE") else "red"),
                )
            return False

    async def screen(self):
        try:
            self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)
            await self.connect_rdp()
        except Exception as e:
            return

        await asyncio.sleep(int(5))
        if self.conn is not None and self.conn.desktop_buffer_has_data is True:
            buffer = self.conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
            filename = os.path.expanduser(f"~/.cme/screenshots/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.png")
            buffer.save(filename, "png")
            self.logger.highlight(f"Screenshot saved {filename}")

    def screenshot(self):
        asyncio.run(self.screen())

    async def nla_screen(self):
        # Otherwise it crash
        self.iosettings.supported_protocols = None
        self.auth = NTLMCredential(secret="", username="", domain="", stype=asyauthSecret.PASS)
        self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)
        await self.connect_rdp()
        await asyncio.sleep(int(self.args.screentime))

        if self.conn is not None and self.conn.desktop_buffer_has_data is True:
            buffer = self.conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
            filename = os.path.expanduser(f"~/.cme/screenshots/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.png")
            buffer.save(filename, "png")
            self.logger.highlight(f"NLA Screenshot saved {filename}")

    def nla_screenshot(self):
        if not self.nla:
            asyncio.run(self.nla_screen())
