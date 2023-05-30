#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import os
from datetime import datetime

from aardwolf.commons.target import RDPTarget

from cme.connection import *
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
from aardwolf.vncconnection import VNCConnection
from aardwolf.commons.iosettings import RDPIOSettings
from aardwolf.commons.queuedata.constants import VIDEO_FORMAT
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthSecret, asyauthProtocol


class vnc(connection):
    def __init__(self, args, db, host):
        self.iosettings = RDPIOSettings()
        self.iosettings.channels = []
        self.iosettings.video_out_format = VIDEO_FORMAT.RAW
        self.iosettings.clipboard_use_pyperclip = False
        self.url = None
        self.target = None
        self.credential = None
        connection.__init__(self, args, db, host)

    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            self.print_host_info()
            if self.login():
                if hasattr(self.args, "module") and self.args.module:
                    self.call_modules()
                else:
                    self.call_cmd_args()

    def proto_logger(self):
        self.logger = CMEAdapter(
            extra={
                "protocol": "VNC",
                "host": self.host,
                "port": self.args.port,
                "hostname": self.hostname,
            }
        )

    def print_host_info(self):
        self.logger.display(f"VNC connecting to {self.hostname}")

    def create_conn_obj(self):
        try:
            self.target = RDPTarget(ip=self.host, port=self.args.port)
            credential = UniCredential(protocol=asyauthProtocol.PLAIN, stype=asyauthSecret.NONE)
            self.conn = VNCConnection(target=self.target, credentials=credential, iosettings=self.iosettings)
            asyncio.run(self.connect_vnc(True))
        except Exception as e:
            self.logger.debug(str(e))
            if "Server supports:" not in str(e):
                return False
        return True

    async def connect_vnc(self, discover=False):
        _, err = await self.conn.connect()
        if err is not None:
            if not discover:
                await asyncio.sleep(self.args.vnc_sleep)
            raise err
        return True

    def plaintext_login(self, username, password):
        try:
            stype = asyauthSecret.PASS
            if password == "":
                stype = asyauthSecret.NONE
            self.credential = UniCredential(secret=password, protocol=asyauthProtocol.PLAIN, stype=stype)
            self.conn = VNCConnection(
                target=self.target,
                credentials=self.credential,
                iosettings=self.iosettings,
            )
            asyncio.run(self.connect_vnc())

            self.admin_privs = True
            self.logger.success(
                "{} {}".format(
                    password,
                    highlight(f"({self.config.get('CME', 'pwn3d_label')})" if self.admin_privs else ""),
                )
            )
            return True

        except Exception as e:
            self.logger.debug(str(e))
            if "Server supports: 1" in str(e):
                self.logger.success(
                    "{} {}".format(
                        "No password seems to be accepted by the server",
                        highlight(f"({self.config.get('CME', 'pwn3d_label')})" if self.admin_privs else ""),
                    )
                )
            else:
                self.logger.fail(f"{password} {'Authentication failed'}")
            return False

    async def screen(self):
        self.conn = VNCConnection(target=self.target, credentials=self.credential, iosettings=self.iosettings)
        await self.connect_vnc()
        await asyncio.sleep(int(self.args.screentime))
        if self.conn is not None and self.conn.desktop_buffer_has_data is True:
            buffer = self.conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
            filename = os.path.expanduser(f"~/.cme/screenshots/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.png")
            buffer.save(filename, "png")
            self.logger.highlight(f"Screenshot saved {filename}")

    def screenshot(self):
        asyncio.run(self.screen())
