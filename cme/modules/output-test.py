#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class CMEModule:
    name = "test"
    description = "I do something"
    supported_protocols = ["smb"]
    opsec_safe = True  # Does the module touch disk?
    multiple_hosts = True  # Does it make sense to run this module on multiple hosts at a time?

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """Required.
        Module options get parsed here. Additionally, put the modules usage here as well
        """
        pass

    def on_admin_login(self, context, connection):
        """Concurrent.
        Required if on_login is not present
        This gets called on each authenticated connection with  Administrative privileges
        """
        context.log.info("info")
        context.log.display("display")
        context.log.success("success")
        context.log.highlight("highlight")
        context.log.fail("error test")
        context.log.fail("fail test")
        context.log.debug("debug")
