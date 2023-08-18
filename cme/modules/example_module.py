#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class CMEModule:
    """
    Example
    Module by @yomama
    """

    name = "example module"
    description = "I do something"
    supported_protocols = [] # Example: ['smb', 'mssql']
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

    def on_login(self, context, connection):
        """Concurrent.
        Required if on_admin_login is not present. This gets called on each authenticated connection
        """
        # Logging best practice
        # Mostly you should use these functions to display information to the user
        context.log.display("I'm doing something")     # Use this for every normal message ([*] I'm doing something)
        context.log.success("I'm doing something")     # Use this for when something succeeds ([+] I'm doing something)
        context.log.fail("I'm doing something")        # Use this for when something fails ([-] I'm doing something), for example a remote registry entry is missing which is needed to proceed
        context.log.highlight("I'm doing something")   # Use this for when something is important and should be highlighted, printing credentials for example

        # These are for debugging purposes
        context.log.info("I'm doing something")        # This will only be displayed if the user has specified the --verbose flag, so add additional info that might be useful
        context.log.debug("I'm doing something")       # This will only be displayed if the user has specified the --debug flag, so add info that you would might need for debugging errors

        # These are for more critical error handling
        context.log.error("I'm doing something")       # This will not be printed in the module context and should only be used for critical errors (e.g. a required python file is missing)
        try:
            raise Exception("Exception that might occure")
        except Exception as e:
            context.log.exception(f"Exception occured: {e}")   # This will display an exception traceback screen after an exception was raised and should only be used for critical errors

    def on_admin_login(self, context, connection):
        """Concurrent.
        Required if on_login is not present
        This gets called on each authenticated connection with  Administrative privileges
        """
        pass

    def on_request(self, context, request):
        """Optional.
        If the payload needs to retrieve additional files, add this function to the module
        """
        pass

    def on_response(self, context, response):
        """Optional.
        If the payload sends back its output to our server, add this function to the module to handle its output
        """
        pass

    def on_shutdown(self, context, connection):
        """Optional.
        Do something on shutdown
        """
        pass
