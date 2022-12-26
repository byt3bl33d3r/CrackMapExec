#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# If you are looking for a local Version, the baseline code is from https://github.com/NeffIsBack/WinSCPPasswdExtractor

class CMEModule:
    '''
        Example
        Module by @NeffIsBack

    '''
    name = 'winscp_dump'
    description = 'The module looks for WinSCP.ini files in the registry 
        and default locations and tries to extract credentials.'
    supported_protocols = ['smb']
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        SEARCH_PATH     Specify the search Path if you already found a WinSCP.ini file or you want to change the default Paths (you must add single quotes around the paths if they include spaces)
                        Default: 'C:\\Users\\{u}\\AppData\\Roaming\\WinSCP.ini',
                        'C:\\Users\\{u}\\Documents\\WinSCP.ini'
        """
        pass

    def on_login(self, context, connection):
        '''Concurrent. Required if on_admin_login is not present. This gets called on each authenticated connection'''
        pass

    def on_admin_login(self, context, connection):
        '''Concurrent. Required if on_login is not present. This gets called on each authenticated connection with Administrative privileges'''
        pass

    def on_request(self, context, request):
        '''Optional. If the payload needs to retrieve additonal files, add this function to the module'''
        pass

    def on_response(self, context, response):
        '''Optional. If the payload sends back its output to our server, add this function to the module to handle its output'''
        pass

    def on_shutdown(self, context, connection):
        '''Optional. Do something on shutdown'''
        pass
