class CMEModule():
    '''
    TO DO
    
    Idea stolen from Veil-Catapult/Veil-Pillage (https://github.com/Veil-Framework)

    Uploads a barebones python environment to a host and uses it to execute shellcode.
    This is awesome for hosts where Powershell is not installed, additionally all binaries that are uploaded are signed so AV solutions will not flag on them.

    However it does touch disk.
    '''

    name = 'python_injector'
    description = 'Uploads a barebones python environment and uses it to execute shellcode'
    supported_protocols = ['smb']
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        PATH   Path to the raw shellcode to inject
        '''

    def on_admin_login(self, context, connection):
        pass
