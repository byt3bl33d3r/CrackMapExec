from datetime import datetime
from cme.helpers.logger import write_log

class CMEModule:
    '''
        Uses WMI to dump DNS from an AD DNS Server.
        Module by @fang0654

    '''

    name = 'enum_dns'
    description = 'Uses WMI to dump DNS from an AD DNS Server'
    supported_protocols = ['smb']
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        DOMAIN             Domain to enumerate DNS for. Defaults to all zones.
        '''
        self.domains = None
        if module_options and 'DOMAIN' in module_options:
            self.domains = module_options['DOMAIN']

    def on_admin_login(self, context, connection):

        if not self.domains:
            domains = []
            output = connection.wmi('Select Name FROM MicrosoftDNS_Zone', 'root\\microsoftdns')

            if output:
                for result in output:
                    domains.append(result['Name']['value'])

                context.log.success('Domains retrieved: {}'.format(domains))
        else:
            domains = [self.domains]
        data = ""
        for domain in domains:
            output = connection.wmi('Select TextRepresentation FROM MicrosoftDNS_ResourceRecord WHERE DomainName = "{}"'.format(domain), 'root\\microsoftdns')
            
            if output:
                domain_data = {}
                context.log.highlight("Results for {}".format(domain))
                data += "Results for {}\n".format(domain)
                for entry in output:
                    text = entry['TextRepresentation']['value']
                    rname = text.split(' ')[0]
                    rtype = text.split(' ')[2]
                    rvalue = ' '.join(text.split(' ')[3:])
                    if domain_data.get(rtype, False):
                        domain_data[rtype].append("{}: {}".format(rname, rvalue))
                    else:
                        domain_data[rtype] = ["{}: {}".format(rname, rvalue)]

                for k, v in sorted(domain_data.items()):
                    context.log.highlight("Record Type: {}".format(k))
                    data += "Record Type: {}\n".format(k)
                    for d in sorted(v):
                        context.log.highlight("\t"+d)
                        data += "\t" + d + "\n"

        log_name = 'DNS-Enum-{}-{}.log'.format(connection.args.target[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
        write_log(data, log_name)
        context.log.info("Saved raw output to {}".format(log_name))

