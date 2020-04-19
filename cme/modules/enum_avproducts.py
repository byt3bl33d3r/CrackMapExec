class CMEModule:
    '''
        Uses WMI to gather information on all endpoint protection solutions installed on the the remote host(s)
        Module by @byt3bl33d3r

    '''

    name = 'enum_avproducts'
    description = 'Gathers information on all endpoint protection solutions installed on the the remote host(s) via WMI'
    supported_protocols = ['smb']
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_admin_login(self, context, connection):
        output = connection.wmi('Select * From AntiSpywareProduct', 'root\\SecurityCenter2')
        if output:
            context.log.success('Found Anti-Spyware product:')
            for entry in output:
                for k,v in entry.items():
                    context.log.highlight('{} => {}'.format(k,v['value']))

        output = connection.wmi('Select * from AntiVirusProduct', 'root\\SecurityCenter2')
        if output:
            context.log.success('Found Anti-Virus product:')
            for entry in output:
                for k,v in entry.items():
                    context.log.highlight('{} => {}'.format(k,v['value']))