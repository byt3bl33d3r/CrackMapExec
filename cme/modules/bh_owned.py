# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import json
import sys


class CMEModule:
    name = 'bh_owned'
    description = "Set pwned computer as owned in Bloodhound"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
            URI            URI for Neo4j database (default: 127.0.0.1)
            PORT           Listening port for Neo4j database (default: 7687)
            USER           Username for Neo4j database (default: 'neo4j')
            PASS           Password for Neo4j database (default: 'neo4j')
        """
        
        self.neo4j_URI = "127.0.0.1"
        self.neo4j_Port = "7687"
        self.neo4j_user = "neo4j"
        self.neo4j_pass = "neo4j"

        if module_options and 'URI' in module_options:
            self.neo4j_URI = module_options['URI']
        if module_options and 'PORT' in module_options:
            self.neo4j_Port = module_options['PORT']
        if module_options and 'USER' in module_options:
            self.neo4j_user = module_options['USER']
        if module_options and 'PASS' in module_options:
            self.neo4j_pass = module_options['PASS']

    def on_admin_login(self, context, connection):
        try:
            from neo4j.v1 import GraphDatabase
        except:
            from neo4j import GraphDatabase

        from neo4j.exceptions import AuthError, ServiceUnavailable
        
        if context.local_auth:
            domain    = connection.conn.getServerDNSDomainName()
        else:
            domain = connection.domain


        host_fqdn = (connection.hostname + "." + domain).upper()
        uri = "bolt://{}:{}".format(self.neo4j_URI, self.neo4j_Port)

        try:
            driver = GraphDatabase.driver(uri, auth=(self.neo4j_user, self.neo4j_pass), encrypted=False)
        except AuthError as e:
            context.log.error(
                "Provided Neo4J credentials ({}:{}) are not valid. See --options".format(self.neo4j_user, self.neo4j_pass))
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
                "Node {} does not appear to be in Neo4J database. Have you imported correct data?".format(host_fqdn))
        driver.close()