#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import sys
from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable


class CMEModule:
    name = "bh_owned"
    description = "Set pwned computer as owned in Bloodhound"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.neo4j_pass = None
        self.neo4j_user = None
        self.neo4j_Port = None
        self.neo4j_URI = None

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

        if module_options and "URI" in module_options:
            self.neo4j_URI = module_options["URI"]
        if module_options and "PORT" in module_options:
            self.neo4j_Port = module_options["PORT"]
        if module_options and "USER" in module_options:
            self.neo4j_user = module_options["USER"]
        if module_options and "PASS" in module_options:
            self.neo4j_pass = module_options["PASS"]

    def on_admin_login(self, context, connection):
        if context.local_auth:
            domain = connection.conn.getServerDNSDomainName()
        else:
            domain = connection.domain

        host_fqdn = f"{connection.hostname}.{domain}".upper()
        uri = f"bolt://{self.neo4j_URI}:{self.neo4j_Port}"
        context.log.debug(f"Neo4j URI: {uri}")
        context.log.debug(f"User: {self.neo4j_user}, Password: {self.neo4j_pass}")

        try:
            driver = GraphDatabase.driver(uri, auth=(self.neo4j_user, self.neo4j_pass), encrypted=False)
        except AuthError:
            context.log.fail(f"Provided Neo4J credentials ({self.neo4j_user}:{self.neo4j_pass}) are" " not valid. See --options")
            sys.exit()
        except ServiceUnavailable:
            context.log.fail(f"Neo4J does not seem to be available on {uri}. See --options")
            sys.exit()
        except Exception as e:
            context.log.fail("Unexpected error with Neo4J")
            context.log.debug(f"Error {e}: ")
            sys.exit()

        with driver.session() as session:
            with session.begin_transaction() as tx:
                result = tx.run(f'MATCH (c:Computer {{name:"{host_fqdn}"}}) SET c.owned=True RETURN' " c.name AS name")
                record = result.single()
                try:
                    value = record.value()
                except AttributeError:
                    value = []
        if len(value) > 0:
            context.log.success(f"Node {host_fqdn} successfully set as owned in BloodHound")
        else:
            context.log.fail(f"Node {host_fqdn} does not appear to be in Neo4J database. Have you" " imported the correct data?")
        driver.close()
