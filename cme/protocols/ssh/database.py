#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from sqlalchemy.dialects.sqlite import Insert
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy import MetaData, Table, select
from sqlalchemy.exc import IllegalStateChangeError, NoInspectionAvailable, NoSuchTableError

import os
import configparser

from cme.logger import cme_logger
from cme.paths import CME_PATH

# we can't import config.py due to a circular dependency, so we have to create redundant code unfortunately
cme_config = configparser.ConfigParser()
cme_config.read(os.path.join(CME_PATH, "cme.conf"))
cme_workspace = cme_config.get("CME", "workspace", fallback="default")


class database:
    def __init__(self, db_engine):
        self.CredentialsTable = None
        self.HostsTable = None

        self.db_engine = db_engine
        self.metadata = MetaData()
        self.reflect_tables()
        session_factory = sessionmaker(
            bind=self.db_engine,
            expire_on_commit=True
        )
        
        Session = scoped_session(session_factory)
        self.sess = Session()

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute(
            '''CREATE TABLE "credentials" (
            "id" integer PRIMARY KEY,
            "username" text,
            "password" text,
            "credtype" text
        )''')
        db_conn.execute(
            '''CREATE TABLE "hosts" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "hostname" text,
            "port" integer,
            "server_banner" text
        )''')
        db_conn.execute(
            '''CREATE TABLE "loggedin_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "hostid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
        )''')
        db_conn.execute(
            '''CREATE TABLE "admin_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "hostid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
        )''')
        db_conn.execute(
            '''CREATE TABLE "keys" (
            "id" integer PRIMARY KEY,
            "data" text,
            FOREIGN KEY(userid) REFERENCES users(id)
        )''')

    def reflect_tables(self):
        with self.db_engine.connect():
            try:
                self.CredentialsTable = Table("credentials", self.metadata, autoload_with=self.db_engine)
                self.HostsTable = Table("hosts", self.metadata, autoload_with=self.db_engine)
            except (NoInspectionAvailable, NoSuchTableError):
                ssh_workspace = f"~/.cme/workspaces/{cme_workspace}/ssh.db"
                print(
                    "[-] Error reflecting tables for SSH protocol - this means there is a DB schema mismatch \n"
                    "[-] This is probably because a newer version of CME is being ran on an old DB schema\n"
                    f"[-] Optionally save the old DB data (`cp {ssh_workspace} ~/cme_ssh.bak`)\n"
                    f"[-] Then remove the CME SSH DB (`rm -rf {ssh_workspace}`) and run CME to initialize the new DB"
                )
                exit()

    def shutdown_db(self):
        try:
            self.sess.close()
        # due to the async nature of CME, sometimes session state is a bit messy and this will throw:
        # Method 'close()' can't be called here; method '_connection_for_bind()' is already in progress and
        # this would cause an unexpected state change to <SessionTransactionState.CLOSED: 5>
        except IllegalStateChangeError as e:
            cme_logger.debug(f"Error while closing session db object: {e}")

    def clear_database(self):
        for table in self.metadata.sorted_tables:
            self.sess.execute(table.delete())

    def add_host(self, ip, hostname, port, os, banner):
        """
        Check if this host has already been added to the database, if not, add it in.
        """
        hosts = []
        updated_ids = []

        q = select(self.HostsTable).filter(
            self.HostsTable.c.ip == ip
        )
        results = self.conn.execute(q).all()

        # create new host
        if not results:
            new_host = {
                "ip": ip,
                "hostname": hostname if hostname is not None else '',
                "port": port,
                "os": os if os is not None else '',
                "banner": banner if banner is not None else ''
            }
            hosts = [new_host]
        # update existing hosts data
        else:
            for host in results:
                host_data = host._asdict()
                # only update column if it is being passed in
                if ip is not None:
                    host_data["ip"] = ip
                if hostname is not None:
                    host_data["hostname"] = hostname
                if port is not None:
                    host_data["port"] = port
                if os is not None:
                    host_data["os"] = os
                if banner is not None:
                    host_data["banner"] = banner
                # only add host to be updated if it has changed
                if host_data not in hosts:
                    hosts.append(host_data)
                    updated_ids.append(host_data["id"])
        cme_logger.debug(f"Update Hosts: {hosts}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.HostsTable)  # .returning(self.HostsTable.c.id)
        update_columns = {col.name: col for col in q.excluded if col.name not in 'id'}
        q = q.on_conflict_do_update(
            index_elements=self.HostsTable.primary_key,
            set_=update_columns
        )

        self.conn.execute(
            q,
            hosts
        )  # .scalar()
        # we only return updated IDs for now - when RETURNING clause is allowed we can return inserted
        if updated_ids:
            cme_logger.debug(f"add_host() - Host IDs Updated: {updated_ids}")
            return updated_ids
