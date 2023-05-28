#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy import MetaData, Table
from sqlalchemy.exc import (
    IllegalStateChangeError,
    NoInspectionAvailable,
    NoSuchTableError,
)
from cme.logger import cme_logger


class database:
    def __init__(self, db_engine):
        self.CredentialsTable = None
        self.HostsTable = None
        self.LoggedinRelationsTable = None

        self.db_engine = db_engine
        self.db_path = self.db_engine.url.database
        self.protocol = Path(self.db_path).stem.upper()
        self.metadata = MetaData()
        self.reflect_tables()

        session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=True)
        Session = scoped_session(session_factory)
        self.sess = Session()

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute("""CREATE TABLE "credentials" (
            "id" integer PRIMARY KEY,
            "username" text,
            "password" text
            )""")

        db_conn.execute("""CREATE TABLE "hosts" (
            "id" integer PRIMARY KEY,
            "host" text,
            "port" integer,
            "banner" text
            )""")
        db_conn.execute("""CREATE TABLE "loggedin_relations" (
            "id" integer PRIMARY KEY,
            "credid" integer,
            "hostid" integer,
            FOREIGN KEY(credid) REFERENCES credentials(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
        )""")
        db_conn.execute("""CREATE TABLE "directory_listings" (
            "id" integer PRIMARY KEY,
            "lir_id" integer,
            "data" text,
            FOREIGN KEY(lir_id) REFERENCES loggedin_relations(id)
        )""")

    def reflect_tables(self):
        with self.db_engine.connect():
            try:
                self.CredentialsTable = Table(
                    "credentials", self.metadata, autoload_with=self.db_engine
                )
                self.HostsTable = Table(
                    "hosts", self.metadata, autoload_with=self.db_engine
                )
                self.LoggedinRelationsTable = Table(
                    "loggedin_relations", self.metadata, autoload_with=self.db_engine
                )
                self.LoggedinRelationsTable = Table(
                    "directory_listings", self.metadata, autoload_with=self.db_engine
                )
            except (NoInspectionAvailable, NoSuchTableError):
                print(
                    f"""
                    [-] Error reflecting tables for the {self.protocol} protocol - this means there is a DB schema mismatch
                    [-] This is probably because a newer version of CME is being ran on an old DB schema
                    [-] Optionally save the old DB data (`cp {self.db_path} ~/cme_{self.protocol.lower()}.bak`)
                    [-] Then remove the {self.protocol} DB (`rm -f {self.db_path}`) and run CME to initialize the new DB"""
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

    def add_host(self, host, port, banner):
        pass

    def add_credential(self, username, password):
        pass

    def remove_credential(self):
        pass

    def is_credential_valid(self):
        pass

    def get_credentials(self):
        pass

    def get_credentials(self):
        pass

    def is_host_valid(self):
        pass

    def get_host(self):
        pass

    def is_user_valid(self):
        pass

    def get_user(self):
        pass

    def get_users(self):
        pass

    def add_loggedin_relation(self, credid, hostid):
        pass

    def get_loggedin_relations(self):
        pass

    def remove_loggedin_relations(self):
        pass

    def add_directory_listing(self, lir_id, data):
        pass

    def get_directory_listing(self):
        pass

    def remove_directory_listing(self):
        pass


