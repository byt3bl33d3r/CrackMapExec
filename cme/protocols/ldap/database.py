#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy import MetaData, Table
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IllegalStateChangeError, NoInspectionAvailable, NoSuchTableError
import asyncio


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
        # this is still named "conn" when it is the session object; TODO: rename
        self.conn = Session()

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute('''CREATE TABLE "credentials" (
            "id" integer PRIMARY KEY,
            "username" text,
            "password" text
            )''')

        db_conn.execute('''CREATE TABLE "hosts" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "hostname" text,
            "port" integer
            )''')

    def reflect_tables(self):
        with self.db_engine.connect() as conn:
            try:
                self.CredentialsTable = Table("credentials", self.metadata, autoload_with=self.db_engine)
                self.HostsTable = Table("hosts", self.metadata, autoload_with=self.db_engine)
            except (NoInspectionAvailable, NoSuchTableError):
                print(
                    "[-] Error reflecting tables - this means there is a DB schema mismatch \n"
                    "[-] This is probably because a newer version of CME is being ran on an old DB schema\n"
                    "[-] If you wish to save the old DB data, copy it to a new location (`cp -r ~/.cme/workspaces/ ~/old_cme_workspaces/`)\n"
                    "[-] Then remove the CME DB folders (`rm -rf ~/.cme/workspaces/`) and rerun CME to initialize the new DB schema"
                )
                exit()

    def shutdown_db(self):
        try:
            self.conn.close()
        # due to the async nature of CME, sometimes session state is a bit messy and this will throw:
        # Method 'close()' can't be called here; method '_connection_for_bind()' is already in progress and
        # this would cause an unexpected state change to <SessionTransactionState.CLOSED: 5>
        except IllegalStateChangeError as e:
            logging.debug(f"Error while closing session db object: {e}")

    def clear_database(self):
        for table in self.metadata.sorted_tables:
            self.conn.execute(table.delete())
