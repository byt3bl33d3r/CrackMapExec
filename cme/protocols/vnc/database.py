#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
from sqlalchemy import MetaData, Table
from sqlalchemy.exc import IllegalStateChangeError
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SAWarning
import asyncio
import warnings


# if there is an issue with SQLAlchemy and a connection cannot be cleaned up properly it spews out annoying warnings
warnings.filterwarnings("ignore", category=SAWarning)


class database:

    def __init__(self, db_engine):
        self.HostsTable = None
        self.CredentialsTable = None

        self.db_engine = db_engine
        self.metadata = MetaData()
        asyncio.run(self.reflect_tables())
        # we don't use async_sessionmaker or async_scoped_session because when `database` is initialized,
        # there is no running async loop
        session_factory = sessionmaker(
            bind=self.db_engine,
            expire_on_commit=True,
            class_=AsyncSession
        )

        Session = scoped_session(session_factory)
        # this is still named "conn" when it is the session object; TODO: rename
        self.conn = Session()

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute('''CREATE TABLE "credentials" (
            "id" integer PRIMARY KEY,
            "username" text,
            "password" text,
            "pkey" text
            )''')

        db_conn.execute('''CREATE TABLE "hosts" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "hostname" text,
            "port" integer,
            "server_banner" text
            )''')

    async def reflect_tables(self):
        async with self.db_engine.connect() as conn:
            await conn.run_sync(self.metadata.reflect)

            self.HostsTable = Table("hosts", self.metadata, autoload_with=self.db_engine)
            self.CredentialsTable = Table("credentials", self.metadata, autoload_with=self.db_engine)

    async def shutdown_db(self):
        try:
            await asyncio.shield(self.conn.close())
        # due to the async nature of CME, sometimes session state is a bit messy and this will throw:
        # Method 'close()' can't be called here; method '_connection_for_bind()' is already in progress and
        # this would cause an unexpected state change to <SessionTransactionState.CLOSED: 5>
        except IllegalStateChangeError as e:
            logging.debug(f"Error while closing session db object: {e}")

    def clear_database(self):
        for table in self.metadata.sorted_tables:
            asyncio.run(self.conn.execute(table.delete()))