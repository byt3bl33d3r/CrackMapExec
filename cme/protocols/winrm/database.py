#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from sqlalchemy.orm import sessionmaker


class database:
    def __init__(self, db_engine, metadata=None):
        session = sessionmaker(bind=db_engine)
        # this is still named "conn" when it is the session object; TODO: rename
        self.conn = session()
        self.metadata = metadata
        self.credentials_table = metadata.tables["credentials"]
        self.hosts_table = metadata.tables["hosts"]

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

    def clear_database(self):
        for table in self.metadata.tables:
            self.conn.query(self.metadata.tables[table]).delete()
        self.conn.commit()
