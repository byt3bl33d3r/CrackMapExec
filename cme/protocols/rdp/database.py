#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class database:
    def __init__(self, conn, metadata=None):
        # this is still named "conn" when it is the Session object, TODO: rename
        self.conn = conn
        self.metadata = metadata
        self.credentials_table = metadata.tables["credentials"]
        self.hosts_table = metadata.tables["hosts"]

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

    def clear_database(self):
        for table in self.metadata.tables:
            self.conn.query(self.metadata.tables[table]).delete()
        self.conn.commit()
