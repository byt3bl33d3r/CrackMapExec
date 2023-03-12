#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging

from sqlalchemy.dialects.sqlite import Insert
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy import MetaData, Table, select, func, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IllegalStateChangeError
import asyncio


class database:
    def __init__(self, db_engine):
        self.ComputersTable = None
        self.UsersTable = None
        self.AdminRelationsTable = None
        self.LoggedinRelationsTable = None

        self.db_engine = db_engine
        self.metadata = MetaData()
        asyncio.run(self.reflect_tables())
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
        db_conn.execute('''CREATE TABLE "computers" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "port" integer,
            "hostname" text,
            "domain" text,
            "os" text
            )''')
        db_conn.execute('''CREATE TABLE "users" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "username" text,
            "password" text,
            "credtype" text,
            "pillaged_from_computerid" integer,
            FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id)
            )''')
        db_conn.execute('''CREATE TABLE "admin_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "computerid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(computerid) REFERENCES computers(id)
        )''')
        db_conn.execute('''CREATE TABLE "loggedin_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "computerid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(computerid) REFERENCES computers(id)
        )''')

    async def reflect_tables(self):
        async with self.db_engine.connect() as conn:
            await conn.run_sync(self.metadata.reflect)

            self.ComputersTable = Table("computers", self.metadata, autoload_with=self.db_engine)
            self.UsersTable = Table("users", self.metadata, autoload_with=self.db_engine)
            self.AdminRelationsTable = Table("admin_relations", self.metadata, autoload_with=self.db_engine)
            self.LoggedinRelationsTable = Table("loggedin_relations", self.metadata, autoload_with=self.db_engine)

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

    def add_computer(self, ip, port, hostname, domain, os):
        """
        Check if this host has already been added to the database, if not, add it in.
        TODO: return inserted or updated row ids as a list
        """
        domain = domain.split('.')[0].upper()
        hosts = []

        q = select(self.ComputersTable).filter(
            self.ComputersTable.c.ip == ip
        )
        results = asyncio.run(self.conn.execute(q)).all()
        logging.debug(f"smb add_computer() - computers returned: {results}")

        host_data = {
            "ip": ip,
            "port": port,
            "hostname": hostname,
            "domain": domain,
            "os": os,
        }

        # create new computer
        if not results:
            hosts = [host_data]
        # update existing hosts data
        else:
            for host in results:
                computer_data = host._asdict()
                # only update column if it is being passed in
                if ip is not None:
                    computer_data["ip"] = ip
                if port is not None:
                    computer_data["port"] = port
                if hostname is not None:
                    computer_data["hostname"] = hostname
                if domain is not None:
                    computer_data["domain"] = domain
                if os is not None:
                    computer_data["os"] = os
                # only add computer to be updated if it has changed
                if computer_data not in hosts:
                    hosts.append(computer_data)
        logging.debug(f"Update Hosts: {hosts}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.ComputersTable)
        update_columns = {col.name: col for col in q.excluded if col.name not in 'id'}
        q = q.on_conflict_do_update(
            index_elements=self.ComputersTable.primary_key,
            set_=update_columns
        )
        asyncio.run(
            self.conn.execute(
                q,
                hosts
            )
        )

    def add_credential(self, credtype, domain, username, password, pillaged_from=None):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        domain = domain.split('.')[0].upper()
        user_rowid = None

        credential_data = {}
        if credtype is not None:
            credential_data["credtype"] = credtype
        if domain is not None:
            credential_data["domain"] = domain
        if username is not None:
            credential_data["username"] = username
        if password is not None:
            credential_data["password"] = password
        if pillaged_from is not None:
            credential_data["pillaged_from"] = pillaged_from

        q = select(self.UsersTable).filter(
            func.lower(self.UsersTable.c.domain) == func.lower(domain),
            func.lower(self.UsersTable.c.username) == func.lower(username),
            func.lower(self.UsersTable.c.credtype) == func.lower(credtype)
        )
        results = asyncio.run(self.conn.execute(q)).all()

        logging.debug(f"Credential results: {results}")

        if not results:
            user_data = {
                "domain": domain,
                "username": username,
                "password": password,
                "credtype": credtype,
                "pillaged_from_computerid": pillaged_from,
            }
            q = Insert(self.UsersTable).values(user_data).returning(self.UsersTable.c.id)
            results = asyncio.run(self.conn.execute(q)).first()
            user_rowid = results.id

            logging.debug(f"User RowID: {user_rowid}")
        else:
            for user in results:
                # might be able to just remove this if check, but leaving it in for now
                if not user[3] and not user[4] and not user[5]:
                    q = update(self.UsersTable).values(credential_data).returning(self.UsersTable.c.id)
                    results = asyncio.run(self.conn.execute(q)).first()
                    user_rowid = results.id

        logging.debug(
            'add_credential(credtype={}, domain={}, username={}, password={}, pillaged_from={}) => {}'.format(
                credtype,
                domain,
                username,
                password,
                pillaged_from,
                user_rowid
            ))
        return user_rowid

    def remove_credentials(self, creds_id):
        """
        Removes a credential ID from the database
        """
        del_hosts = []
        for cred_id in creds_id:
            q = delete(self.UsersTable).filter(
                self.UsersTable.c.id == cred_id
            )
            del_hosts.append(q)
        asyncio.run(self.conn.execute(q))

    def add_admin_user(self, credtype, domain, username, password, host, user_id=None):
        domain = domain.split('.')[0].upper()

        if user_id:
            q = select(self.UsersTable).filter(
                self.UsersTable.c.id == user_id
            )
            users = asyncio.run(self.conn.execute(q)).all()
        else:
            q = select(self.UsersTable).filter(
                self.UsersTable.c.credtype == credtype,
                func.lower(self.UsersTable.c.domain) == func.lower(domain),
                func.lower(self.UsersTable.c.username) == func.lower(username),
                self.UsersTable.c.password == password
            )
            users = asyncio.run(self.conn.execute(q)).all()
        logging.debug(f"Users: {users}")

        like_term = func.lower(f"%{host}%")
        q = select(self.ComputersTable).filter(
            self.ComputersTable.c.ip.like(like_term)
        )
        hosts = asyncio.run(self.conn.execute(q)).all()
        logging.debug(f"Hosts: {hosts}")

        if users is not None and hosts is not None:
            for user, host in zip(users, hosts):
                user_id = user[0]
                host_id = host[0]

                q = select(self.AdminRelationsTable).filter(
                    self.AdminRelationsTable.c.userid == user_id,
                    self.AdminRelationsTable.c.computerid == host_id
                )
                links = asyncio.run(self.conn.execute(q)).all()

                if not links:
                    asyncio.run(self.conn.execute(
                        Insert(self.AdminRelationsTable),
                        links
                    ))

    def get_admin_relations(self, user_id=None, host_id=None):
        if user_id:
            q = select(self.AdminRelationsTable).filter(
                self.AdminRelationsTable.c.userid == user_id
            )
        elif host_id:
            q = select(self.AdminRelationsTable).filter(
                self.AdminRelationsTable.c.computerid == host_id
            )
        else:
            q = select(self.AdminRelationsTable)

        results = asyncio.run(self.conn.execute(q)).all()
        return results

    def remove_admin_relation(self, user_ids=None, host_ids=None):
        q = delete(self.AdminRelationsTable)
        if user_ids:
            for user_id in user_ids:
                q = q.filter(
                    self.AdminRelationsTable.c.userid == user_id
                )
        elif host_ids:
            for host_id in host_ids:
                q = q.filter(
                    self.AdminRelationsTable.c.hostid == host_id
                )
        asyncio.run(self.conn.execute(q))

    def is_credential_valid(self, credential_id):
        """
        Check if this credential ID is valid.
        """
        q = select(self.UsersTable).filter(
            self.UsersTable.c.id == credential_id,
            self.UsersTable.c.password is not None
        )
        results = asyncio.run(self.conn.execute(q)).all()
        return len(results) > 0

    def get_credentials(self, filter_term=None, cred_type=None):
        """
        Return credentials from the database.
        """
        # if we're returning a single credential by ID
        if self.is_credential_valid(filter_term):
            q = select(self.UsersTable).filter(
                self.UsersTable.c.id == filter_term
            )
        elif cred_type:
            q = select(self.UsersTable).filter(
                self.UsersTable.c.credtype == cred_type
            )
        # if we're filtering by username
        elif filter_term and filter_term != '':
            like_term = func.lower(f"%{filter_term}%")
            q = select(self.UsersTable).filter(
                func.lower(self.UsersTable.c.username).like(like_term)
            )
        # otherwise return all credentials
        else:
            q = select(self.UsersTable)

        results = asyncio.run(self.conn.execute(q)).all()
        return results

    def is_credential_local(self, credential_id):
        q = select(self.UsersTable.c.domain).filter(
            self.UsersTable.c.id == credential_id
        )
        user_domain = asyncio.run(self.conn.execute(q)).all()

        if user_domain:
            q = select(self.ComputersTable).filter(
                func.lower(self.ComputersTable.c.id) == func.lower(user_domain)
            )
            results = asyncio.run(self.conn.execute(q)).all()

            return len(results) > 0

    def is_computer_valid(self, host_id):
        """
        Check if this host ID is valid.
        """
        q = select(self.ComputersTable).filter(
            self.ComputersTable.c.id == host_id
        )
        results = asyncio.run(self.conn.execute(q)).all()
        return len(results) > 0

    def get_computers(self, filter_term=None):
        """
        Return hosts from the database.
        """
        q = select(self.ComputersTable)

        # if we're returning a single host by ID
        if self.is_computer_valid(filter_term):
            q = q.filter(
                self.ComputersTable.c.id == filter_term
            )
            results = asyncio.run(self.conn.execute(q)).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return [results]
        # if we're filtering by domain controllers
        elif filter_term is not None and filter_term.startswith('domain'):
            domain = filter_term.split()[1]
            like_term = func.lower(f"%{domain}%")
            q = q.filter(
                self.ComputersTable.c.domain.like(like_term)
            )
        # if we're filtering by ip/hostname
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = q.filter(
                self.ComputersTable.c.ip.like(like_term) |
                func.lower(self.ComputersTable.c.hostname).like(like_term)
            )
        results = asyncio.run(self.conn.execute(q)).all()
        return results

    def is_user_valid(self, user_id):
        """
        Check if this User ID is valid.
        """
        q = select(self.UsersTable).filter(
            self.UsersTable.c.id == user_id
        )
        results = asyncio.run(self.conn.execute(q)).all()
        return len(results) > 0

    def get_users(self, filter_term=None):
        q = select(self.UsersTable)

        if self.is_user_valid(filter_term):
            q = q.filter(
                self.UsersTable.c.id == filter_term
            )
        # if we're filtering by username
        elif filter_term and filter_term != '':
            like_term = func.lower(f"%{filter_term}%")
            q = q.filter(
                func.lower(self.UsersTable.c.username).like(like_term)
            )
        results = asyncio.run(self.conn.execute(q)).all()
        return results

    def get_user(self, domain, username):
        q = select(self.UsersTable).filter(
            func.lower(self.UsersTable.c.domain) == func.lower(domain),
            func.lower(self.UsersTable.c.username) == func.lower(username)
        )
        results = asyncio.run(self.conn.execute(q)).all()
        return results