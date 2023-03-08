#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
from sqlalchemy import MetaData, func, Table, select, insert, update, delete
from sqlalchemy.dialects.sqlite import Insert  # used for upsert
from sqlalchemy.exc import IllegalStateChangeError
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SAWarning
from datetime import datetime
import asyncio
import warnings


class database:
    def __init__(self, db_engine):
        self.ComputersTable = None
        self.UsersTable = None
        self.AdminRelationsTable = None

        self.db_engine = db_engine
        self.metadata = MetaData()
        asyncio.run(self.reflect_tables())
        session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=True, class_=AsyncSession)
        # session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=False)
        Session = scoped_session(session_factory)
        # this is still named "conn" when it is the session object; TODO: rename
        self.conn = Session()

    async def shutdown_db(self):
        try:
            await asyncio.shield(self.conn.close())
        # due to the async nature of CME, sometimes session state is a bit messy and this will throw:
        # Method 'close()' can't be called here; method '_connection_for_bind()' is already in progress and
        # this would cause an unexpected state change to <SessionTransactionState.CLOSED: 5>
        except IllegalStateChangeError as e:
            logging.debug(f"Error while closing session db object: {e}")

    async def reflect_tables(self):
        async with self.db_engine.connect() as conn:
            await conn.run_sync(self.metadata.reflect)

            self.ComputersTable = Table("computers", self.metadata, autoload_with=self.db_engine)
            self.UsersTable = Table("users", self.metadata, autoload_with=self.db_engine)
            self.AdminRelationsTable = Table("admin_relations", self.metadata, autoload_with=self.db_engine)

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute('''CREATE TABLE "computers" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "hostname" text,
            "domain" text,
            "os" text,
            "instances" integer
            )''')

        # This table keeps track of which credential has admin access over which machine and vice-versa
        db_conn.execute('''CREATE TABLE "admin_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "computerid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(computerid) REFERENCES computers(id)
            )''')

        # type = hash, plaintext
        db_conn.execute('''CREATE TABLE "users" (
            "id" integer PRIMARY KEY,
            "credtype" text,
            "domain" text,
            "username" text,
            "password" text,
            "pillaged_from_computerid" integer,
            FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id)
            )''')

    def add_computer(self, ip, hostname, domain, os, instances):
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
        logging.debug(f"mssql add_computer() - computers returned: {results}")

        host_data = {
            "ip": ip,
            "hostname": hostname,
            "domain": domain,
            "os": os,
            "instances": instances,
        }

        if not results:
            hosts = [host_data]
        else:
            for host in results:
                computer_data = host._asdict()
                if ip is not None:
                    computer_data["ip"] = ip
                if hostname is not None:
                    computer_data["hostname"] = hostname
                if domain is not None:
                    computer_data["domain"] = domain
                if os is not None:
                    computer_data["os"] = os
                if instances is not None:
                    computer_data["instances"] = instances
                if computer_data not in hosts:
                    hosts.append(computer_data)

        logging.debug(f"Update Hosts: {hosts}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.ComputersTable)
        q = q.on_conflict_do_update(
            index_elements=self.ComputersTable.primary_key,
            set_=self.ComputersTable.columns
        )
        asyncio.run(
            self.conn.execute(
                q,
                hosts
            )
        )

    def add_credential(self, credtype, domain, username, password, group_id=None, pillaged_from=None):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        domain = domain.split('.')[0].upper()
        user_rowid = None

        if (group_id and not self.is_group_valid(group_id)) or \
                (pillaged_from and not self.is_computer_valid(pillaged_from)):
            self.conn.close()
            return

        credential_data = {}
        if credtype is not None:
            credential_data["credtype"] = credtype
        if domain is not None:
            credential_data["domain"] = domain
        if username is not None:
            credential_data["username"] = username
        if password is not None:
            credential_data["password"] = password
        if group_id is not None:
            credential_data["groupid"] = group_id
            credential_data["groupid"] = group_id
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
            q = insert(self.UsersTable).values(user_data).returning(self.UsersTable.c.id)
            results = asyncio.run(self.conn.execute(q)).first()
            user_rowid = results.id

            logging.debug(f"User RowID: {user_rowid}")
            if group_id:
                gr_data = {
                    "userid": user_rowid,
                    "groupid": group_id,
                }
                q = insert(self.GroupRelationsTable).values(gr_data)
                asyncio.run(self.conn.execute(q))
        else:
            for user in results:
                # might be able to just remove this if check, but leaving it in for now
                if not user[3] and not user[4] and not user[5]:
                    q = update(self.UsersTable).values(credential_data).returning(self.UsersTable.c.id)
                    results = asyncio.run(self.conn.execute(q)).first()
                    user_rowid = results.id

                    if group_id and not len(self.get_group_relations(user_rowid, group_id)):
                        gr_data = {
                            "userid": user_rowid,
                            "groupid": group_id,
                        }
                        q = update(self.GroupRelationsTable).values(gr_data)
                        asyncio.run(self.conn.execute(q))

        logging.debug('add_credential(credtype={}, domain={}, username={}, password={}, groupid={}, pillaged_from={}) => {}'.format(
            credtype,
            domain,
            username,
            password,
            group_id,
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
            users = self.conn.query(self.users_table).filter(
                self.users_table.c.id == user_id
            ).all()
        else:
            users = self.conn.query(self.users_table).filter(
                self.users_table.c.credtype == credtype,
                func.lower(self.users_table.c.domain) == func.lower(domain),
                func.lower(self.users_table.c.username) == func.lower(username),
                self.users_table.c.password == password
            ).all()
        logging.debug(f"Users: {users}")

        hosts = self.conn.query(self.computers_table).filter(
            self.computers_table.c.ip.like(func.lower(f"%{host}%"))
        )
        logging.debug(f"Hosts: {hosts}")

        if users is not None and hosts is not None:
            for user, host in zip(users, hosts):
                user_id = user[0]
                host_id = host[0]

                # Check to see if we already added this link
                links = self.conn.query(self.admin_relations_table).filter(
                    self.admin_relations_table.c.userid == user_id,
                    self.admin_relations_table.c.computerid == host_id
                ).all()

                if not links:
                    self.conn.execute(
                        self.admin_relations_table.insert(),
                        [{"userid": user_id, "computerid": host_id}]
                    )

        self.conn.commit()
        self.conn.close()

    def get_admin_relations(self, user_id=None, host_id=None):
        if user_id:
            results = self.conn.query(self.admin_relations_table).filter(
                self.admin_relations_table.c.userid == user_id
            ).all()
        elif host_id:
            results = self.conn.query(self.admin_relations_table).filter(
                self.admin_relations_table.c.computerid == host_id
            ).all()
        else:
            results = self.conn.query(self.admin_relations_table).all()

        self.conn.commit()
        self.conn.close()
        return results

    def remove_admin_relation(self, user_ids=None, host_ids=None):
        if user_ids:
            for user_id in user_ids:
                self.conn.query(self.admin_relations_table).filter(
                    self.admin_relations_table.c.userid == user_id
                ).delete()
        elif host_ids:
            for host_id in host_ids:
                self.conn.query(self.admin_relations_table).filter(
                    self.admin_relations_table.c.hostid == host_id
                ).delete()
        self.conn.commit()
        self.conn.close()

    def is_credential_valid(self, credential_id):
        """
        Check if this credential ID is valid.
        """
        results = self.conn.query(self.users_table).filter(
            self.users_table.c.id == credential_id,
            self.users_table.c.password is not None
        ).all()
        self.conn.commit()
        self.conn.close()
        return len(results) > 0

    def get_credentials(self, filter_term=None, cred_type=None):
        """
        Return credentials from the database.
        """
        # if we're returning a single credential by ID
        if self.is_credential_valid(filter_term):
            results = self.conn.query(self.users_table).filter(
                self.users_table.c.id == filter_term
            ).all()
        elif cred_type:
            results = self.conn.query(self.users_table).filter(
                self.users_table.c.credtype == cred_type
            ).all()
        # if we're filtering by username
        elif filter_term and filter_term != '':
            results = self.conn.query(self.users_table).filter(
                func.lower(self.users_table.c.username).like(func.lower(f"%{filter_term}%"))
            ).all()
        # otherwise return all credentials
        else:
            results = self.conn.query(self.users_table).all()

        self.conn.commit()
        self.conn.close()
        return results

    def is_computer_valid(self, host_id):
        """
        Check if this host ID is valid.
        """
        results = self.conn.query(self.computers_table).filter(
            self.computers_table.c.id == host_id
        ).all()
        self.conn.commit()
        self.conn.close()
        return len(results) > 0

    def get_computers(self, filter_term=None, domain=None):
        """
        Return hosts from the database.
        """
        # if we're returning a single host by ID
        if self.is_computer_valid(filter_term):
            results = self.conn.query(self.computers_table).filter(
                self.computers_table.c.id == filter_term
            ).first()
        # if we're filtering by domain controllers
        elif filter_term == 'dc':
            if domain:
                results = self.conn.query(self.computers_table).filter(
                    self.computers_table.c.dc == 1,
                    func.lower(self.computers_table.c.domain) == func.lower(domain)
                ).all()
            else:
                results = self.conn.query(self.computers_table).filter(
                    self.computers_table.c.dc == 1
                ).all()
        # if we're filtering by ip/hostname
        elif filter_term and filter_term != "":
            results = self.conn.query(self.computers_table).filter((
                    func.lower(self.computers_table.c.ip).like(func.lower(f"%{filter_term}%")) |
                    func.lower(self.computers_table.c.hostname).like(func.lower(f"%{filter_term}"))
            )).all()
        # otherwise return all computers
        else:
            results = self.conn.query(self.computers_table).all()

        self.conn.commit()
        self.conn.close()
        return results

    def clear_database(self):
        for table in self.metadata.tables:
            self.conn.query(self.metadata.tables[table]).delete()
        self.conn.commit()
