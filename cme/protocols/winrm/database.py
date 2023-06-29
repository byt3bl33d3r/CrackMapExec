#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from sqlalchemy.dialects.sqlite import Insert
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy import MetaData, Table, select, func, delete
from sqlalchemy.exc import (
    IllegalStateChangeError,
    NoInspectionAvailable,
    NoSuchTableError,
)
from cme.logger import cme_logger


class database:
    def __init__(self, db_engine):
        self.HostsTable = None
        self.UsersTable = None
        self.AdminRelationsTable = None
        self.LoggedinRelationsTable = None

        self.db_engine = db_engine
        self.db_path = self.db_engine.url.database
        self.protocol = Path(self.db_path).stem.upper()
        self.metadata = MetaData()
        self.reflect_tables()
        session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=True)

        Session = scoped_session(session_factory)
        # this is still named "conn" when it is the session object; TODO: rename
        self.conn = Session()

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute(
            """CREATE TABLE "hosts" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "port" integer,
            "hostname" text,
            "domain" text,
            "os" text
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "users" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "username" text,
            "password" text,
            "credtype" text,
            "pillaged_from_hostid" integer,
            FOREIGN KEY(pillaged_from_hostid) REFERENCES hosts(id)
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "admin_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "hostid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
        )"""
        )
        db_conn.execute(
            """CREATE TABLE "loggedin_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "hostid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
        )"""
        )

    def reflect_tables(self):
        with self.db_engine.connect() as conn:
            try:
                self.HostsTable = Table("hosts", self.metadata, autoload_with=self.db_engine)
                self.UsersTable = Table("users", self.metadata, autoload_with=self.db_engine)
                self.AdminRelationsTable = Table("admin_relations", self.metadata, autoload_with=self.db_engine)
                self.LoggedinRelationsTable = Table("loggedin_relations", self.metadata, autoload_with=self.db_engine)
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
            self.conn.close()
        # due to the async nature of CME, sometimes session state is a bit messy and this will throw:
        # Method 'close()' can't be called here; method '_connection_for_bind()' is already in progress and
        # this would cause an unexpected state change to <SessionTransactionState.CLOSED: 5>
        except IllegalStateChangeError as e:
            cme_logger.debug(f"Error while closing session db object: {e}")

    def clear_database(self):
        for table in self.metadata.sorted_tables:
            self.conn.execute(table.delete())

    def add_host(self, ip, port, hostname, domain, os=None):
        """
        Check if this host has already been added to the database, if not, add it in.
        TODO: return inserted or updated row ids as a list
        """
        domain = domain.split(".")[0].upper()
        hosts = []

        q = select(self.HostsTable).filter(self.HostsTable.c.ip == ip)
        results = self.conn.execute(q).all()
        cme_logger.debug(f"smb add_host() - hosts returned: {results}")

        # create new host
        if not results:
            new_host = {
                "ip": ip,
                "port": port,
                "hostname": hostname,
                "domain": domain,
                "os": os,
            }
            hosts = [new_host]
        # update existing hosts data
        else:
            for host in results:
                host_data = host._asdict()
                # only update column if it is being passed in
                if ip is not None:
                    host_data["ip"] = ip
                if port is not None:
                    host_data["port"] = port
                if hostname is not None:
                    host_data["hostname"] = hostname
                if domain is not None:
                    host_data["domain"] = domain
                if os is not None:
                    host_data["os"] = os
                # only add host to be updated if it has changed
                if host_data not in hosts:
                    hosts.append(host_data)
        cme_logger.debug(f"Update Hosts: {hosts}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.HostsTable)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.HostsTable.primary_key, set_=update_columns)
        self.conn.execute(q, hosts)

    def add_credential(self, credtype, domain, username, password, pillaged_from=None):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        domain = domain.split(".")[0].upper()
        credentials = []

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
            func.lower(self.UsersTable.c.credtype) == func.lower(credtype),
        )
        results = self.conn.execute(q).all()

        # add new credential
        if not results:
            new_cred = {
                "credtype": credtype,
                "domain": domain,
                "username": username,
                "password": password,
                "pillaged_from": pillaged_from,
            }
            credentials = [new_cred]
        # update existing cred data
        else:
            for creds in results:
                # this will include the id, so we don't touch it
                cred_data = creds._asdict()
                # only update column if it is being passed in
                if credtype is not None:
                    cred_data["credtype"] = credtype
                if domain is not None:
                    cred_data["domain"] = domain
                if username is not None:
                    cred_data["username"] = username
                if password is not None:
                    cred_data["password"] = password
                if pillaged_from is not None:
                    cred_data["pillaged_from"] = pillaged_from
                # only add cred to be updated if it has changed
                if cred_data not in credentials:
                    credentials.append(cred_data)

        # TODO: find a way to abstract this away to a single Upsert call
        q_users = Insert(self.UsersTable)  # .returning(self.UsersTable.c.id)
        update_columns_users = {col.name: col for col in q_users.excluded if col.name not in "id"}
        q_users = q_users.on_conflict_do_update(index_elements=self.UsersTable.primary_key, set_=update_columns_users)
        self.conn.execute(q_users, credentials)  # .scalar()
        # return user_ids

    def remove_credentials(self, creds_id):
        """
        Removes a credential ID from the database
        """
        del_hosts = []
        for cred_id in creds_id:
            q = delete(self.UsersTable).filter(self.UsersTable.c.id == cred_id)
            del_hosts.append(q)
        self.conn.execute(q)

    def add_admin_user(self, credtype, domain, username, password, host, user_id=None):
        domain = domain.split(".")[0]
        add_links = []

        creds_q = select(self.UsersTable)
        if user_id:
            creds_q = creds_q.filter(self.UsersTable.c.id == user_id)
        else:
            creds_q = creds_q.filter(
                func.lower(self.UsersTable.c.credtype) == func.lower(credtype),
                func.lower(self.UsersTable.c.domain) == func.lower(domain),
                func.lower(self.UsersTable.c.username) == func.lower(username),
                self.UsersTable.c.password == password,
            )
        users = self.conn.execute(creds_q)
        hosts = self.get_hosts(host)

        if users and hosts:
            for user, host in zip(users, hosts):
                user_id = user[0]
                host_id = host[0]
                link = {"userid": user_id, "hostid": host_id}
                admin_relations_select = select(self.AdminRelationsTable).filter(
                    self.AdminRelationsTable.c.userid == user_id,
                    self.AdminRelationsTable.c.hostid == host_id,
                )
                links = self.conn.execute(admin_relations_select).all()

                if not links:
                    add_links.append(link)

        admin_relations_insert = Insert(self.AdminRelationsTable)

        self.conn.execute(admin_relations_insert, add_links)

    def get_admin_relations(self, user_id=None, host_id=None):
        if user_id:
            q = select(self.AdminRelationsTable).filter(self.AdminRelationsTable.c.userid == user_id)
        elif host_id:
            q = select(self.AdminRelationsTable).filter(self.AdminRelationsTable.c.hostid == host_id)
        else:
            q = select(self.AdminRelationsTable)

        results = self.conn.execute(q).all()
        return results

    def remove_admin_relation(self, user_ids=None, host_ids=None):
        q = delete(self.AdminRelationsTable)
        if user_ids:
            for user_id in user_ids:
                q = q.filter(self.AdminRelationsTable.c.userid == user_id)
        elif host_ids:
            for host_id in host_ids:
                q = q.filter(self.AdminRelationsTable.c.hostid == host_id)
        self.conn.execute(q)

    def is_credential_valid(self, credential_id):
        """
        Check if this credential ID is valid.
        """
        q = select(self.UsersTable).filter(
            self.UsersTable.c.id == credential_id,
            self.UsersTable.c.password is not None,
        )
        results = self.conn.execute(q).all()
        return len(results) > 0

    def get_credentials(self, filter_term=None, cred_type=None):
        """
        Return credentials from the database.
        """
        # if we're returning a single credential by ID
        if self.is_credential_valid(filter_term):
            q = select(self.UsersTable).filter(self.UsersTable.c.id == filter_term)
        elif cred_type:
            q = select(self.UsersTable).filter(self.UsersTable.c.credtype == cred_type)
        # if we're filtering by username
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = select(self.UsersTable).filter(func.lower(self.UsersTable.c.username).like(like_term))
        # otherwise return all credentials
        else:
            q = select(self.UsersTable)

        results = self.conn.execute(q).all()
        return results

    def is_credential_local(self, credential_id):
        q = select(self.UsersTable.c.domain).filter(self.UsersTable.c.id == credential_id)
        user_domain = self.conn.execute(q).all()

        if user_domain:
            q = select(self.HostsTable).filter(func.lower(self.HostsTable.c.id) == func.lower(user_domain))
            results = self.conn.execute(q).all()

            return len(results) > 0

    def is_host_valid(self, host_id):
        """
        Check if this host ID is valid.
        """
        q = select(self.HostsTable).filter(self.HostsTable.c.id == host_id)
        results = self.conn.execute(q).all()
        return len(results) > 0

    def get_hosts(self, filter_term=None):
        """
        Return hosts from the database.
        """
        q = select(self.HostsTable)

        # if we're returning a single host by ID
        if self.is_host_valid(filter_term):
            q = q.filter(self.HostsTable.c.id == filter_term)
            results = self.conn.execute(q).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return [results]
        # if we're filtering by domain controllers
        elif filter_term is not None and filter_term.startswith("domain"):
            domain = filter_term.split()[1]
            like_term = func.lower(f"%{domain}%")
            q = q.filter(self.HostsTable.c.domain.like(like_term))
        # if we're filtering by ip/hostname
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = q.filter(self.HostsTable.c.ip.like(like_term) | func.lower(self.HostsTable.c.hostname).like(like_term))
        results = self.conn.execute(q).all()
        cme_logger.debug(f"winrm get_hosts() - results: {results}")
        return results

    def is_user_valid(self, user_id):
        """
        Check if this User ID is valid.
        """
        q = select(self.UsersTable).filter(self.UsersTable.c.id == user_id)
        results = self.conn.execute(q).all()
        return len(results) > 0

    def get_users(self, filter_term=None):
        q = select(self.UsersTable)

        if self.is_user_valid(filter_term):
            q = q.filter(self.UsersTable.c.id == filter_term)
        # if we're filtering by username
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = q.filter(func.lower(self.UsersTable.c.username).like(like_term))
        results = self.conn.execute(q).all()
        return results

    def get_user(self, domain, username):
        q = select(self.UsersTable).filter(
            func.lower(self.UsersTable.c.domain) == func.lower(domain),
            func.lower(self.UsersTable.c.username) == func.lower(username),
        )
        results = self.conn.execute(q).all()
        return results

    def add_loggedin_relation(self, user_id, host_id):
        relation_query = select(self.LoggedinRelationsTable).filter(
            self.LoggedinRelationsTable.c.userid == user_id,
            self.LoggedinRelationsTable.c.hostid == host_id,
        )
        results = self.conn.execute(relation_query).all()

        # only add one if one doesn't already exist
        if not results:
            relation = {"userid": user_id, "hostid": host_id}
            try:
                # TODO: find a way to abstract this away to a single Upsert call
                q = Insert(self.LoggedinRelationsTable)  # .returning(self.LoggedinRelationsTable.c.id)

                self.conn.execute(q, [relation])  # .scalar()
                # return inserted_ids
            except Exception as e:
                cme_logger.debug(f"Error inserting LoggedinRelation: {e}")

    def get_loggedin_relations(self, user_id=None, host_id=None):
        q = select(self.LoggedinRelationsTable)  # .returning(self.LoggedinRelationsTable.c.id)
        if user_id:
            q = q.filter(self.LoggedinRelationsTable.c.userid == user_id)
        if host_id:
            q = q.filter(self.LoggedinRelationsTable.c.hostid == host_id)
        results = self.conn.execute(q).all()
        return results

    def remove_loggedin_relations(self, user_id=None, host_id=None):
        q = delete(self.LoggedinRelationsTable)
        if user_id:
            q = q.filter(self.LoggedinRelationsTable.c.userid == user_id)
        elif host_id:
            q = q.filter(self.LoggedinRelationsTable.c.hostid == host_id)
        self.conn.execute(q)
