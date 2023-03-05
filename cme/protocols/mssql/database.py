#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func
import logging


class database:
    def __init__(self, db_engine, metadata=None):
        session = sessionmaker(bind=db_engine)
        # this is still named "conn" when it is the session object; TODO: rename
        self.conn = session()
        self.metadata = metadata
        self.computers_table = metadata.tables["computers"]
        self.admin_relations_table = metadata.tables["admin_relations"]
        self.users_table = metadata.tables["users"]

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
        Check if this host has already been added to the database, if not add it in.
        """
        domain = domain.split('.')[0].upper()

        results = self.conn.query(self.computers_table).filter(
            self.computers_table.c.ip == ip
        ).all()

        # initialize the cid to the first (or only) id
        if len(results) > 0:
            cid = results[0][0]

        computer_data = {}
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

        if not results:
            new_host = {
                "ip": ip,
                "hostname": hostname,
                "domain": domain,
                "os": os,
                "instances": instances
            }
            try:
                cid = self.conn.execute(
                    self.computers_table.insert(),
                    [new_host]
                )
            except Exception as e:
                logging.error(f"Exception: {e}")
        else:
            for host in results:
                try:
                    cid = self.conn.execute(
                        self.computers_table.update().values(
                            computer_data
                        ).where(
                            self.computers_table.c.id == host.id
                        )
                    )
                except Exception as e:
                    logging.error(f"Exception: {e}")
        self.conn.close()
        return cid

    def add_credential(self, credtype, domain, username, password, group_id=None, pillaged_from=None):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        domain = domain.split('.')[0].upper()
        user_rowid = None

        if group_id and not self.is_group_valid(group_id):
            self.conn.close()
            return

        if pillaged_from and not self.is_computer_valid(pillaged_from):
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
        if pillaged_from is not None:
            credential_data["pillaged_from"] = pillaged_from

        results = self.conn.query(self.users_table).filter(
            func.lower(self.users_table.c.domain) == func.lower(domain),
            func.lower(self.users_table.c.username) == func.lower(username),
            func.lower(self.users_table.c.credtype) == func.lower(credtype)
        ).all()
        logging.debug(f"Credential results: {results}")

        if not results:
            user_data = {
                "domain": domain,
                "username": username,
                "password": password,
                "credtype": credtype,
                "pillaged_from_computerid": pillaged_from,
            }
            user_rowid = self.conn.execute(
                self.users_table.insert(),
                [user_data]
            )
            logging.debug(f"User RowID: {user_rowid}")
            if group_id:
                gr_data = {
                    "userid": user_rowid,
                    "groupid": group_id,
                }
                self.conn.execute(
                    self.group_relations_table.insert(),
                    [gr_data]
                )
        else:
            for user in results:
                # might be able to just remove this if check, but leaving it in for now
                if not user[3] and not user[4] and not user[5]:
                    user_rowid = self.conn.execute(
                        self.users_table.update().values(
                            credential_data
                        ).where(
                            self.users_table.c.id == user[0]
                        )
                    )
                    if group_id and not len(self.get_group_relations(user_rowid, group_id)):
                        self.conn.execute(
                            self.group_relations_table.update().values(
                                {"userid": user_rowid, "groupid": group_id}
                            )
                        )
        self.conn.commit()
        self.conn.close()
        logging.debug(
            'add_credential(credtype={}, domain={}, username={}, password={}, groupid={}, pillaged_from={}) => {}'.format(
                credtype, domain, username, password, group_id, pillaged_from, user_rowid))

        return user_rowid

    def remove_credentials(self, creds_id):
        """
        Removes a credential ID from the database
        """
        for cred_id in creds_id:
            self.conn.query(self.users_table).filter(
                self.users_table.c.id == cred_id
            ).delete()
        self.conn.commit()
        self.conn.close()

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

    def is_credential_valid(self, credentialID):
        """
        Check if this credential ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM users WHERE id=? LIMIT 1', [credentialID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0

    def get_credentials(self, filterTerm=None, credtype=None):
        """
        Return credentials from the database.
        """

        cur = self.conn.cursor()

        # if we're returning a single credential by ID
        if self.is_credential_valid(filterTerm):
            cur.execute("SELECT * FROM users WHERE id=? LIMIT 1", [filterTerm])

        # if we're filtering by credtype
        elif credtype:
            cur.execute("SELECT * FROM users WHERE credtype=?", [credtype])

        # if we're filtering by username
        elif filterTerm and filterTerm != "":
            cur.execute("SELECT * FROM users WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filterTerm.lower())])

        # otherwise return all credentials
        else:
            cur.execute("SELECT * FROM users")

        results = cur.fetchall()
        cur.close()
        return results

    def is_computer_valid(self, hostID):
        """
        Check if this computer ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM computers WHERE id=? LIMIT 1', [hostID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0

    def get_computers(self, filterTerm=None):
        """
        Return computers from the database.
        """

        cur = self.conn.cursor()

        # if we're returning a single host by ID
        if self.is_computer_valid(filterTerm):
            cur.execute("SELECT * FROM computers WHERE id=? LIMIT 1", [filterTerm])

        # if we're filtering by ip/hostname
        elif filterTerm and filterTerm != "":
            cur.execute("SELECT * FROM computers WHERE ip LIKE ? OR LOWER(hostname) LIKE LOWER(?)", ['%{}%'.format(filterTerm.lower()), '%{}%'.format(filterTerm.lower())])

        # otherwise return all credentials
        else:
            cur.execute("SELECT * FROM computers")

        results = cur.fetchall()
        cur.close()
        return results

    def clear_database(self):
        for table in self.metadata.tables:
            self.conn.query(self.metadata.tables[table]).delete()
        self.conn.commit()
