#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from sqlalchemy import func
from sqlalchemy.orm import sessionmaker
from datetime import datetime


class database:
    def __init__(self, db_engine, metadata=None):
        Session = sessionmaker(bind=db_engine)
        # this is still named "conn" when it is the session object; TODO: rename
        self.conn = Session()
        self.metadata = metadata
        self.computers_table = metadata.tables["computers"]
        self.users_table = metadata.tables["users"]
        self.groups_table = metadata.tables["groups"]
        self.shares_table = metadata.tables["shares"]
        self.admin_relations_table = metadata.tables["admin_relations"]
        self.group_relations_table = metadata.tables["group_relations"]
        self.loggedin_relations = metadata.tables["loggedin_relations"]

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute('''CREATE TABLE "computers" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "hostname" text,
            "domain" text,
            "os" text,
            "dc" boolean,
            "smbv1" boolean,
            "signing" boolean,
            "spooler" boolean,
            "zerologon" boolean,
            "petitpotam" boolean
            )''')

        # type = hash, plaintext
        db_conn.execute('''CREATE TABLE "users" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "username" text,
            "password" text,
            "credtype" text,
            "pillaged_from_computerid" integer,
            FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id)
            )''')

        db_conn.execute('''CREATE TABLE "groups" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "name" text,
            "member_count_ad" integer,
            "last_query_time" text
            )''')

        # This table keeps track of which credential has admin access over which machine and vice-versa
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

        db_conn.execute('''CREATE TABLE "group_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "groupid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(groupid) REFERENCES groups(id)
            )''')

        db_conn.execute('''CREATE TABLE "shares" (
            "id" integer PRIMARY KEY,
            "computerid" text,
            "userid" integer,
            "name" text,
            "remark" text,
            "read" boolean,
            "write" boolean,
            FOREIGN KEY(userid) REFERENCES users(id)
            UNIQUE(computerid, userid, name)
        )''')

        #db_conn.execute('''CREATE TABLE "ntds_dumps" (
        #    "id" integer PRIMARY KEY,
        #    "computerid", integer,
        #    "domain" text,
        #    "username" text,
        #    "hash" text,
        #    FOREIGN KEY(computerid) REFERENCES computers(id)
        #    )''')

    def add_share(self, computer_id, user_id, name, remark, read, write):
        data = {
            "computerid": computer_id,
            "userid": user_id,
            "name": name,
            "remark": remark,
            "read": read,
            "write": write,
        }
        self.conn.execute(
            self.shares_table.insert(),
            [data]
        )
        self.conn.commit()
        self.conn.close()

    def is_share_valid(self, share_id):
        """
        Check if this share ID is valid.
        """
        results = self.conn.query(self.shares_table).filter(
            self.shares_table.c.id == share_id
        ).all()
        self.conn.commit()
        self.conn.close()

        logging.debug(f"is_share_valid(shareID={share_id}) => {len(results) > 0}")
        return len(results) > 0

    def get_shares(self, filter_term=None):
        if self.is_share_valid(filter_term):
            results = self.conn.query(self.shares_table).filter(
                self.shares_table.c.id == filter_term
            ).all()
        elif filter_term:
            results = self.conn.query(self.shares_table).filter(
                func.lower(self.shares_table.c.name).like(func.lower(f"%{filter_term}%"))
            ).all()
        else:
            results = self.conn.query(self.shares_table).all()
        return results

    def get_shares_by_access(self, permissions, share_id=None):
        permissions = permissions.lower()

        if share_id:
            if permissions == "r":
                results = self.conn.query(self.shares_table).filter(
                    self.shares_table.c.id == share_id,
                    self.shares_table.c.read == 1
                ).all()
            elif permissions == "w":
                results = self.conn.query(self.shares_table).filter(
                    self.shares_table.c.id == share_id,
                    self.shares_table.c.write == 1
                ).all()
            elif permissions == "rw":
                results = self.conn.query(self.shares_table).filter(
                    self.shares_table.c.id == share_id,
                    self.shares_table.c.read == 1,
                    self.shares_table.c.write == 1
                ).all()
        else:
            if permissions == "r":
                results = self.conn.query(self.shares_table).filter(
                    self.shares_table.c.read == 1
                ).all()
            elif permissions == "w":
                results = self.conn.query(self.shares_table).filter(
                    self.shares_table.c.write == 1
                ).all()
            elif permissions == "rw":
                results = self.conn.query(self.shares_table).filter(
                    self.shares_table.c.read == 1,
                    self.shares_table.c.write == 1
                ).all()
        return results

    def get_users_with_share_access(self, computer_id, share_name, permissions):
        permissions = permissions.lower()

        if permissions == "r":
            results = self.conn.query(self.shares_table.c.userid).filter(
                self.shares_table.c.computerid == computer_id,
                self.shares_table.c.name == share_name,
                self.shares_table.c.read == 1
            ).all()
        elif permissions == "w":
            results = self.conn.query(self.shares_table.c.userid).filter(
                self.shares_table.c.computerid == computer_id,
                self.shares_table.c.name == share_name,
                self.shares_table.c.write == 1
            ).all()
        elif permissions == "rw":
            results = self.conn.query(self.shares_table.c.userid).filter(
                self.shares_table.c.computerid == computer_id,
                self.shares_table.c.name == share_name,
                self.shares_table.c.read == 1,
                self.shares_table.c.write == 1
            ).all()
        return results

    # pull/545
    def add_computer(self, ip, hostname, domain, os, smbv1, signing=None, spooler=None, zerologon=None, petitpotam=None, dc=None):
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
        if smbv1 is not None:
            computer_data["smbv1"] = smbv1
        if signing is not None:
            computer_data["signing"] = signing
        if spooler is not None:
            computer_data["spooler"] = spooler
        if zerologon is not None:
            computer_data["zerologon"] = zerologon
        if petitpotam is not None:
            computer_data["petitpotam"] = petitpotam
        if dc is not None:
            computer_data["dc"] = dc

        if not results:
            new_host = {
                "ip": ip,
                "hostname": hostname,
                "domain": domain,
                "os": os,
                "dc": dc,
                "smbv1": smbv1,
                "signing": signing,
                "spooler": spooler,
                "zerologon": zerologon,
                "petitpotam": petitpotam
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
        # self.conn.commit()
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
        logging.debug('add_credential(credtype={}, domain={}, username={}, password={}, groupid={}, pillaged_from={}) => {}'.format(credtype, domain, username, password, group_id, pillaged_from, user_rowid))

        return user_rowid

    def add_user(self, domain, username, group_id=None):
        if group_id and not self.is_group_valid(group_id):
            return

        domain = domain.split('.')[0].upper()
        user_rowid = None

        self.conn.execute("SELECT * FROM users WHERE LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?)", [domain, username])
        results = self.conn.fetchall()

        if not len(results):
            self.conn.execute("INSERT INTO users (domain, username, password, credtype, pillaged_from_computerid) VALUES (?,?,?,?,?)", [domain, username, '', '', ''])
            user_rowid = self.conn.lastrowid
            if group_id:
                self.conn.execute("INSERT INTO group_relations (userid, groupid) VALUES (?,?)", [user_rowid, group_id])
        else:
            for user in results:
                if (domain != user[1]) and (username != user[2]):
                    self.conn.execute("UPDATE users SET domain=?, user=? WHERE id=?", [domain, username, user[0]])
                    user_rowid = self.conn.lastrowid

                if not user_rowid: user_rowid = user[0]
                if group_id and not len(self.get_group_relations(user_rowid, group_id)):
                    self.conn.execute("INSERT INTO group_relations (userid, groupid) VALUES (?,?)", [user_rowid, group_id])

        self.conn.commit()
        self.conn.close()

        logging.debug('add_user(domain={}, username={}, groupid={}) => {}'.format(domain, username, group_id, user_rowid))

        return user_rowid

    def add_group(self, domain, name, member_count_ad=None):
        domain = domain.split('.')[0].upper()

        results = self.conn.query(self.groups_table).filter(
            func.lower(self.groups_table.c.domain) == func.lower(domain),
            func.lower(self.groups_table.c.name) == func.lower(name)
        ).all()

        group_data = {}
        if domain is not None:
            group_data["domain"] = domain
        if name is not None:
            group_data["name"] = name
        if member_count_ad is not None:
            group_data["member_count_ad"] = member_count_ad
            today = datetime.now()
            iso_date = today.isoformat()
            group_data["last_query_time"] = iso_date

        if results:
            # initialize the cid to the first (or only) id
            cid = results[0][0]
            for group in results:
                cid = self.conn.execute(
                    self.groups_table.update().values(
                        group_data
                    ).where(
                        self.groups_table.c.id == group[0]
                    )
                )
        else:
            cid = self.conn.execute(
                self.groups_table.insert(),
                [group_data]
            )
        self.conn.commit()
        self.conn.close()

        logging.debug('add_group(domain={}, name={}) => {}'.format(domain, name, cid))
        return cid

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

    def get_group_relations(self, user_id=None, group_id=None):
        if user_id and group_id:
            results = self.conn.query(self.group_relations_table).filter(
                self.group_relations_table.c.id == user_id,
                self.group_relations_table.c.groupid == group_id
            ).all()
        elif user_id:
            results = self.conn.query(self.group_relations_table).filter(
                self.group_relations_table.c.id == user_id
            ).all()
        elif group_id:
            results = self.conn.query(self.group_relations_table).filter(
                self.group_relations_table.c.groupid == group_id
            ).all()

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

    def remove_group_relations(self, user_id=None, group_id=None):
        if user_id:
            self.conn.query(self.group_relations_table).filter(
                self.group_relations_table.c.userid == user_id
            ).delete()
        elif group_id:
            self.conn.query(self.group_relations_table).filter(
                self.group_relations_table.c.groupid == group_id
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

    def is_credential_local(self, credential_id):
        user_domain = self.conn.query(self.users_table.c.domain).filter(
            self.users_table.c.id == credential_id
        ).all()

        if user_domain:
            results = self.conn.query(self.computers_table).filter(
                func.lower(self.computers_table.c.id) == func.lower(user_domain)
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

    def is_user_valid(self, user_id):
        """
        Check if this User ID is valid.
        """
        self.conn.execute('SELECT * FROM users WHERE id=? LIMIT 1', [user_id])
        results = self.conn.fetchall()
        self.conn.commit()
        self.conn.close()
        return len(results) > 0

    def get_users(self, filter_term=None):
        if self.is_user_valid(filter_term):
            self.conn.execute("SELECT * FROM users WHERE id=? LIMIT 1", [filter_term])

        # if we're filtering by username
        elif filter_term and filter_term != '':
            self.conn.execute("SELECT * FROM users WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filter_term)])

        else:
            self.conn.execute("SELECT * FROM users")

        results = self.conn.fetchall()
        self.conn.commit()
        self.conn.close()
        return results

    def get_user(self, domain, username):
        results = self.conn.query(self.users_table).filter(
            func.lower(self.users_table.c.domain) == func.lower(domain),
            func.lower(self.users_table.c.username) == func.lower(username)
        ).all()
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
            results = self.conn.query(self.computers_table).filter(self.computers_table.c.id == filter_term).first()
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

    def get_domain_controllers(self, domain=None):
        return self.get_computers(filter_term='dc', domain=domain)

    def is_group_valid(self, group_id):
        """
        Check if this group ID is valid.
        """
        results = self.conn.query(self.groups_table).filter(
            self.groups_table.c.id == group_id
        ).first()
        self.conn.commit()
        self.conn.close()

        valid = True if results else False
        logging.debug(f"is_group_valid(groupID={group_id}) => {valid}")

        return valid

    def get_groups(self, filter_term=None, group_name=None, group_domain=None):
        """
        Return groups from the database
        """
        if group_domain:
            group_domain = group_domain.split('.')[0].upper()

        if self.is_group_valid(filter_term):
            results = self.conn.query(self.groups_table).filter(
                self.groups_table.c.id == filter_term
            ).first()
        elif group_name and group_domain:
            results = self.conn.query(self.groups_table).filter(
                func.lower(self.groups_table.c.username) == func.lower(group_name),
                func.lower(self.groups_table.c.domain) == func.lower(group_domain)
            ).all()
        elif filter_term and filter_term != "":
            results = self.conn.query(self.groups_table).filter(
                func.lower(self.groups_table.c.name).like(func.lower(f"%{filter_term}%"))
            ).all()
        else:
            results = self.conn.query(self.groups_table).all()

        self.conn.commit()
        self.conn.close()
        logging.debug(f"get_groups(filterTerm={filter_term}, groupName={group_name}, groupDomain={group_domain}) => {results}")
        return results

    def clear_database(self):
        for table in self.metadata.tables:
            self.conn.query(self.metadata.tables[table]).delete()
        self.conn.commit()
