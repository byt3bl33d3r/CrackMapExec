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

from sqlalchemy.ext.compiler import compiles

# if there is an issue with SQLAlchemy and a connection cannot be cleaned up properly it spews out annoying warnings
warnings.filterwarnings("ignore", category=SAWarning)


@compiles(insert)
def _prefix_insert_with_ignore(ins, compiler, **kw):
    return compiler.visit_insert(ins.prefix_with('OR IGNORE'), **kw)


class database:
    def __init__(self, db_engine):
        self.ComputersTable = None
        self.UsersTable = None
        self.GroupsTable = None
        self.SharesTable = None
        self.AdminRelationsTable = None
        self.GroupRelationsTable = None
        self.LoggedinRelationsTable = None

        self.db_engine = db_engine
        self.metadata = MetaData()
        asyncio.run(self.reflect_tables())
        session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=True, class_=AsyncSession)
        
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
            self.GroupsTable = Table("groups", self.metadata, autoload_with=self.db_engine)
            self.SharesTable = Table("shares", self.metadata, autoload_with=self.db_engine)
            self.AdminRelationsTable = Table("admin_relations", self.metadata, autoload_with=self.db_engine)
            self.GroupRelationsTable = Table("group_relations", self.metadata, autoload_with=self.db_engine)
            self.LoggedinRelationsTable = Table("loggedin_relations", self.metadata, autoload_with=self.db_engine)

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

    # pull/545
    def add_computer(self, ip, hostname, domain, os, smbv1, signing, spooler=None, zerologon=None, petitpotam=None, dc=None):
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
                        insert(self.AdminRelationsTable).values(links)
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

    def is_computer_valid(self, host_id):
        """
        Check if this host ID is valid.
        """
        q = select(self.ComputersTable).filter(
            self.ComputersTable.c.id == host_id
        )
        results = asyncio.run(self.conn.execute(q)).all()
        return len(results) > 0

    def get_computers(self, filter_term=None, domain=None):
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
        elif filter_term == 'dc':
            q = q.filter(
                self.ComputersTable.c.dc == 1
            )
            if domain:
                q = q.filter(
                    func.lower(self.ComputersTable.c.domain) == func.lower(domain)
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

    def is_group_valid(self, group_id):
        """
        Check if this group ID is valid.
        """
        q = select(self.GroupsTable).filter(
            self.GroupsTable.c.id == group_id
        )
        results = asyncio.run(self.conn.execute(q)).first()

        valid = True if results else False
        logging.debug(f"is_group_valid(groupID={group_id}) => {valid}")

        return valid

    def add_group(self, domain, name, member_count_ad=None):
        domain = domain.split('.')[0].upper()
        groups = []

        q = select(self.GroupsTable).filter(
            func.lower(self.GroupsTable.c.domain) == func.lower(domain),
            func.lower(self.GroupsTable.c.name) == func.lower(name)
        )
        results = asyncio.run(self.conn.execute(q)).all()
        logging.debug(f"add_group() - groups returned: {results}")

        group_data = {
            "domain": domain,
            "name": name,
        }

        if not results:
            if member_count_ad is not None:
                group_data["member_count_ad"] = member_count_ad
                today = datetime.now()
                iso_date = today.isoformat()
                group_data["last_query_time"] = iso_date
            groups = [group_data]
        else:
            for group in results:
                g_data = group._asdict()
                if domain is not None:
                    g_data["domain"] = domain
                if name is not None:
                    g_data["name"] = name
                if member_count_ad is not None:
                    g_data["member_count_ad"] = member_count_ad
                    today = datetime.now()
                    iso_date = today.isoformat()
                    g_data["last_query_time"] = iso_date
                # only add it to the upsert query if it's changed to save query execution time
                if g_data not in groups:
                    groups.append(g_data)

        logging.debug(f"Update Groups: {groups}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.GroupsTable).returning(self.GroupsTable.c.id)
        update_columns = {col.name: col for col in q.excluded if col.name not in 'id'}
        q = q.on_conflict_do_update(
            index_elements=self.GroupsTable.primary_key,
            set_=update_columns
        )
        res_inserted_result = asyncio.run(
            self.conn.execute(
                q,
                groups
            )
        )

        # from the code, the resulting ID is only referenced if it expects one group, which isn't great
        # TODO: always return a list and fix code references to not expect a single integer
        inserted_result = res_inserted_result.first()
        gid = inserted_result.id

        logging.debug(f"inserted_results: {inserted_result}\ntype: {type(inserted_result)}")
        logging.debug('add_group(domain={}, name={}) => {}'.format(domain, name, gid))

        return gid

    def get_groups(self, filter_term=None, group_name=None, group_domain=None):
        """
        Return groups from the database
        """
        if group_domain:
            group_domain = group_domain.split('.')[0].upper()

        if self.is_group_valid(filter_term):
            q = select(self.GroupsTable).filter(
                self.GroupsTable.c.id == filter_term
            )
            results = asyncio.run(self.conn.execute(q)).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return [results]
        elif group_name and group_domain:
            q = select(self.GroupsTable).filter(
                func.lower(self.GroupsTable.c.username) == func.lower(group_name),
                func.lower(self.GroupsTable.c.domain) == func.lower(group_domain)
            )
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = select(self.GroupsTable).filter(
                self.GroupsTable.c.name.like(like_term)
            )
        else:
            q = select(self.GroupsTable).filter()

        results = asyncio.run(self.conn.execute(q)).all()

        logging.debug(f"get_groups(filterTerm={filter_term}, groupName={group_name}, groupDomain={group_domain}) => {results}")
        return results

    def get_group_relations(self, user_id=None, group_id=None):
        if user_id and group_id:
            q = select(self.GroupRelationsTable).filter(
                self.GroupRelationsTable.c.id == user_id,
                self.GroupRelationsTable.c.groupid == group_id
            )
        elif user_id:
            q = select(self.GroupRelationsTable).filter(
                self.GroupRelationsTable.c.id == user_id
            )
        elif group_id:
            q = select(self.GroupRelationsTable).filter(
                self.GroupRelationsTable.c.groupid == group_id
            )

        results = asyncio.run(self.conn.execute(q)).all()
        return results

    def remove_group_relations(self, user_id=None, group_id=None):
        q = delete(self.GroupRelationsTable)
        if user_id:
            q = q.filter(
                self.GroupRelationsTable.c.userid == user_id
            )
        elif group_id:
            q = q.filter(
                self.GroupRelationsTable.c.groupid == group_id
            )
        asyncio.run(self.conn.execute(q))

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

    def get_domain_controllers(self, domain=None):
        return self.get_computers(filter_term='dc', domain=domain)

    def is_share_valid(self, share_id):
        """
        Check if this share ID is valid.
        """
        q = select(self.SharesTable).filter(
            self.SharesTable.c.id == share_id
        )
        results = asyncio.run(self.conn.execute(q)).all()

        logging.debug(f"is_share_valid(shareID={share_id}) => {len(results) > 0}")
        return len(results) > 0

    def add_share(self, computer_id, user_id, name, remark, read, write):
        share_data = {
            "computerid": computer_id,
            "userid": user_id,
            "name": name,
            "remark": remark,
            "read": read,
            "write": write,
        }
        share_id = asyncio.run(self.conn.execute(
            insert(self.SharesTable).values(share_data).returning(self.SharesTable.c.id)
        )).scalar_one()

        return share_id

    def get_shares(self, filter_term=None):
        if self.is_share_valid(filter_term):
            q = select(self.SharesTable).filter(
                self.SharesTable.c.id == filter_term
            )
        elif filter_term:
            like_term = func.lower(f"%{filter_term}%")
            q = select(self.SharesTable).filter(
                self.SharesTable.c.name.like(like_term)
            )
        else:
            q = select(self.SharesTable)
        results = asyncio.run(self.conn.execute(q)).all()
        return results

    def get_shares_by_access(self, permissions, share_id=None):
        permissions = permissions.lower()
        q = select(self.SharesTable)
        if share_id:
            q = q.filter(self.SharesTable.c.id == share_id)
        if "r" in permissions:
            q = q.filter(self.SharesTable.c.read == 1)
        if "w" in permissions:
            q = q.filter(self.SharesTable.c.write == 1)
        results = asyncio.run(self.conn.execute(q)).all()
        return results

    def get_users_with_share_access(self, computer_id, share_name, permissions):
        permissions = permissions.lower()
        q = select(self.SharesTable.c.userid).filter(
            self.SharesTable.c.name == share_name,
            self.SharesTable.c.computerid == computer_id
        )
        if "r" in permissions:
            q = q.filter(self.SharesTable.c.read == 1)
        if "w" in permissions:
            q = q.filter(self.SharesTable.c.write == 1)
        results = asyncio.run(self.conn.execute(q)).all()

        return results

    def clear_database(self):
        for table in self.metadata.sorted_tables:
            asyncio.run(self.conn.execute(table.delete()))
