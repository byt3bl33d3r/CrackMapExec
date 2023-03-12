#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
from sqlalchemy import MetaData, func, Table, select, update, delete
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


class database:
    def __init__(self, db_engine):
        self.HostsTable = None
        self.UsersTable = None
        self.GroupsTable = None
        self.SharesTable = None
        self.AdminRelationsTable = None
        self.GroupRelationsTable = None
        self.LoggedinRelationsTable = None

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
        db_conn.execute('''CREATE TABLE "hosts" (
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
            "pillaged_from_hostid" integer,
            FOREIGN KEY(pillaged_from_hostid) REFERENCES hosts(id)
            )''')
        db_conn.execute('''CREATE TABLE "groups" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "name" text,
            "rid" text,
            "member_count_ad" integer,
            "last_query_time" text
            )''')
        # This table keeps track of which credential has admin access over which machine and vice-versa
        db_conn.execute('''CREATE TABLE "admin_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "hostid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
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
            "hostid" text,
            "userid" integer,
            "name" text,
            "remark" text,
            "read" boolean,
            "write" boolean,
            FOREIGN KEY(userid) REFERENCES users(id)
            UNIQUE(hostid, userid, name)
        )''')
        db_conn.execute('''CREATE TABLE "loggedin_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "hostid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
        )''')
        db_conn.execute('''CREATE TABLE "dpapi_secrets" (
            "id" integer PRIMARY KEY,
            "computer" text,
            "dpapi_type" text,
            "windows_user" text,
            "username" text,
            "password" text,
            "url" text,
            UNIQUE(computer, dpapi_type, windows_user, username, password, url)
        )''')
        db_conn.execute('''CREATE TABLE "dpapi_backupkey" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "pvk" text,
            UNIQUE(domain)
        )''')
        # db_conn.execute('''CREATE TABLE "ntds_dumps" (
        #    "id" integer PRIMARY KEY,
        #    "hostid", integer,
        #    "domain" text,
        #    "username" text,
        #    "hash" text,
        #    FOREIGN KEY(hostid) REFERENCES hosts(id)
        #    )''')

    async def reflect_tables(self):
        async with self.db_engine.connect() as conn:
            await conn.run_sync(self.metadata.reflect)

            self.HostsTable = Table("hosts", self.metadata, autoload_with=self.db_engine)
            self.UsersTable = Table("users", self.metadata, autoload_with=self.db_engine)
            self.GroupsTable = Table("groups", self.metadata, autoload_with=self.db_engine)
            self.SharesTable = Table("shares", self.metadata, autoload_with=self.db_engine)
            self.AdminRelationsTable = Table("admin_relations", self.metadata, autoload_with=self.db_engine)
            self.GroupRelationsTable = Table("group_relations", self.metadata, autoload_with=self.db_engine)
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

    # pull/545
    def add_host(self, ip, hostname, domain, os, smbv1, signing, spooler=None, zerologon=None, petitpotam=None, dc=None):
        """
        Check if this host has already been added to the database, if not, add it in.
        """
        domain = domain.split('.')[0]
        hosts = []

        q = select(self.HostsTable).filter(
            self.HostsTable.c.ip == ip
        )
        results = asyncio.run(self.conn.execute(q)).all()

        # create new host
        if not results:
            new_host = {
                "ip": ip,
                "hostname": hostname,
                "domain": domain,
                "os": os if os is not None else '',
                "dc": dc,
                "smbv1": smbv1,
                "signing": signing,
                "spooler": spooler,
                "zerologon": zerologon,
                "petitpotam": petitpotam
            }
            hosts = [new_host]
        # update existing hosts data
        else:
            for host in results:
                host_data = host._asdict()
                # only update column if it is being passed in
                if ip is not None:
                    host_data["ip"] = ip
                if hostname is not None:
                    host_data["hostname"] = hostname
                if domain is not None:
                    host_data["domain"] = domain
                if os is not None:
                    host_data["os"] = os
                if smbv1 is not None:
                    host_data["smbv1"] = smbv1
                if signing is not None:
                    host_data["signing"] = signing
                if spooler is not None:
                    host_data["spooler"] = spooler
                if zerologon is not None:
                    host_data["zerologon"] = zerologon
                if petitpotam is not None:
                    host_data["petitpotam"] = petitpotam
                if dc is not None:
                    host_data["dc"] = dc
                # only add computer to be updated if it has changed
                if host_data not in hosts:
                    hosts.append(host_data)
        logging.debug(f"Update Hosts: {hosts}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.HostsTable).returning(self.HostsTable.c.id)
        update_columns = {col.name: col for col in q.excluded if col.name not in 'id'}
        q = q.on_conflict_do_update(
            index_elements=self.HostsTable.primary_key,
            set_=update_columns
        )
        added_host_ids = asyncio.run(
            self.conn.execute(
                q,
                hosts
            )
        ).scalar()
        logging.debug(f"add_host() - Host IDs Added or Updated: {added_host_ids}")
        return added_host_ids

    def add_credential(self, credtype, domain, username, password, group_id=None, pillaged_from=None):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        domain = domain.split('.')[0]
        credentials = []
        groups = []

        if (group_id and not self.is_group_valid(group_id)) or \
                (pillaged_from and not self.is_host_valid(pillaged_from)):
            logging.debug(f"Invalid group or host")
            return

        q = select(self.UsersTable).filter(
            func.lower(self.UsersTable.c.domain) == func.lower(domain),
            func.lower(self.UsersTable.c.username) == func.lower(username),
            func.lower(self.UsersTable.c.credtype) == func.lower(credtype)
        )
        results = asyncio.run(self.conn.execute(q)).all()

        # add new credential
        if not results:
            new_cred = {
                "credtype": credtype,
                "domain": domain,
                "username": username,
                "password": password,
                "groupid": group_id,
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
                if group_id is not None:
                    cred_data["groupid"] = group_id
                    groups.append({
                        "userid": cred_data["id"],
                        "groupid": group_id
                    })
                if pillaged_from is not None:
                    cred_data["pillaged_from"] = pillaged_from
                # only add cred to be updated if it has changed
                if cred_data not in credentials:
                    credentials.append(cred_data)

        # TODO: find a way to abstract this away to a single Upsert call
        q_users = Insert(self.UsersTable).returning(self.UsersTable.c.id)
        update_columns_users = {col.name: col for col in q_users.excluded if col.name not in 'id'}
        q_users = q_users.on_conflict_do_update(
            index_elements=self.UsersTable.primary_key,
            set_=update_columns_users
        )
        user_ids = asyncio.run(
            self.conn.execute(
                q_users,
                credentials
            )
        ).scalar()

        if groups:
            q_groups = Insert(self.GroupRelationsTable)
            asyncio.run(
                self.conn.execute(
                    q_groups,
                    groups
                )
            )
        return user_ids

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
        domain = domain.split('.')[0]
        add_links = []

        creds_q = select(self.UsersTable)
        if user_id:
            creds_q = creds_q.filter(
                self.UsersTable.c.id == user_id
            )
        else:
            creds_q = creds_q.filter(
                func.lower(self.UsersTable.c.credtype) == func.lower(credtype),
                func.lower(self.UsersTable.c.domain) == func.lower(domain),
                func.lower(self.UsersTable.c.username) == func.lower(username),
                self.UsersTable.c.password == password
            )
        users = asyncio.run(self.conn.execute(creds_q))
        hosts = self.get_hosts(host)

        if users and hosts:
            for user, host in zip(users, hosts):
                user_id = user[0]
                host_id = host[0]
                link = {
                    "userid": user_id,
                    "hostid": host_id
                }
                admin_relations_select = select(self.AdminRelationsTable).filter(
                    self.AdminRelationsTable.c.userid == user_id,
                    self.AdminRelationsTable.c.hostid == host_id
                )
                links = asyncio.run(self.conn.execute(admin_relations_select)).all()

                if not links:
                    add_links.append(link)

        admin_relations_insert = Insert(self.AdminRelationsTable)

        asyncio.run(self.conn.execute(
            admin_relations_insert,
            add_links
        ))

    def get_admin_relations(self, user_id=None, host_id=None):
        if user_id:
            q = select(self.AdminRelationsTable).filter(
                self.AdminRelationsTable.c.userid == user_id
            )
        elif host_id:
            q = select(self.AdminRelationsTable).filter(
                self.AdminRelationsTable.c.hostid == host_id
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
            q = select(self.HostsTable).filter(
                func.lower(self.HostsTable.c.id) == func.lower(user_domain)
            )
            results = asyncio.run(self.conn.execute(q)).all()

            return len(results) > 0

    def is_host_valid(self, host_id):
        """
        Check if this host ID is valid.
        """
        q = select(self.HostsTable).filter(
            self.HostsTable.c.id == host_id
        )
        results = asyncio.run(self.conn.execute(q)).all()
        return len(results) > 0

    def get_hosts(self, filter_term=None, domain=None):
        """
        Return hosts from the database.
        """
        q = select(self.HostsTable)

        # if we're returning a single host by ID
        if self.is_host_valid(filter_term):
            q = q.filter(
                self.HostsTable.c.id == filter_term
            )
            results = asyncio.run(self.conn.execute(q)).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return [results]
        # if we're filtering by domain controllers
        elif filter_term == 'dc':
            q = q.filter(
                self.HostsTable.c.dc == True
            )
            if domain:
                q = q.filter(
                    func.lower(self.HostsTable.c.domain) == func.lower(domain)
                )
        elif filter_term == 'spooler':
            q = q.filter(
                self.HostsTable.c.spooler == True
            )
        elif filter_term == 'zerologon':
            q = q.filter(
                self.HostsTable.c.zerologon == True
            )
        elif filter_term == 'petitpotam':
            q = q.filter(
                self.HostsTable.c.petitpotam == True
            )
        elif filter_term is not None and filter_term.startswith('domain'):
            domain = filter_term.split()[1]
            like_term = func.lower(f"%{domain}%")
            q = q.filter(
                self.HostsTable.c.domain.like(like_term)
            )
        # if we're filtering by ip/hostname
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = q.filter(
                self.HostsTable.c.ip.like(like_term) |
                func.lower(self.HostsTable.c.hostname).like(like_term)
            )
        results = asyncio.run(self.conn.execute(q)).all()
        logging.debug(f"smb hosts() - results: {results}")
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

    def add_group(self, domain, name, rid=None, member_count_ad=None):
        domain = domain.split('.')[0]
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
            "rid": rid
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
                if rid is not None:
                    g_data["rid"] = rid
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
            group_domain = group_domain.split('.')[0]

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

        logging.debug(
            f"get_groups(filterTerm={filter_term}, groupName={group_name}, groupDomain={group_domain}) => {results}")
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
        return self.get_hosts(filter_term='dc', domain=domain)

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

    def add_share(self, host_id, user_id, name, remark, read, write):
        share_data = {
            "hostid": host_id,
            "userid": user_id,
            "name": name,
            "remark": remark,
            "read": read,
            "write": write,
        }
        share_id = asyncio.run(self.conn.execute(
            Insert(self.SharesTable).returning(self.SharesTable.c.id),
            share_data
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

    def get_users_with_share_access(self, host_id, share_name, permissions):
        permissions = permissions.lower()
        q = select(self.SharesTable.c.userid).filter(
            self.SharesTable.c.name == share_name,
            self.SharesTable.c.hostid == host_id
        )
        if "r" in permissions:
            q = q.filter(self.SharesTable.c.read == 1)
        if "w" in permissions:
            q = q.filter(self.SharesTable.c.write == 1)
        results = asyncio.run(self.conn.execute(q)).all()

        return results

    def add_domain_backupkey(self, domain:str, pvk:bytes):
        """
        Add domain backupkey
        :domain is the domain fqdn
        :pvk is the domain backupkey
        """
        cur = self.conn.cursor()

        cur.execute("SELECT * FROM dpapi_backupkey WHERE LOWER(domain)=LOWER(?)", [domain])
        results = cur.fetchall()

        if not len(results):
            import base64
            pvk_encoded = base64.b64encode(pvk)
            cur.execute("INSERT INTO dpapi_backupkey (domain, pvk) VALUES (?,?)", [domain, pvk_encoded])

        cur.close()

        logging.debug('add_domain_backupkey(domain={}, pvk={}) => {}'.format(domain, pvk_encoded, cur.lastrowid))

    def get_domain_backupkey(self, domain:str = None):
        """
        Get domain backupkey
        :domain is the domain fqdn
        """
        cur = self.conn.cursor()

        if domain is not None:
            cur.execute("SELECT * FROM dpapi_backupkey WHERE LOWER(domain)=LOWER(?)", [domain])
        else:
            cur.execute("SELECT * FROM dpapi_backupkey", [domain])
        results = cur.fetchall()
        cur.close()
        logging.debug('get_domain_backupkey(domain={}) => {}'.format(domain, results))
        if len(results) >0:
            import base64
            results = [(idkey, domain, base64.b64decode(pvk)) for idkey, domain, pvk in results]
        return results

    def is_dpapi_secret_valid(self, dpapiSecretID):
        """
        Check if this group ID is valid.
        :dpapiSecretID is a primary id
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM dpapi_secrets WHERE id=? LIMIT 1', [dpapiSecretID])
        results = cur.fetchall()
        cur.close()

        logging.debug('is_dpapi_secret_valid(groupID={}) => {}'.format(dpapiSecretID, True if len(results) else False))
        return len(results) > 0

    def add_dpapi_secrets(self, computer:str, dpapi_type:str, windows_user:str, username:str, password:str, url:str=''):
        """
        Add dpapi secrets to cmedb
        """
        cur = self.conn.cursor()
        cur.execute("INSERT OR IGNORE INTO dpapi_secrets (computer, dpapi_type, windows_user, username, password, url) VALUES (?,?,?,?,?,?)", [computer, dpapi_type, windows_user, username, password, url])
        cur.close()

        logging.debug('add_dpapi_secrets(computer={}, dpapi_type={}, windows_user={}, username={}, password={}, url={}) => {}'.format(computer, dpapi_type, windows_user, username, password, url, cur.lastrowid))

    def get_dpapi_secrets(self, filterTerm=None, computer:str=None, dpapi_type:str=None, windows_user:str=None, username:str=None, url:str=None):
        """
        Get dpapi secrets from cmedb
        """
        cur = self.conn.cursor()
        if self.is_dpapi_secret_valid(filterTerm):
            cur.execute("SELECT * FROM dpapi_secrets WHERE id=? LIMIT 1", [filterTerm])
        elif computer:
            cur.execute("SELECT * FROM dpapi_secrets WHERE computer=? LIMIT 1", [computer])
        elif dpapi_type:
            cur.execute('SELECT * FROM dpapi_secrets WHERE LOWER(dpapi_type)=LOWER(?)', [dpapi_type])
        elif windows_user:
            cur.execute('SELECT * FROM dpapi_secrets WHERE LOWER(windows_user) LIKE LOWER(?)', [windows_user])
        elif username:
            cur.execute('SELECT * FROM dpapi_secrets WHERE LOWER(windows_user) LIKE LOWER(?)', [username])
        elif url:
            cur.execute('SELECT * FROM dpapi_secrets WHERE LOWER(url)=LOWER(?)', [url])
        else:
            cur.execute("SELECT * FROM dpapi_secrets")
        results = cur.fetchall()
        cur.close()
        logging.debug('get_dpapi_secrets(filterTerm={}, computer={}, dpapi_type={}, windows_user={}, username={}, url={}) => {}'.format(filterTerm, computer, dpapi_type, windows_user, username, url, results))
        return results

    def add_loggedin_relation(self, user_id, host_id):
        relation_query = select(self.LoggedinRelationsTable).filter(
            self.LoggedinRelationsTable.c.userid == user_id,
            self.LoggedinRelationsTable.c.hostid == host_id
        )
        results = asyncio.run(self.conn.execute(relation_query)).all()

        # only add one if one doesn't already exist
        if not results:
            relation = {
                "userid": user_id,
                "hostid": host_id
            }
            try:
                # TODO: find a way to abstract this away to a single Upsert call
                q = Insert(self.LoggedinRelationsTable).returning(self.LoggedinRelationsTable.c.id)
                inserted_ids = asyncio.run(
                    self.conn.execute(
                        q,
                        [relation]
                    )
                ).scalar()
                return inserted_ids
            except Exception as e:
                logging.debug(f"Error inserting LoggedinRelation: {e}")

    def get_loggedin_relations(self, user_id=None, host_id=None):
        q = select(self.LoggedinRelationsTable).returning(self.LoggedinRelationsTable.c.id)
        if user_id:
            q = q.filter(
                self.LoggedinRelationsTable.c.userid == user_id
            )
        if host_id:
            q = q.filter(
                self.LoggedinRelationsTable.c.hostid == host_id
            )
        results = asyncio.run(self.conn.execute(q)).all()
        return results

    def remove_loggedin_relations(self, user_id=None, host_id=None):
        q = delete(self.LoggedinRelationsTable)
        if user_id:
            q = q.filter(
                self.LoggedinRelationsTable.c.userid == user_id
            )
        elif host_id:
            q = q.filter(
                self.LoggedinRelationsTable.c.hostid == host_id
            )
        asyncio.run(self.conn.execute(q))
