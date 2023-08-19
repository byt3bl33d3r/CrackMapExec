#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import warnings
from datetime import datetime
from pathlib import Path

from sqlalchemy import MetaData, func, Table, select, delete
from sqlalchemy.dialects.sqlite import Insert  # used for upsert
from sqlalchemy.exc import (
    IllegalStateChangeError,
    NoInspectionAvailable,
    NoSuchTableError,
)
from sqlalchemy.exc import SAWarning
from sqlalchemy.orm import sessionmaker, scoped_session

from cme.logger import cme_logger

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
        self.ConfChecksTable = None
        self.ConfChecksResultsTable = None
        self.DpapiBackupkey = None
        self.DpapiSecrets = None

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
            "hostname" text,
            "domain" text,
            "os" text,
            "dc" boolean,
            "smbv1" boolean,
            "signing" boolean,
            "spooler" boolean,
            "zerologon" boolean,
            "petitpotam" boolean
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "conf_checks" (
            "id" integer PRIMARY KEY,
            "name" text,
            "description" text
            )"""
        )

        db_conn.execute(
            """CREATE TABLE "conf_checks_results" (
            "id" integer PRIMARY KEY,
            "host_id" integer,
            "check_id" integer,
            "secure" boolean,
            "reasons" text,
            FOREIGN KEY(host_id) REFERENCES hosts(id),
            FOREIGN KEY(check_id) REFERENCES conf_checks(id)
            )
            """
        )

        # type = hash, plaintext
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
            """CREATE TABLE "groups" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "name" text,
            "rid" text,
            "member_count_ad" integer,
            "last_query_time" text
            )"""
        )
        # This table keeps track of which credential has admin access over which machine and vice-versa
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
            """CREATE TABLE "group_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "groupid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(groupid) REFERENCES groups(id)
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "shares" (
            "id" integer PRIMARY KEY,
            "hostid" text,
            "userid" integer,
            "name" text,
            "remark" text,
            "read" boolean,
            "write" boolean,
            FOREIGN KEY(userid) REFERENCES users(id)
            UNIQUE(hostid, userid, name)
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
        db_conn.execute(
            """CREATE TABLE "dpapi_secrets" (
            "id" integer PRIMARY KEY,
            "host" text,
            "dpapi_type" text,
            "windows_user" text,
            "username" text,
            "password" text,
            "url" text,
            UNIQUE(host, dpapi_type, windows_user, username, password, url)
        )"""
        )
        db_conn.execute(
            """CREATE TABLE "dpapi_backupkey" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "pvk" text,
            UNIQUE(domain)
        )"""
        )
        # db_conn.execute('''CREATE TABLE "ntds_dumps" (
        #    "id" integer PRIMARY KEY,
        #    "hostid", integer,
        #    "domain" text,
        #    "username" text,
        #    "hash" text,
        #    FOREIGN KEY(hostid) REFERENCES hosts(id)
        #    )''')

    def reflect_tables(self):
        with self.db_engine.connect() as conn:
            try:
                self.HostsTable = Table("hosts", self.metadata, autoload_with=self.db_engine)
                self.UsersTable = Table("users", self.metadata, autoload_with=self.db_engine)
                self.GroupsTable = Table("groups", self.metadata, autoload_with=self.db_engine)
                self.SharesTable = Table("shares", self.metadata, autoload_with=self.db_engine)
                self.AdminRelationsTable = Table("admin_relations", self.metadata, autoload_with=self.db_engine)
                self.GroupRelationsTable = Table("group_relations", self.metadata, autoload_with=self.db_engine)
                self.LoggedinRelationsTable = Table("loggedin_relations", self.metadata, autoload_with=self.db_engine)
                self.DpapiSecrets = Table("dpapi_secrets", self.metadata, autoload_with=self.db_engine)
                self.DpapiBackupkey = Table("dpapi_backupkey", self.metadata, autoload_with=self.db_engine)
                self.ConfChecksTable = Table("conf_checks", self.metadata, autoload_with=self.db_engine)
                self.ConfChecksResultsTable = Table("conf_checks_results", self.metadata, autoload_with=self.db_engine)
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

    # pull/545
    def add_host(
        self,
        ip,
        hostname,
        domain,
        os,
        smbv1,
        signing,
        spooler=None,
        zerologon=None,
        petitpotam=None,
        dc=None,
    ):
        """
        Check if this host has already been added to the database, if not, add it in.
        """
        hosts = []
        updated_ids = []

        q = select(self.HostsTable).filter(self.HostsTable.c.ip == ip)
        results = self.conn.execute(q).all()

        # create new host
        if not results:
            new_host = {
                "ip": ip,
                "hostname": hostname,
                "domain": domain,
                "os": os if os is not None else "",
                "dc": dc,
                "smbv1": smbv1,
                "signing": signing,
                "spooler": spooler,
                "zerologon": zerologon,
                "petitpotam": petitpotam,
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
                # only add host to be updated if it has changed
                if host_data not in hosts:
                    hosts.append(host_data)
                    updated_ids.append(host_data["id"])
        cme_logger.debug(f"Update Hosts: {hosts}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.HostsTable)  # .returning(self.HostsTable.c.id)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.HostsTable.primary_key, set_=update_columns)

        self.conn.execute(q, hosts)  # .scalar()
        # we only return updated IDs for now - when RETURNING clause is allowed we can return inserted
        if updated_ids:
            cme_logger.debug(f"add_host() - Host IDs Updated: {updated_ids}")
            return updated_ids

    def add_credential(self, credtype, domain, username, password, group_id=None, pillaged_from=None):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        credentials = []
        groups = []

        if (group_id and not self.is_group_valid(group_id)) or (pillaged_from and not self.is_host_valid(pillaged_from)):
            cme_logger.debug(f"Invalid group or host")
            return

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
                    groups.append({"userid": cred_data["id"], "groupid": group_id})
                if pillaged_from is not None:
                    cred_data["pillaged_from"] = pillaged_from
                # only add cred to be updated if it has changed
                if cred_data not in credentials:
                    credentials.append(cred_data)

        # TODO: find a way to abstract this away to a single Upsert call
        q_users = Insert(self.UsersTable)  # .returning(self.UsersTable.c.id)
        update_columns_users = {col.name: col for col in q_users.excluded if col.name not in "id"}
        q_users = q_users.on_conflict_do_update(index_elements=self.UsersTable.primary_key, set_=update_columns_users)
        cme_logger.debug(f"Adding credentials: {credentials}")

        self.conn.execute(q_users, credentials)  # .scalar()

        if groups:
            q_groups = Insert(self.GroupRelationsTable)

            self.conn.execute(q_groups, groups)
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

        if add_links:
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

    def get_credential(self, cred_type, domain, username, password):

        q = select(self.UsersTable).filter(
            self.UsersTable.c.domain == domain,
            self.UsersTable.c.username == username,
            self.UsersTable.c.password == password,
            self.UsersTable.c.credtype == cred_type,
        )
        results = self.conn.execute(q).first()
        return results.id

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

    def get_hosts(self, filter_term=None, domain=None):
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
        elif filter_term == "dc":
            q = q.filter(self.HostsTable.c.dc == True)
            if domain:
                q = q.filter(func.lower(self.HostsTable.c.domain) == func.lower(domain))
        elif filter_term == "signing":
            # generally we want hosts that are vulnerable, so signing disabled
            q = q.filter(self.HostsTable.c.signing == False)
        elif filter_term == "spooler":
            q = q.filter(self.HostsTable.c.spooler == True)
        elif filter_term == "zerologon":
            q = q.filter(self.HostsTable.c.zerologon == True)
        elif filter_term == "petitpotam":
            q = q.filter(self.HostsTable.c.petitpotam == True)
        elif filter_term is not None and filter_term.startswith("domain"):
            domain = filter_term.split()[1]
            like_term = func.lower(f"%{domain}%")
            q = q.filter(self.HostsTable.c.domain.like(like_term))
        # if we're filtering by ip/hostname
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = q.filter(self.HostsTable.c.ip.like(like_term) | func.lower(self.HostsTable.c.hostname).like(like_term))
        results = self.conn.execute(q).all()
        cme_logger.debug(f"smb hosts() - results: {results}")
        return results

    def is_group_valid(self, group_id):
        """
        Check if this group ID is valid.
        """
        q = select(self.GroupsTable).filter(self.GroupsTable.c.id == group_id)
        results = self.conn.execute(q).first()

        valid = True if results else False
        cme_logger.debug(f"is_group_valid(groupID={group_id}) => {valid}")

        return valid

    def add_group(self, domain, name, rid=None, member_count_ad=None):
        results = self.get_groups(group_name=name, group_domain=domain)

        groups = []
        updated_ids = []

        group_data = {
            "domain": domain,
            "name": name,
            "rid": rid,
            "member_count_ad": member_count_ad,
            "last_query_time": None,
        }

        if not results:
            if member_count_ad is not None:
                group_data["member_count_ad"] = member_count_ad
                today = datetime.now()
                iso_date = today.isoformat()
                group_data["last_query_time"] = iso_date
            groups = [group_data]

            # insert the group and get the returned id right away, this can be refactored when we can use RETURNING
            q = Insert(self.GroupsTable)

            self.conn.execute(q, groups)
            new_group_data = self.get_groups(group_name=group_data["name"], group_domain=group_data["domain"])
            returned_id = [new_group_data[0].id]
            cme_logger.debug(f"Inserted group with ID: {returned_id[0]}")
            return returned_id
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
                    updated_ids.append(g_data["id"])

        cme_logger.debug(f"Update Groups: {groups}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.GroupsTable)  # .returning(self.GroupsTable.c.id)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.GroupsTable.primary_key, set_=update_columns)

        self.conn.execute(q, groups)
        # TODO: always return a list and fix code references to not expect a single integer
        # inserted_result = res_inserted_result.first()
        # gid = inserted_result.id
        #
        # logger.debug(f"inserted_results: {inserted_result}\ntype: {type(inserted_result)}")
        # logger.debug('add_group(domain={}, name={}) => {}'.format(domain, name, gid))
        if updated_ids:
            cme_logger.debug(f"Updated groups with IDs: {updated_ids}")
        return updated_ids

    def get_groups(self, filter_term=None, group_name=None, group_domain=None):
        """
        Return groups from the database
        """

        if filter_term and self.is_group_valid(filter_term):
            q = select(self.GroupsTable).filter(self.GroupsTable.c.id == filter_term)
            results = self.conn.execute(q).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return [results]
        elif group_name and group_domain:
            q = select(self.GroupsTable).filter(
                func.lower(self.GroupsTable.c.name) == func.lower(group_name),
                func.lower(self.GroupsTable.c.domain) == func.lower(group_domain),
            )
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = select(self.GroupsTable).filter(self.GroupsTable.c.name.like(like_term))
        else:
            q = select(self.GroupsTable).filter()

        results = self.conn.execute(q).all()

        cme_logger.debug(f"get_groups(filter_term={filter_term}, groupName={group_name}, groupDomain={group_domain}) => {results}")
        return results

    def get_group_relations(self, user_id=None, group_id=None):
        if user_id and group_id:
            q = select(self.GroupRelationsTable).filter(
                self.GroupRelationsTable.c.id == user_id,
                self.GroupRelationsTable.c.groupid == group_id,
            )
        elif user_id:
            q = select(self.GroupRelationsTable).filter(self.GroupRelationsTable.c.id == user_id)
        elif group_id:
            q = select(self.GroupRelationsTable).filter(self.GroupRelationsTable.c.groupid == group_id)

        results = self.conn.execute(q).all()
        return results

    def remove_group_relations(self, user_id=None, group_id=None):
        q = delete(self.GroupRelationsTable)
        if user_id:
            q = q.filter(self.GroupRelationsTable.c.userid == user_id)
        elif group_id:
            q = q.filter(self.GroupRelationsTable.c.groupid == group_id)
        self.conn.execute(q)

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

    def get_domain_controllers(self, domain=None):
        return self.get_hosts(filter_term="dc", domain=domain)

    def is_share_valid(self, share_id):
        """
        Check if this share ID is valid.
        """
        q = select(self.SharesTable).filter(self.SharesTable.c.id == share_id)
        results = self.conn.execute(q).all()

        cme_logger.debug(f"is_share_valid(shareID={share_id}) => {len(results) > 0}")
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
        share_id = self.conn.execute(
            Insert(self.SharesTable).on_conflict_do_nothing(),  # .returning(self.SharesTable.c.id),
            share_data,
        )  # .scalar_one()
        # return share_id

    def get_shares(self, filter_term=None):
        if self.is_share_valid(filter_term):
            q = select(self.SharesTable).filter(self.SharesTable.c.id == filter_term)
        elif filter_term:
            like_term = func.lower(f"%{filter_term}%")
            q = select(self.SharesTable).filter(self.SharesTable.c.name.like(like_term))
        else:
            q = select(self.SharesTable)
        results = self.conn.execute(q).all()
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
        results = self.conn.execute(q).all()
        return results

    def get_users_with_share_access(self, host_id, share_name, permissions):
        permissions = permissions.lower()
        q = select(self.SharesTable.c.userid).filter(self.SharesTable.c.name == share_name, self.SharesTable.c.hostid == host_id)
        if "r" in permissions:
            q = q.filter(self.SharesTable.c.read == 1)
        if "w" in permissions:
            q = q.filter(self.SharesTable.c.write == 1)
        results = self.conn.execute(q).all()

        return results

    def add_domain_backupkey(self, domain: str, pvk: bytes):
        """
        Add domain backupkey
        :domain is the domain fqdn
        :pvk is the domain backupkey
        """
        q = select(self.DpapiBackupkey).filter(func.lower(self.DpapiBackupkey.c.domain) == func.lower(domain))
        results = self.conn.execute(q).all()

        if not len(results):
            pvk_encoded = base64.b64encode(pvk)
            backup_key = {"domain": domain, "pvk": pvk_encoded}
            try:
                # TODO: find a way to abstract this away to a single Upsert call
                q = Insert(self.DpapiBackupkey)  # .returning(self.DpapiBackupkey.c.id)

                self.conn.execute(q, [backup_key])  # .scalar()
                cme_logger.debug(f"add_domain_backupkey(domain={domain}, pvk={pvk_encoded})")
                # return inserted_id
            except Exception as e:
                cme_logger.debug(f"Issue while inserting DPAPI Backup Key: {e}")

    def get_domain_backupkey(self, domain: str = None):
        """
        Get domain backupkey
        :domain is the domain fqdn
        """
        q = select(self.DpapiBackupkey)
        if domain is not None:
            q = q.filter(func.lower(self.DpapiBackupkey.c.domain) == func.lower(domain))
        results = self.conn.execute(q).all()

        cme_logger.debug(f"get_domain_backupkey(domain={domain}) => {results}")

        if len(results) > 0:
            results = [(id_key, domain, base64.b64decode(pvk)) for id_key, domain, pvk in results]
        return results

    def is_dpapi_secret_valid(self, dpapi_secret_id):
        """
        Check if this group ID is valid.
        :dpapi_secret_id is a primary id
        """
        q = select(self.DpapiSecrets).filter(func.lower(self.DpapiSecrets.c.id) == dpapi_secret_id)
        results = self.conn.execute(q).first()
        valid = True if results is not None else False
        cme_logger.debug(f"is_dpapi_secret_valid(groupID={dpapi_secret_id}) => {valid}")
        return valid

    def add_dpapi_secrets(
        self,
        host: str,
        dpapi_type: str,
        windows_user: str,
        username: str,
        password: str,
        url: str = "",
    ):
        """
        Add dpapi secrets to cmedb
        """
        secret = {
            "host": host,
            "dpapi_type": dpapi_type,
            "windows_user": windows_user,
            "username": username,
            "password": password,
            "url": url,
        }
        q = Insert(self.DpapiSecrets).on_conflict_do_nothing()  # .returning(self.DpapiSecrets.c.id)

        self.conn.execute(q, [secret])  # .scalar()

        # inserted_result = res_inserted_result.first()
        # inserted_id = inserted_result.id

        cme_logger.debug(f"add_dpapi_secrets(host={host}, dpapi_type={dpapi_type}, windows_user={windows_user}, username={username}, password={password}, url={url})")

    def get_dpapi_secrets(
        self,
        filter_term=None,
        host: str = None,
        dpapi_type: str = None,
        windows_user: str = None,
        username: str = None,
        url: str = None,
    ):
        """
        Get dpapi secrets from cmedb
        """
        q = select(self.DpapiSecrets)

        if self.is_dpapi_secret_valid(filter_term):
            q = q.filter(self.DpapiSecrets.c.id == filter_term)
            results = self.conn.execute(q).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return [results]
        elif host:
            q = q.filter(self.DpapiSecrets.c.host == host)
            results = self.conn.execute(q).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return [results]
        elif dpapi_type:
            q = q.filter(func.lower(self.DpapiSecrets.c.dpapi_type) == func.lower(dpapi_type))
        elif windows_user:
            like_term = func.lower(f"%{windows_user}%")
            q = q.filter(func.lower(self.DpapiSecrets.c.windows_user).like(like_term))
        elif username:
            like_term = func.lower(f"%{username}%")
            q = q.filter(func.lower(self.DpapiSecrets.c.windows_user).like(like_term))
        elif url:
            q = q.filter(func.lower(self.DpapiSecrets.c.url) == func.lower(url))
        results = self.conn.execute(q).all()

        cme_logger.debug(f"get_dpapi_secrets(filter_term={filter_term}, host={host}, dpapi_type={dpapi_type}, windows_user={windows_user}, username={username}, url={url}) => {results}")
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
                cme_logger.debug(f"Inserting loggedin_relations: {relation}")
                # TODO: find a way to abstract this away to a single Upsert call
                q = Insert(self.LoggedinRelationsTable)  # .returning(self.LoggedinRelationsTable.c.id)

                self.conn.execute(q, [relation])  # .scalar()
                inserted_id_results = self.get_loggedin_relations(user_id, host_id)
                cme_logger.debug(f"Checking if relation was added: {inserted_id_results}")
                return inserted_id_results[0].id
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

    def get_checks(self):
        q = select(self.ConfChecksTable)
        return self.conn.execute(q).all()
        
    def get_check_results(self):
        q = select(self.ConfChecksResultsTable)
        return self.conn.execute(q).all()
        
    def insert_data(self, table, select_results=[], **new_row):
        """
        Insert a new row in the given table.
        Basically it's just a more generic version of add_host
        """
        results = []
        updated_ids = []

        # Create new row
        if not select_results:
            results = [new_row]
        # Update existing row data
        else:
            for row in select_results:
                row_data = row._asdict()
                for column,value in new_row.items():
                    row_data[column] = value

                # Only add data to be updated if it has changed
                if row_data not in results:
                    results.append(row_data)
                    updated_ids.append(row_data['id'])

        cme_logger.debug(f'Update data: {results}')
        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(table) # .returning(table.c.id)
        update_column = {col.name: col for col in q.excluded if col.name not in 'id'}
        q = q.on_conflict_do_update(index_elements=table.primary_key, set_=update_column)
        self.conn.execute(q, results) # .scalar()
        # we only return updated IDs for now - when RETURNING clause is allowed we can return inserted
        return updated_ids

    def add_check(self, name, description):
        """
        Check if this check item has already been added to the database, if not, add it in.
        """
        q = select(self.ConfChecksTable).filter(self.ConfChecksTable.c.name == name)
        select_results = self.conn.execute(q).all()
        context = locals()
        new_row = dict(((column, context[column]) for column in ('name', 'description')))
        updated_ids = self.insert_data(self.ConfChecksTable, select_results, **new_row)

        if updated_ids:
            cme_logger.debug(f"add_check() - Checks IDs Updated: {updated_ids}")
            return updated_ids

    def add_check_result(self, host_id, check_id, secure, reasons):
        """
        Check if this check result has already been added to the database, if not, add it in.
        """
        q = select(self.ConfChecksResultsTable).filter(self.ConfChecksResultsTable.c.host_id == host_id, self.ConfChecksResultsTable.c.check_id == check_id)
        select_results = self.conn.execute(q).all()
        context = locals()
        new_row = dict(((column, context[column]) for column in ('host_id', 'check_id', 'secure', 'reasons')))
        updated_ids = self.insert_data(self.ConfChecksResultsTable, select_results, **new_row)

        if updated_ids:
            cme_logger.debug(f"add_check_result() - Check Results IDs Updated: {updated_ids}")
            return updated_ids
