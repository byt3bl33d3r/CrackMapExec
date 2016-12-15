class database:

    def __init__(self, conn):
        self.conn = conn

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute('''CREATE TABLE "computers" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "hostname" text,
            "domain" text,
            "os" text,
            "dc" boolean
            )''')

        # type = hash, plaintext
        db_conn.execute('''CREATE TABLE "credentials" (
            "id" integer PRIMARY KEY,
            "userid", integer,
            "credtype" text,
            "password" text,
            "pillaged_from_computerid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id)
            )''')

        db_conn.execute('''CREATE TABLE "users" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "username" text,
            "local" boolean,
            )''')

        db_conn.execute('''CREATE TABLE "groups" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "name" text
            )''')

        db_conn.execute('''CREATE TABLE "ntds_dumps" (
            "id" integer PRIMARY KEY,
            "computerid", integer,
            "domain" text,
            "username" text,
            "hash" text,
            FOREIGN KEY(computerid) REFERENCES computers(id)
            )''')

        #This table keeps track of which credential has admin access over which machine and vice-versa
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

        #db_conn.execute('''CREATE TABLE "shares" (
        #    "id" integer PRIMARY KEY,
        #    "hostid" integer,
        #    "name" text,
        #    "remark" text,
        #    "read" boolean,
        #    "write" boolean
        #    )''')

    #def add_share(self, hostid, name, remark, read, write):
    #    cur = self.conn.cursor()

    #    cur.execute("INSERT INTO shares (hostid, name, remark, read, write) VALUES (?,?,?,?,?)", [hostid, name, remark, read, write])

    #    cur.close()

    def add_host(self, ip, hostname, domain, os, dc=False):
        """
        Check if this host has already been added to the database, if not add it in.
        """
        cur = self.conn.cursor()

        cur.execute('SELECT * FROM computers WHERE ip LIKE ?', [ip])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO computers (ip, hostname, domain, os, dc) VALUES (?,?,?,?,?)", [ip, hostname, domain, os, dc])

        cur.close()

    def add_credential(self, credtype, domain, username, password, pillaged_from='NULL', local=False, userID=None):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        self.add_user(domain, username, local)

        cur = self.conn.cursor()

        cur.execute("SELECT * FROM users WHERE LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?) AND local=?", [domain, username, local])
        results = cur.fetchall()
        for user in results:
            userid = user[0]
            cur.execute("SELECT * from credentials WHERE userid=? AND credtype=? AND password=?", [userid, credtype, password])
            results=cur.fetchall()
            if not len(results):
                cur.execute("INSERT INTO credentials (userid, credtype, password, pillaged_from_computerid) VALUES (?,?,?,?)", [userid, credtype, password, pillaged_from] )

        cur.close()

    def add_user(self, domain, username, local=False):
        cur = self.conn.cursor()

        cur.execute("SELECT * FROM users WHERE LOWER(domain)=LOWER(?) and LOWER(username)=LOWER(?) and local=(?)", [domain, username, local])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO users (domain, username, local) VALUES (?,?,?)", [domain, username, local])

        cur.close()

    def add_group(self, domain, name):

        cur = self.conn.cursor()

        cur.execute("SELECT * FROM groups WHERE LOWER(domain)=LOWER(?) AND LOWER(name)=LOWER(?)", [domain, name])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO groups (domain, name) VALUES (?,?)", [domain, name])

        cur.close()

    def add_ntds_hash(self, hostid, domain, username, hash):

        cur = self.conn.cursor()

        cur.execute("INSERT INTO ntds (dcid, domain, username, hash) VALUES (?,?,?,?)", [hostid, domain, username, hash])

        cur.close()

    def remove_credentials(self, credIDs):
        """
        Removes a credential ID from the database
        """
        for credID in credIDs:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM credentials WHERE id=?", [credID])
            cur.close()

    def add_admin_user(self, userid, host):

        cur = self.conn.cursor()

        cur.execute("SELECT * FROM users WHERE userid=?", [userid])
        users = cur.fetchall()

        cur.execute('SELECT * FROM computers WHERE ip LIKE ?', [host])
        hosts = cur.fetchall()

        if len(users) and len(hosts):
            for user, host in zip(users, hosts):
                userid = user[0]
                hostid = host[0]

                #Check to see if we already added this link
                cur.execute("SELECT * FROM admin_relations WHERE userid=? AND computerid=?", [userid, hostid])
                links = cur.fetchall()

                if not len(links):
                    cur.execute("INSERT INTO admin_relations (userid, computerid) VALUES (?,?)", [userid, hostid])

        cur.close()

    def get_admin_relations(self, userID=None, hostID=None):

        cur = self.conn.cursor()

        if userID:
            cur.execute("SELECT * from admin_relations WHERE userid=?", [userID])

        elif hostID:
            cur.execute("SELECT * from admin_relations WHERE computerid=?", [hostID])

        results = cur.fetchall()
        cur.close()
        return results

    def remove_admin_relation(self, userIDs=None, hostIDs=None):

        cur = self.conn.cursor()

        if userIDs:
            for userID in userIDs:
                cur.execute("DELETE FROM admin_relations WHERE userid=?", [userID])

        elif hostIDs:
            for hostID in hostIDs:
                cur.execute("DELETE FROM admin_relations WHERE hostid=?", [hostID])

        cur.close()

    def is_credential_valid(self, credentialID):
        """
        Check if this credential ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM credentials WHERE id=? LIMIT 1', [credentialID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0

    def get_credentials(self, filterTerm=None, credtype=None, userID=None):
        """
        Return credentials from the database.
        """

        cur = self.conn.cursor()

        # if we're returning a single credential by ID
        if self.is_credential_valid(filterTerm):
            cur.execute("SELECT * FROM credentials WHERE id=? LIMIT 1", [filterTerm])

        # if we're filtering by credtype
        elif credtype:
            cur.execute("SELECT * FROM credentials WHERE credtype=?", [credtype])

        elif userID:
            cur.execute("SELECT * FROM credentials WHERE userid=?", [userID])

        # otherwise return all credentials
        else:
            cur.execute("SELECT * FROM credentials")

        results = cur.fetchall()
        cur.close()
        return results

    def is_user_valid(self, userID):
        """
        Check if this User ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM users WHERE id=? LIMIT 1', [userID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0

    def get_users(self, filterTerm=None):

        cur = self.conn.cursor()

        if self.is_user_valid(filterTerm):
            cur.execute("SELECT * FROM users WHERE id=? LIMIT 1", [filterTerm])

        # if we're filtering by username
        elif filterTerm and filterTerm != '':
            cur.execute("SELECT * FROM users WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])

        else:
            cur.execute("SELECT * FROM users")

        results = cur.fetchall()
        cur.close()
        return results

    def is_host_valid(self, hostID):
        """
        Check if this host ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM computers WHERE id=? LIMIT 1', [hostID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0

    def get_hosts(self, filterTerm=None):
        """
        Return hosts from the database.
        """

        cur = self.conn.cursor()

        # if we're returning a single host by ID
        if self.is_host_valid(filterTerm):
            cur.execute("SELECT * FROM computers WHERE id=? LIMIT 1", [filterTerm])

        # if we're filtering by ip/hostname
        elif filterTerm and filterTerm != "":
            cur.execute("SELECT * FROM computers WHERE ip LIKE ? OR LOWER(hostname) LIKE LOWER(?)", ['%{}%'.format(filterTerm), '%{}%'.format(filterTerm)])

        # otherwise return all credentials
        else:
            cur.execute("SELECT * FROM computers")

        results = cur.fetchall()
        cur.close()
        return results

    def get_group_members(self, groupID):
        cur = self.conn.cursor()

        cur.execute("SELECT * from group_relations WHERE groupid=?", [groupID])

        results = cur.fetchall()
        cur.close()
        return results

    def is_group_valid(self, groupID):
        """
        Check if this group ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM groups WHERE id=? LIMIT 1', [groupID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0

    def get_groups(self, filterTerm=None):
        """
        Return groups from the database
        """

        cur = self.conn.cursor()

        if self.is_group_valid(filterTerm):
            cur.execute("SELECT * FROM groups WHERE id=? LIMIT 1", [filterTerm])

        elif filterTerm and filterTerm !="":
            cur.execute("SELECT * FROM groups WHERE LOWER(name) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])

        else:
            cur.execute("SELECT * FROM groups")

        results = cur.fetchall()
        cur.close()
        return results
