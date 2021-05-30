import logging


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
            "name" text
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
            "computerid" integer,
            "userid" integer,
            "name" text,
            "remark" text,
            "read" boolean,
            "write" boolean,
            FOREIGN KEY(computerid) REFERENCES computers(id),
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

    def add_share(self, computerid, userid, name, remark, read, write):
        cur = self.conn.cursor()
        cur.execute("INSERT OR IGNORE INTO shares (computerid, userid, name, remark, read, write) VALUES (?,?,?,?,?,?)", [computerid, userid, name, remark, read, write])
        cur.close()

    def is_share_valid(self, shareID):
        """
        Check if this share ID is valid.
        """

        cur = self.conn.cursor()
        cur.execute('SELECT * FROM shares WHERE id=? LIMIT 1', [shareID])
        results = cur.fetchall()
        cur.close()

        logging.debug(f"is_share_valid(shareID={shareID}) => {len(results) > 0}")
        return len(results) > 0
    
    def get_shares(self, filterTerm = None):
        cur = self.conn.cursor()

        if self.is_share_valid(filterTerm):
            cur.execute("SELECT * FROM shares WHERE id=?", [filterTerm])
        elif filterTerm:
            cur.execute("SELECT * FROM shares WHERE LOWER(name) LIKE LOWER(?)", [f"%{filterTerm}%"])
        else:
            cur.execute("SELECT * FROM shares")

        results = cur.fetchall()
        return results

    def get_shares_by_access(self, permissions, shareID=None):
        cur = self.conn.cursor()
        permissions = permissions.lower()

        if shareID:
            if permissions == "r":
                cur.execute("SELECT * FROM shares WHERE id=? AND read=1",[shareID])
            elif permissions == "w":
                cur.execute("SELECT * FROM shares WHERE id=? write=1", [shareID])
            elif permissions == "rw":
                cur.execute("SELECT * FROM shares WHERE id=? AND read=1 AND write=1", [shareID])
        else:
            if permissions == "r":
                cur.execute("SELECT * FROM shares WHERE read=1")
            elif permissions == "w":
                cur.execute("SELECT * FROM shares WHERE write=1")
            elif permissions == "rw":
                cur.execute("SELECT * FROM shares WHERE read= AND write=1")

        results = cur.fetchall()
        return results

    def get_users_with_share_access(self, computerID, share_name, permissions):
        cur = self.conn.cursor()
        permissions = permissions.lower()

        if permissions == "r":
            cur.execute("SELECT userid FROM shares WHERE computerid=(?) AND name=(?) AND read=1", [computerID, share_name])
        elif permissions == "w":
            cur.execute("SELECT userid FROM shares WHERE computerid=(?) AND name=(?) AND write=1", [computerID, share_name])
        elif permissions == "rw":
            cur.execute("SELECT userid FROM shares WHERE computerid=(?) AND name=(?) AND read=1 AND write=1", [computerID, share_name])

        results = cur.fetchall()
        return results

    def add_computer(self, ip, hostname, domain, os, dc=None):
        """
        Check if this host has already been added to the database, if not add it in.
        """
        domain = domain.split('.')[0].upper()
        cur = self.conn.cursor()

        cur.execute('SELECT * FROM computers WHERE ip LIKE ?', [ip])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO computers (ip, hostname, domain, os, dc) VALUES (?,?,?,?,?)", [ip, hostname, domain, os, dc])
        else:
            for host in results:
                if (hostname != host[2]) or (domain != host[3]) or (os != host[4]):
                    cur.execute("UPDATE computers SET hostname=?, domain=?, os=? WHERE id=?", [hostname, domain, os, host[0]])
                if dc != None and (dc != host[5]):
                    cur.execute("UPDATE computers SET dc=? WHERE id=?", [dc, host[0]])

        cur.close()

        return cur.lastrowid

    def add_credential(self, credtype, domain, username, password, groupid=None, pillaged_from=None):
        """
        Check if this credential has already been added to the database, if not add it in.
        """

        domain = domain.split('.')[0].upper()
        user_rowid = None
        cur = self.conn.cursor()

        if groupid and not self.is_group_valid(groupid):
            cur.close()
            return

        if pillaged_from and not self.is_computer_valid(pillaged_from):
            cur.close()
            return

        cur.execute("SELECT * FROM users WHERE LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?) AND LOWER(credtype)=LOWER(?)", [domain, username, credtype])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO users (domain, username, password, credtype, pillaged_from_computerid) VALUES (?,?,?,?,?)", [domain, username, password, credtype, pillaged_from])
            user_rowid = cur.lastrowid
            if groupid:
                cur.execute("INSERT INTO group_relations (userid, groupid) VALUES (?,?)", [user_rowid, groupid])
        else:
            for user in results:
                if not user[3] and not user[4] and not user[5]:
                    cur.execute('UPDATE users SET password=?, credtype=?, pillaged_from_computerid=? WHERE id=?', [password, credtype, pillaged_from, user[0]])
                    user_rowid = cur.lastrowid
                    if groupid and not len(self.get_group_relations(user_rowid, groupid)):
                        cur.execute("INSERT INTO group_relations (userid, groupid) VALUES (?,?)", [user_rowid, groupid])

        cur.close()

        logging.debug('add_credential(credtype={}, domain={}, username={}, password={}, groupid={}, pillaged_from={}) => {}'.format(credtype, domain, username, password, groupid, pillaged_from, user_rowid))

        return user_rowid

    def add_user(self, domain, username, groupid=None):

        if groupid and not self.is_group_valid(groupid):
            return

        domain = domain.split('.')[0].upper()
        user_rowid = None
        cur = self.conn.cursor()

        cur.execute("SELECT * FROM users WHERE LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?)", [domain, username])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO users (domain, username, password, credtype, pillaged_from_computerid) VALUES (?,?,?,?,?)", [domain, username, '', '', ''])
            user_rowid = cur.lastrowid
            if groupid:
                cur.execute("INSERT INTO group_relations (userid, groupid) VALUES (?,?)", [user_rowid, groupid])
        else:
            for user in results:
                if (domain != user[1]) and (username != user[2]):
                    cur.execute("UPDATE users SET domain=?, user=? WHERE id=?", [domain, username, user[0]])
                    user_rowid = cur.lastrowid

                if not user_rowid: user_rowid = user[0]
                if groupid and not len(self.get_group_relations(user_rowid, groupid)):
                    cur.execute("INSERT INTO group_relations (userid, groupid) VALUES (?,?)", [user_rowid, groupid])

        cur.close()

        logging.debug('add_user(domain={}, username={}, groupid={}) => {}'.format(domain, username, groupid, user_rowid))

        return user_rowid

    def add_group(self, domain, name):

        domain = domain.split('.')[0].upper()
        cur = self.conn.cursor()

        cur.execute("SELECT * FROM groups WHERE LOWER(domain)=LOWER(?) AND LOWER(name)=LOWER(?)", [domain, name])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO groups (domain, name) VALUES (?,?)", [domain, name])

        cur.close()

        logging.debug('add_group(domain={}, name={}) => {}'.format(domain, name, cur.lastrowid))

        return cur.lastrowid
    '''
    def remove_credentials(self, credIDs):
        """
        Removes a credential ID from the database
        """
        for credID in credIDs:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM credentials WHERE id=?", [credID])
            cur.close()
    '''
    def add_admin_user(self, credtype, domain, username, password, host, userid=None):

        domain = domain.split('.')[0].upper()
        cur = self.conn.cursor()

        if userid:
            cur.execute("SELECT * FROM users WHERE id=?", [userid])
            users = cur.fetchall()
        else:
            cur.execute("SELECT * FROM users WHERE credtype=? AND LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?) AND password=?", [credtype, domain, username, password])
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
            cur.execute("SELECT * FROM admin_relations WHERE userid=?", [userID])

        elif hostID:
            cur.execute("SELECT * FROM admin_relations WHERE computerid=?", [hostID])

        results = cur.fetchall()
        cur.close()

        return results

    def get_group_relations(self, userID=None, groupID=None):

        cur = self.conn.cursor()

        if userID and groupID:
            cur.execute("SELECT * FROM group_relations WHERE userid=? and groupid=?", [userID, groupID])

        elif userID:
            cur.execute("SELECT * FROM group_relations WHERE userid=?", [userID])

        elif groupID:
            cur.execute("SELECT * FROM group_relations WHERE groupid=?", [groupID])

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

    def remove_group_relations(self, userID=None, groupID=None):

        cur = self.conn.cursor()

        if userID:
            cur.execute("DELETE FROM group_relations WHERE userid=?", [userID])

        elif groupID:
            cur.execute("DELETE FROM group_relations WHERE groupid=?", [groupID])

        results = cur.fetchall()
        cur.close()

        return results

    def is_credential_valid(self, credentialID):
        """
        Check if this credential ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM users WHERE id=? AND password IS NOT NULL LIMIT 1', [credentialID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0

    def is_credential_local(self, credentialID):
        cur = self.conn.cursor()
        cur.execute('SELECT domain FROM users WHERE id=?', [credentialID])
        user_domain = cur.fetchall()

        if user_domain:
            cur.execute('SELECT * FROM computers WHERE LOWER(hostname)=LOWER(?)', [user_domain])
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
            cur.execute("SELECT * FROM users WHERE id=?", [filterTerm])

        elif credtype:
            cur.execute("SELECT * FROM users WHERE credtype=?", [credtype])

        # if we're filtering by username
        elif filterTerm and filterTerm != '':
            cur.execute("SELECT * FROM users WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])

        # otherwise return all credentials
        else:
            cur.execute("SELECT * FROM users")

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

    def get_user(self, domain, username):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM users WHERE LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?)", [domain, username])
        results = cur.fetchall()
        cur.close()
        return results

    def is_computer_valid(self, hostID):
        """
        Check if this host ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM computers WHERE id=? LIMIT 1', [hostID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0

    def get_computers(self, filterTerm=None, domain=None):
        """
        Return hosts from the database.
        """

        cur = self.conn.cursor()

        # if we're returning a single host by ID
        if self.is_computer_valid(filterTerm):
            cur.execute("SELECT * FROM computers WHERE id=? LIMIT 1", [filterTerm])

        # if we're filtering by domain controllers
        elif filterTerm == 'dc':
            if domain:
                cur.execute("SELECT * FROM computers WHERE dc=1 AND LOWER(domain)=LOWER(?)", [domain])
            else:
                cur.execute("SELECT * FROM computers WHERE dc=1")

        # if we're filtering by ip/hostname
        elif filterTerm and filterTerm != "":
            cur.execute("SELECT * FROM computers WHERE ip LIKE ? OR LOWER(hostname) LIKE LOWER(?)", ['%{}%'.format(filterTerm), '%{}%'.format(filterTerm)])

        # otherwise return all computers
        else:
            cur.execute("SELECT * FROM computers")

        results = cur.fetchall()
        cur.close()
        return results

    def get_domain_controllers(self, domain=None):
        return self.get_computers(filterTerm='dc', domain=domain)

    def is_group_valid(self, groupID):
        """
        Check if this group ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM groups WHERE id=? LIMIT 1', [groupID])
        results = cur.fetchall()
        cur.close()

        logging.debug('is_group_valid(groupID={}) => {}'.format(groupID, True if len(results) else False))
        return len(results) > 0

    def get_groups(self, filterTerm=None, groupName=None, groupDomain=None):
        """
        Return groups from the database
        """
        if groupDomain:
            groupDomain = groupDomain.split('.')[0].upper()

        cur = self.conn.cursor()

        if self.is_group_valid(filterTerm):
            cur.execute("SELECT * FROM groups WHERE id=? LIMIT 1", [filterTerm])

        elif groupName and groupDomain:
            cur.execute("SELECT * FROM groups WHERE LOWER(name)=LOWER(?) AND LOWER(domain)=LOWER(?)", [groupName, groupDomain])

        elif filterTerm and filterTerm !="":
            cur.execute("SELECT * FROM groups WHERE LOWER(name) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])

        else:
            cur.execute("SELECT * FROM groups")

        results = cur.fetchall()
        cur.close()
        logging.debug('get_groups(filterTerm={}, groupName={}, groupDomain={}) => {}'.format(filterTerm, groupName, groupDomain, results))
        return results
