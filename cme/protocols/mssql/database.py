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
            "password" text
            )''')

    def add_computer(self, ip, hostname, domain, os, instances):
        """
        Check if this host has already been added to the database, if not add it in.
        """
        cur = self.conn.cursor()

        cur.execute('SELECT * FROM computers WHERE ip LIKE ?', [ip])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO computers (ip, hostname, domain, os, instances) VALUES (?,?,?,?,?)", [ip, hostname, domain, os, instances])

        cur.close()

    def add_credential(self, credtype, domain, username, password):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        cur = self.conn.cursor()

        cur.execute("SELECT * FROM users WHERE credtype=? AND LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?) AND password=?", [credtype, domain, username, password])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO users (credtype, domain, username, password) VALUES (?,?,?,?)", [credtype, domain, username, password])

        cur.close()

    def remove_credentials(self, credIDs):
        """
        Removes a credential ID from the database
        """
        for credID in credIDs:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM users WHERE id=?", [credID])
            cur.close()

    def add_admin_user(self, credtype, domain, username, password, host):

        cur = self.conn.cursor()

        cur.execute("SELECT * FROM users WHERE credtype=? AND LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?) AND password=?", [credtype, domain, username, password])
        creds = cur.fetchall()

        cur.execute('SELECT * FROM computers WHERE ip LIKE ?', [host])
        hosts = cur.fetchall()

        if len(creds) and len(hosts):
            for cred, host in zip(creds, hosts):
                userid = cred[0]
                computerid = host[0]

                # Check to see if we already added this link
                cur.execute("SELECT * FROM admin_relations WHERE userid=? AND computerid=?", [userid, computerid])
                links = cur.fetchall()

                if not len(links):
                    cur.execute("INSERT INTO admin_relations (userid, computerid) VALUES (?,?)", [userid, computerid])

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
                cur.execute("DELETE FROM admin_relations WHERE computerid=?", [hostID])

        cur.close()

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
