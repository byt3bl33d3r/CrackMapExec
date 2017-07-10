class database:

    def __init__(self, conn):
        self.conn = conn

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute('''CREATE TABLE "credentials" (
            "id" integer PRIMARY KEY,
            "username" text,
            "password" text
            )''')

        db_conn.execute('''CREATE TABLE "hosts" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "hostname" text,
            "port" integer,
            "server" text,
            "page_title" text,
            "login_url" text
            )''')

    def add_credential(self, url, username, password):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        cur = self.conn.cursor()

        cur.execute("SELECT * FROM credentials WHERE LOWER(username)=LOWER(?) AND password=?", [url, username, password])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO credentials (username, password) VALUES (?,?)", [username, password] )

        cur.close()

    def add_host(self, ip, hostname, port, title=None, login_url=None):
        cur = self.conn.cursor()

        cur.execute("SELECT * FROM hosts WHERE LOWER(ip)=LOWER(?) AND LOWER(hostname)=LOWER(?) AND port=? AND LOWER(login_url)=LOWER(?)", [ip, hostname, port, login_url])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO hosts (ip, hostname, port, login_url) VALUES (?,?,?,?)", [ip, hostname, port, login_url])

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

    def is_host_valid(self, hostID):
        """
        Check if this credential ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM host WHERE id=? LIMIT 1', [hostID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0

    def get_credentials(self, filterTerm=None):
        """
        Return credentials from the database.
        """

        cur = self.conn.cursor()

        # if we're returning a single credential by ID
        if self.is_credential_valid(filterTerm):
            cur.execute("SELECT * FROM credentials WHERE id=? LIMIT 1", [filterTerm])

        # if we're filtering by username
        elif filterTerm and filterTerm != "":
            cur.execute("SELECT * FROM credentials WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filterTerm.lower())])

        # otherwise return all credentials
        else:
            cur.execute("SELECT * FROM credentials")

        results = cur.fetchall()
        cur.close()
        return results

    def remove_credentials(self, credIDs):
        """
        Removes a credential ID from the database
        """
        for credID in credIDs:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM credentials WHERE id=?", [credID])
            cur.close()
