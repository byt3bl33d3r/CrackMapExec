class database:

    def __init__(self, conn):
        self.conn = conn

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute('''CREATE TABLE "credentials" (
            "id" integer PRIMARY KEY,
            "url" text,
            "username" text,
            "password" text
            )''')

    def add_credential(self, url, username, password):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        cur = self.conn.cursor()

        cur.execute("SELECT * FROM credentials WHERE credtype=? AND LOWER(url)=LOWER(?) AND LOWER(username)=LOWER(?) AND password=?", [url, username, password])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO credentials (url, username, password) VALUES (?,?,?)", [url, username, password] )

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
