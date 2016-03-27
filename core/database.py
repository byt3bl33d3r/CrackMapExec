class CMEDatabase:

    def __init__(self, conn):
        self.conn = conn

    def add_host(self, ip, hostname, domain, os):
        """
        Check if this host has already been added to the database, if not add it in.
        """
        cur = self.conn.cursor()

        cur.execute('SELECT * FROM hosts WHERE ip LIKE ?', [ip])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO hosts (ip, hostname, domain, os) VALUES (?,?,?,?)", [ip, hostname, domain, os])

        cur.close()

    def add_credential(self, credtype, domain, username, password):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        cur = self.conn.cursor()

        cur.execute("SELECT * FROM credentials WHERE LOWER(credtype) LIKE LOWER(?) AND LOWER(domain) LIKE LOWER(?) AND LOWER(username) LIKE LOWER(?) AND password LIKE ?", [credtype, domain, username, password])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO credentials (credtype, domain, username, password) VALUES (?,?,?,?)", [credtype, domain, username, password] )

        cur.close()

    def is_credential_valid(self, credentialID):
        """
        Check if this credential ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM credentials WHERE id=? limit 1', [credentialID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0

    def get_credentials(self, filterTerm=None, credtype=None):
        """
        Return credentials from the database.

        'credtype' can be specified to return creds of a specific type.
        
        Values are: hash and plaintext.
        """

        cur = self.conn.cursor()

        # if we're returning a single credential by ID
        if self.is_credential_valid(filterTerm):
            cur.execute("SELECT * FROM credentials WHERE id=? limit 1", [filterTerm])

        # if we're filtering by host/username
        elif filterTerm and filterTerm != "":
            cur.execute("SELECT * FROM credentials WHERE LOWER(host) LIKE LOWER(?) or LOWER(username) like LOWER(?)", [filterTerm, filterTerm])

        # if we're filtering by credential type (hash, plaintext, token)
        elif(credtype and credtype != ""):
            cur.execute("SELECT * FROM credentials WHERE LOWER(credtype) LIKE LOWER(?)", [credtype])

        # otherwise return all credentials            
        else:
            cur.execute("SELECT * FROM credentials")

        results = cur.fetchall()
        cur.close()
        return results