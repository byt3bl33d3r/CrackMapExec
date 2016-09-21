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

    def add_credential(self, credtype, domain, username, password, pillaged_from=-1):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        cur = self.conn.cursor()

        cur.execute("SELECT * FROM credentials WHERE credtype=? AND LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?) AND password=?", [credtype, domain, username, password])
        results = cur.fetchall()

        if not len(results):
            cur.execute("INSERT INTO credentials (credtype, domain, username, password, pillagedfrom) VALUES (?,?,?,?,?)", [credtype, domain, username, password, pillaged_from] )

        cur.close()

    def remove_credentials(self, credIDs):
        """
        Removes a credential ID from the database
        """
        for credID in credIDs:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM credentials WHERE id=?", [credID])
            cur.close()

    def link_cred_to_host(self, credtype, domain, username, password, host):

        cur = self.conn.cursor()

        cur.execute("SELECT * FROM credentials WHERE credtype=? AND LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?) AND password=?", [credtype, domain, username, password])
        creds = cur.fetchall()

        cur.execute('SELECT * FROM hosts WHERE ip LIKE ?', [host])
        hosts = cur.fetchall()

        if len(creds) and len(hosts):
            for cred, host in zip(creds, hosts):
                credid = cred[0]
                hostid = host[0]

                #Check to see if we already added this link
                cur.execute("SELECT * FROM links WHERE credid=? AND hostid=?", [credid, hostid])
                links = cur.fetchall()

                if not len(links):
                    cur.execute("INSERT INTO links (credid, hostid) VALUES (?,?)", [credid, hostid])

        cur.close()

    def get_links(self, credID=None, hostID=None):

        cur = self.conn.cursor()

        if credID:
            cur.execute("SELECT * from links WHERE credid=?", [credID])
        
        elif hostID:
            cur.execute("SELECT * from links WHERE hostid=?", [hostID])

        results = cur.fetchall()
        cur.close()
        return results

    def remove_links(self, credIDs=None, hostIDs=None):

        cur = self.conn.cursor()

        if credIDs:
            for credID in credIDs:
                cur.execute("DELETE FROM links WHERE credid=?", [credID])
        
        elif hostIDs:
            for hostID in hostIDs:
                cur.execute("DELETE FROM links WHERE hostid=?", [hostID])

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

    def get_credentials(self, filterTerm=None, credtype=None):
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

        # if we're filtering by username
        elif filterTerm and filterTerm != "":
            cur.execute("SELECT * FROM credentials WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filterTerm.lower())])

        # otherwise return all credentials            
        else:
            cur.execute("SELECT * FROM credentials")

        results = cur.fetchall()
        cur.close()
        return results

    def is_host_valid(self, hostID):
        """
        Check if this host ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM hosts WHERE id=? LIMIT 1', [hostID])
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
            cur.execute("SELECT * FROM hosts WHERE id=? LIMIT 1", [filterTerm])

        # if we're filtering by ip/hostname
        elif filterTerm and filterTerm != "":
            cur.execute("SELECT * FROM hosts WHERE ip LIKE ? OR LOWER(hostname) LIKE LOWER(?)", ['%{}%'.format(filterTerm.lower()), '%{}%'.format(filterTerm.lower())])

        # otherwise return all credentials            
        else:
            cur.execute("SELECT * FROM hosts")

        results = cur.fetchall()
        cur.close()
        return results