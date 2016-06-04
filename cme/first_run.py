import os
import sqlite3

CME_PATH = os.path.expanduser('~/.cme')

def first_run_setup(logger):
    
    if not os.path.exists(CME_PATH):
        logger.info('First time use detected, setting things up, please wait...') 
        
        os.mkdir(CME_PATH)
        folders = ['logs', 'modules']
        for folder in folders:
            os.mkdir(os.path.join(CME_PATH,folder))

        conn = sqlite3.connect(os.path.join(CME_PATH, 'cme.db'))

        c = conn.cursor()

        # try to prevent some of the weird sqlite I/O errors
        c.execute('PRAGMA journal_mode = OFF')

        c.execute('''CREATE TABLE "hosts" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "hostname" text,
            "domain" test,
            "os" text
            )''')

        #This table keeps track of which credential has admin access over which machine
        c.execute('''CREATE TABLE "links" (
            "id" integer PRIMARY KEY,
            "credid" integer,
            "hostid" integer
            )''')

        # type = hash, plaintext
        c.execute('''CREATE TABLE "credentials" (
            "id" integer PRIMARY KEY,
            "credtype" text,
            "domain" text,
            "username" text,
            "password" text
            )''')

        # commit the changes and close everything off
        conn.commit()
        conn.close()

        os.system('openssl req -new -x509 -keyout {path} -out {path} -days 365 -nodes -subj "/C=US" > /dev/null 2>&1'.format(path=os.path.join(CME_PATH, 'cme.pem')))