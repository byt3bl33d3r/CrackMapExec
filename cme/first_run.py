import os
import sqlite3
import shutil
import cme
from subprocess import check_output, PIPE
from sys import exit

CME_PATH  = os.path.expanduser('~/.cme')
DB_PATH   = os.path.join(CME_PATH, 'cme.db')
CERT_PATH = os.path.join(CME_PATH, 'cme.pem')
CONFIG_PATH = os.path.join(CME_PATH, 'cme.conf')

def first_run_setup(logger):

    if not os.path.exists(CME_PATH):
        logger.info('First time use detected')
        logger.info('Creating home directory structure') 

        os.mkdir(CME_PATH)
        folders = ['logs', 'modules']
        for folder in folders:
            os.mkdir(os.path.join(CME_PATH,folder))

    if not os.path.exists(DB_PATH):
        logger.info('Initializing the database')
        conn = sqlite3.connect(DB_PATH)
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

        #This table keeps track of which credential has admin access over which machine and vice-versa
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
            "password" text,
            "pillagedfrom" integer
            )''')

        # commit the changes and close everything off
        conn.commit()
        conn.close()

    if not os.path.exists(CONFIG_PATH):
        logger.info('Copying default configuration file')
        default_path = os.path.join(os.path.dirname(cme.__file__), 'data', 'cme.conf')
        shutil.copy(default_path, CME_PATH)

    if not os.path.exists(CERT_PATH):
        logger.info('Generating SSL certificate')
        try:
            out = check_output(['openssl', 'help'], stderr=PIPE)
        except OSError as e:
            if e.errno == os.errno.ENOENT:
                logger.error('OpenSSL command line utility is not installed, could not generate certificate')
                exit(1)
            else:
                logger.error('Error while generating SSL certificate: {}'.format(e))
                exit(1)

        os.system('openssl req -new -x509 -keyout {path} -out {path} -days 365 -nodes -subj "/C=US" > /dev/null 2>&1'.format(path=CERT_PATH))