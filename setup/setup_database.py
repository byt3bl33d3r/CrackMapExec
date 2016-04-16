#!/usr/bin/env python2

import sqlite3

conn = sqlite3.connect('../data/cme.db')

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

print "\n [*] Database setup completed! \n"