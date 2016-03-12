#!/bin/bash
openssl genrsa -out crackmapexec.key 2048
openssl req -new -x509 -days 3650 -key cme.key -out cme.crt -subj "/"
