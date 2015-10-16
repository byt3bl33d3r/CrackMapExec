#!/bin/bash
openssl genrsa -out crackmapexec.key 2048
openssl req -new -x509 -days 3650 -key crackmapexec.key -out crackmapexec.crt -subj "/"
