#!/bin/bash
openssl req -new -x509 -keyout ../data/cme.pem -out ../data/cme.pem -days 365 -nodes -subj "/C=US"
echo -e "\n\n [*] Certificate written to ../data/cme.pem\n"