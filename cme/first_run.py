#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import errno
import sqlite3
import shutil
import cme
import configparser
from configparser import ConfigParser, NoSectionError, NoOptionError
from cme.paths import CME_PATH, CONFIG_PATH, CERT_PATH, TMP_PATH
from cmedb import initialize_db
from subprocess import check_output, PIPE
import sys


def first_run_setup(logger):
    if not os.path.exists(TMP_PATH):
        os.mkdir(TMP_PATH)

    if not os.path.exists(CME_PATH):
        logger.info('First time use detected')
        logger.info('Creating home directory structure')
        os.mkdir(CME_PATH)

    folders = ['logs', 'modules', 'protocols', 'workspaces', 'obfuscated_scripts', 'screenshots']
    for folder in folders:
        if not os.path.exists(os.path.join(CME_PATH, folder)):
            logger.info("Creating missing folder {}".format(folder))
            os.mkdir(os.path.join(CME_PATH, folder))

    initialize_db(logger)

    if not os.path.exists(CONFIG_PATH):
        logger.info('Copying default configuration file')
        default_path = os.path.join(os.path.dirname(cme.__file__), 'data', 'cme.conf')
        shutil.copy(default_path, CME_PATH)
    else:
        # This is just a quick check to make sure the config file isn't the old 3.x format
        try:
            config = configparser.ConfigParser()
            config.read(CONFIG_PATH)
            config.get('CME', 'workspace')
            config.get('CME', 'pwn3d_label')
            config.get('CME', 'audit_mode')
            config.get('BloodHound', 'bh_enabled')
        except (NoSectionError, NoOptionError):
            logger.info('Old configuration file detected, replacing with new version')
            default_path = os.path.join(os.path.dirname(cme.__file__), 'data', 'cme.conf')
            shutil.copy(default_path, CME_PATH)

    if not os.path.exists(CERT_PATH):
        logger.info('Generating SSL certificate')
        try:
            check_output(['openssl', 'help'], stderr=PIPE)
            if os.name != 'nt':
                os.system('openssl req -new -x509 -keyout {path} -out {path} -days 365 -nodes -subj "/C=US" > /dev/null 2>&1'.format(path=CERT_PATH))
            else:
                os.system('openssl req -new -x509 -keyout {path} -out {path} -days 365 -nodes -subj "/C=US"'.format(path=CERT_PATH))
        except OSError as e:
            if e.errno == errno.ENOENT:
                logger.error('OpenSSL command line utility is not installed, could not generate certificate, using default certificate')
                default_path = os.path.join(os.path.dirname(cme.__file__), 'data', 'default.pem')
                shutil.copy(default_path, CERT_PATH)                
            else:
                logger.error('Error while generating SSL certificate: {}'.format(e))
                sys.exit(1)
