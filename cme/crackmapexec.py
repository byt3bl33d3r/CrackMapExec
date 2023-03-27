#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import concurrent.futures

import sqlalchemy

from cme.logger import setup_logger, setup_debug_logger, CMEAdapter
from cme.helpers.logger import highlight
from cme.helpers.misc import identify_target_file
from cme.parsers.ip import parse_targets
from cme.parsers.nmap import parse_nmap_xml
from cme.parsers.nessus import parse_nessus_file
from cme.cli import gen_cli_args
from cme.loaders.protocol_loader import protocol_loader
from cme.loaders.module_loader import module_loader
from cme.servers.http import CMEServer
from cme.first_run import first_run_setup
from cme.context import Context
from cme.paths import CME_PATH
from concurrent.futures import ThreadPoolExecutor
from pprint import pformat
from decimal import Decimal
import asyncio
import configparser
import cme.helpers.powershell as powershell
import cme
import shutil
import webbrowser
import sqlite3
import random
import os
import sys
import logging
from sqlalchemy.orm import declarative_base
from sqlalchemy.exc import SAWarning
import warnings
from tqdm import tqdm

Base = declarative_base()

setup_logger()
logger = CMEAdapter()

try:
    import librlers
except:
    print("Incompatible python version, try with another python version or another binary 3.8 / 3.9 / 3.10 / 3.11 that match your python version (python -V)")
    sys.exit()
# if there is an issue with SQLAlchemy and a connection cannot be cleaned up properly it spews out annoying warnings
warnings.filterwarnings("ignore", category=SAWarning)


def create_db_engine(db_path):
    db_engine = sqlalchemy.create_engine(
        f"sqlite:///{db_path}",
        isolation_level="AUTOCOMMIT",
        future=True
    )
    return db_engine


async def start_scan(protocol_obj, args, db, targets):
    with tqdm(total=len(targets), disable=args.progress) as pbar:
        with ThreadPoolExecutor(max_workers=args.threads + 1) as executor:
            futures = [executor.submit(protocol_obj, args, db, target) for target in targets]
            for future in concurrent.futures.as_completed(futures):
                pbar.update(1)


def main():
    logging.getLogger('asyncio').setLevel(logging.CRITICAL)
    logging.getLogger('aiosqlite').setLevel(logging.CRITICAL)
    logging.getLogger('pypsrp').setLevel(logging.CRITICAL)
    logging.getLogger('spnego').setLevel(logging.CRITICAL)
    logging.getLogger('sqlalchemy.pool.impl.NullPool').setLevel(logging.CRITICAL)
    first_run_setup(logger)

    args = gen_cli_args()

    if args.darrell:
        links = open(os.path.join(os.path.dirname(cme.__file__), 'data', 'videos_for_darrell.harambe')).read().splitlines()
        try:
            webbrowser.open(random.choice(links))
        except:
            sys.exit(1)

    config = configparser.ConfigParser()
    config.read(os.path.join(CME_PATH, 'cme.conf'))

    module = None
    module_server = None
    targets = []
    server_port_dict = {'http': 80, 'https': 443, 'smb': 445}
    current_workspace = config.get('CME', 'workspace')
    if config.get('CME', 'log_mode') != "False":
        logger.setup_logfile()

    if args.verbose:
        setup_debug_logger()

    logging.debug('Passed args:\n' + pformat(vars(args)))

    if args.jitter:
        if '-' in args.jitter:
            start, end = args.jitter.split('-')
            args.jitter = (int(start), int(end))
        else:
            args.jitter = (0, int(args.jitter))

    if hasattr(args, 'cred_id') and args.cred_id:
        for cred_id in args.cred_id:
            if '-' in str(cred_id):
                start_id, end_id = cred_id.split('-')
                try:
                    for n in range(int(start_id), int(end_id) + 1):
                        args.cred_id.append(n)
                    args.cred_id.remove(cred_id)
                except Exception as e:
                    logger.error('Error parsing database credential id: {}'.format(e))
                    sys.exit(1)

    if hasattr(args, 'target') and args.target:
        for target in args.target:
            if os.path.exists(target):
                target_file_type = identify_target_file(target)
                if target_file_type == 'nmap':
                    targets.extend(parse_nmap_xml(target, args.protocol))
                elif target_file_type == 'nessus':
                    targets.extend(parse_nessus_file(target, args.protocol))
                else:
                    with open(target, 'r') as target_file:
                        for target_entry in target_file:
                            targets.extend(parse_targets(target_entry.strip()))
            else:
                targets.extend(parse_targets(target))

    # The following is a quick hack for the powershell obfuscation functionality, I know this is yucky
    if hasattr(args, 'clear_obfscripts') and args.clear_obfscripts:
        shutil.rmtree(os.path.expanduser('~/.cme/obfuscated_scripts/'))
        os.mkdir(os.path.expanduser('~/.cme/obfuscated_scripts/'))
        logger.success('Cleared cached obfuscated PowerShell scripts')

    if hasattr(args, 'obfs') and args.obfs:
        powershell.obfuscate_ps_scripts = True

    logging.debug(f"Protocol: {args.protocol}")
    p_loader = protocol_loader()
    protocol_path = p_loader.get_protocols()[args.protocol]['path']
    logging.debug(f"Protocol Path: {protocol_path}")
    protocol_db_path = p_loader.get_protocols()[args.protocol]['dbpath']
    logging.debug(f"Protocol DB Path: {protocol_db_path}")

    protocol_object = getattr(p_loader.load_protocol(protocol_path), args.protocol)
    logging.debug(f"Protocol Object: {protocol_object}")
    protocol_db_object = getattr(p_loader.load_protocol(protocol_db_path), 'database')
    logging.debug(f"Protocol DB Object: {protocol_db_object}")

    db_path = os.path.join(CME_PATH, 'workspaces', current_workspace, args.protocol + '.db')
    logging.debug(f"DB Path: {db_path}")

    db_engine = create_db_engine(db_path)

    db = protocol_db_object(db_engine)

    setattr(protocol_object, 'config', config)

    if hasattr(args, 'module'):
        loader = module_loader(args, db, logger)
        if args.list_modules:
            modules = loader.get_modules()

            for name, props in sorted(modules.items()):
                logger.info('{:<25} {}'.format(name, props['description']))
            sys.exit(0)

        elif args.module and args.show_module_options:

            modules = loader.get_modules()
            for name, props in modules.items():
                if args.module.lower() == name.lower():
                    logger.info('{} module options:\n{}'.format(name, props['options']))
            sys.exit(0)

        elif args.module:
            modules = loader.get_modules()
            for name, props in modules.items():
                if args.module.lower() == name.lower():
                    module = loader.init_module(props['path'])
                    setattr(protocol_object, 'module', module)
                    break

            if not module:
                logger.error('Module not found')
                exit(1)

            if getattr(module, 'opsec_safe') is False:
                ans = input(highlight('[!] Module is not opsec safe, are you sure you want to run this? [Y/n] ', 'red'))
                if ans.lower() not in ['y', 'yes', '']:
                    sys.exit(1)

            if getattr(module, 'multiple_hosts') is False and len(targets) > 1:
                ans = input(highlight("[!] Running this module on multiple hosts doesn't really make any sense, are you sure you want to continue? [Y/n] ", 'red'))
                if ans.lower() not in ['y', 'yes', '']:
                    sys.exit(1)

            if hasattr(module, 'on_request') or hasattr(module, 'has_response'):

                if hasattr(module, 'required_server'):
                    args.server = getattr(module, 'required_server')

                if not args.server_port:
                    args.server_port = server_port_dict[args.server]

                context = Context(db, logger, args)
                module_server = CMEServer(module, context, logger, args.server_host, args.server_port, args.server)
                module_server.start()
                setattr(protocol_object, 'server', module_server.server)

    if hasattr(args, 'ntds') and args.ntds and not args.userntds:
        ans = input(highlight('[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] ', 'red'))
        if ans.lower() not in ['y', 'yes', '']:
            sys.exit(1)

    try:
        asyncio.run(
            start_scan(protocol_object, args, db, targets)
        )
    except KeyboardInterrupt:
        logging.debug("Got keyboard interrupt")
    finally:
        if module_server:
            module_server.shutdown()
        db_engine.dispose()


if __name__ == '__main__':
    main()
