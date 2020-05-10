#!/usr/bin/env python3

from gevent.pool import Pool
from gevent import sleep
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
from pprint import pformat
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


def main():

    setup_logger()
    logger = CMEAdapter()
    first_run_setup(logger)

    args = gen_cli_args()

    if args.darrell:
        links = open(os.path.join(os.path.dirname(cme.__file__), 'data', 'videos_for_darrell.harambe')).read().splitlines()
        try:
            webbrowser.open(random.choice(links))
        except:
            sys.exit(1)

    cme_path = os.path.expanduser('~/.cme')

    config = configparser.ConfigParser()
    config.read(os.path.join(cme_path, 'cme.conf'))

    module = None
    module_server = None
    targets = []
    jitter = None
    server_port_dict = {'http': 80, 'https': 443, 'smb': 445}
    current_workspace = config.get('CME', 'workspace')

    if args.verbose:
        setup_debug_logger()

    logging.debug('Passed args:\n' + pformat(vars(args)))

    if args.jitter:
        if '-' in args.jitter:
            start, end = args.jitter.split('-')
            jitter = (int(start), int(end))
        else:
            jitter = (0, int(args.jitter))

    if hasattr(args, 'username') and args.username:
        for user in args.username:
            if os.path.exists(user):
                args.username.remove(user)
                args.username.append(open(user, 'r'))

    if hasattr(args, 'password') and args.password:
        for passw in args.password:
            if os.path.exists(passw):
                args.password.remove(passw)
                args.password.append(open(passw, 'r'))

    elif hasattr(args, 'hash') and args.hash:
        for ntlm_hash in args.hash:
            if os.path.exists(ntlm_hash):
                args.hash.remove(ntlm_hash)
                args.hash.append(open(ntlm_hash, 'r'))

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

    p_loader = protocol_loader()
    protocol_path = p_loader.get_protocols()[args.protocol]['path']
    protocol_db_path = p_loader.get_protocols()[args.protocol]['dbpath']

    protocol_object = getattr(p_loader.load_protocol(protocol_path), args.protocol)
    protocol_db_object = getattr(p_loader.load_protocol(protocol_db_path), 'database')

    db_path = os.path.join(cme_path, 'workspaces', current_workspace, args.protocol + '.db')
    # set the database connection to autocommit w/ isolation level
    db_connection = sqlite3.connect(db_path, check_same_thread=False)
    db_connection.text_factory = str
    db_connection.isolation_level = None
    db = protocol_db_object(db_connection)

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

    try:
        '''
            Open all the greenlet (as supposed to redlet??) threads
            Whoever came up with that name has a fetish for traffic lights
        '''
        pool = Pool(args.threads)
        jobs = []
        for target in targets:
            jobs.append(pool.spawn(protocol_object, args, db, str(target)))

            if jitter:
                value = random.choice(range(jitter[0], jitter[1]))
                logging.debug("Doin' the Jitterbug for {} seconds".format(value))
                sleep(value)

        for job in jobs:
            job.join(timeout=args.timeout)
    except KeyboardInterrupt:
        pass

    if module_server:
        module_server.shutdown()

if __name__ == '__main__':
    main()