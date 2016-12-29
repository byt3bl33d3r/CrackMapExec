#!/usr/bin/env python2

#This must be one of the first imports or else we get threading error on completion
from gevent import monkey
monkey.patch_all()

from gevent.pool import Pool
from gevent import joinall
from argparse import RawTextHelpFormatter
from cme.connection import Connection
from cme.database import CMEDatabase
from cme.logger import setup_logger, setup_debug_logger, CMEAdapter
from cme.helpers import highlight
from cme.targetparser import parse_targets
from cme.moduleloader import ModuleLoader
from cme.first_run import first_run_setup
import sqlite3
import argparse
import os
import sys
import logging

def main():

    VERSION  = '3.1.5'
    CODENAME = '\'Smidge\''

    parser = argparse.ArgumentParser(description="""
      ______ .______           ___        ______  __  ___ .___  ___.      ___      .______    _______ ___   ___  _______   ______
     /      ||   _  \         /   \      /      ||  |/  / |   \/   |     /   \     |   _  \  |   ____|\  \ /  / |   ____| /      |
    |  ,----'|  |_)  |       /  ^  \    |  ,----'|  '  /  |  \  /  |    /  ^  \    |  |_)  | |  |__    \  V  /  |  |__   |  ,----'
    |  |     |      /       /  /_\  \   |  |     |    <   |  |\/|  |   /  /_\  \   |   ___/  |   __|    >   <   |   __|  |  |
    |  `----.|  |\  \----. /  _____  \  |  `----.|  .  \  |  |  |  |  /  _____  \  |  |      |  |____  /  .  \  |  |____ |  `----.
     \______|| _| `._____|/__/     \__\  \______||__|\__\ |__|  |__| /__/     \__\ | _|      |_______|/__/ \__\ |_______| \______|


                     Swiss army knife for pentesting Windows/Active Directory environments | @byt3bl33d3r

                           Powered by Impacket https://github.com/CoreSecurity/impacket (@agsolino)

                                                       Inspired by:
                                @ShawnDEvans's smbmap https://github.com/ShawnDEvans/smbmap
                                @gojhonny's CredCrack https://github.com/gojhonny/CredCrack
                                @pentestgeek's smbexec https://github.com/pentestgeek/smbexec

                                                      {}: {}
                                                     {}: {}
    """.format(highlight('Version', 'red'),
               highlight(VERSION),
               highlight('Codename', 'red'),
               highlight(CODENAME)),

                                    formatter_class=RawTextHelpFormatter,
                                    version='{} - {}'.format(VERSION, CODENAME),
                                    epilog="Y'all got any more of that smidge left?")

    parser.add_argument("target", nargs='*', type=str, help="The target IP(s), range(s), CIDR(s), hostname(s), FQDN(s) or file(s) containg a list of targets")
    parser.add_argument("-t", type=int, dest="threads", default=100, help="Set how many concurrent threads to use (default: 100)")
    parser.add_argument('-id', metavar="CRED_ID", nargs='+', default=[], type=str, dest='cred_id', help='Database credential ID(s) to use for authentication')
    parser.add_argument("-u", metavar="USERNAME", dest='username', nargs='+', default=[], help="Username(s) or file(s) containing usernames")
    ddgroup = parser.add_mutually_exclusive_group()
    ddgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, help="Domain name")
    ddgroup.add_argument("--local-auth", action='store_true', help='Authenticate locally to each target')
    msgroup = parser.add_mutually_exclusive_group()
    msgroup.add_argument("-p", metavar="PASSWORD", dest='password', nargs= '+', default=[], help="Password(s) or file(s) containing passwords")
    msgroup.add_argument("-H", metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
    mcgroup = parser.add_mutually_exclusive_group()
    mcgroup.add_argument("-M", "--module", metavar='MODULE', help='Payload module to use')
    parser.add_argument('-o', metavar='MODULE_OPTION', nargs='+', default=[], dest='module_options', help='Payload module options')
    parser.add_argument('-L', '--list-modules', action='store_true', help='List available modules')
    parser.add_argument('--show-options', action='store_true', help='Display module options')
    parser.add_argument("--share", metavar="SHARE", default="C$", help="Specify a share (default: C$)")
    parser.add_argument("--smb-port", type=int, choices={139, 445}, default=445, help="SMB port (default: 445)")
    parser.add_argument("--mssql-port", default=1433, type=int, metavar='PORT', help='MSSQL port (default: 1433)')
    parser.add_argument("--server", choices={'http', 'https'}, default='https', help='Use the selected server (default: https)')
    parser.add_argument("--server-host", type=str, default='0.0.0.0', metavar='HOST', help='IP to bind the server to (default: 0.0.0.0)')
    parser.add_argument("--server-port", metavar='PORT', type=int, help='Start the server on the specified port')
    parser.add_argument("--timeout", default=20, type=int, help='Max timeout in seconds of each thread (default: 20)')
    fail_group = parser.add_mutually_exclusive_group()
    fail_group.add_argument("--gfail-limit", metavar='LIMIT', type=int, help='Max number of global failed login attempts')
    fail_group.add_argument("--ufail-limit", metavar='LIMIT', type=int, help='Max number of failed login attempts per username')
    fail_group.add_argument("--fail-limit", metavar='LIMIT', type=int, help='Max number of failed login attempts per host')
    parser.add_argument("--verbose", action='store_true', help="Enable verbose output")

    rgroup = parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
    rgroup.add_argument("--sam", action='store_true', help='Dump SAM hashes from target systems')
    rgroup.add_argument("--lsa", action='store_true', help='Dump LSA secrets from target systems')
    rgroup.add_argument("--ntds", choices={'vss', 'drsuapi'}, help="Dump the NTDS.dit from target DCs using the specifed method\n(drsuapi is the fastest)")
    rgroup.add_argument("--ntds-history", action='store_true', help='Dump NTDS.dit password history')
    rgroup.add_argument("--ntds-pwdLastSet", action='store_true', help='Shows the pwdLastSet attribute for each NTDS.dit account')
    rgroup.add_argument("--wdigest", choices={'enable', 'disable'}, help="Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1")

    egroup = parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
    egroup.add_argument("--shares", action="store_true", help="Enumerate shares and access")
    egroup.add_argument('--uac', action='store_true', help='Checks UAC status')
    egroup.add_argument("--sessions", action='store_true', help='Enumerate active sessions')
    egroup.add_argument('--disks', action='store_true', help='Enumerate disks')
    egroup.add_argument("--users", action='store_true', help='Enumerate users')
    egroup.add_argument("--rid-brute", nargs='?', const=4000, metavar='MAX_RID', help='Enumerate users by bruteforcing RID\'s (default: 4000)')
    egroup.add_argument("--pass-pol", action='store_true', help='Dump password policy')
    egroup.add_argument("--lusers", action='store_true', help='Enumerate logged on users')
    egroup.add_argument("--wmi", metavar='QUERY', type=str, help='Issues the specified WMI query')
    egroup.add_argument("--wmi-namespace", metavar='NAMESPACE', default='//./root/cimv2', help='WMI Namespace (default: //./root/cimv2)')

    sgroup = parser.add_argument_group("Spidering", "Options for spidering shares")
    sgroup.add_argument("--spider", metavar='FOLDER', nargs='?', const='.', type=str, help='Folder to spider (default: root directory)')
    sgroup.add_argument("--content", action='store_true', help='Enable file content searching')
    sgroup.add_argument("--exclude-dirs", type=str, metavar='DIR_LIST', default='', help='Directories to exclude from spidering')
    esgroup = sgroup.add_mutually_exclusive_group()
    esgroup.add_argument("--pattern", nargs='+', help='Pattern(s) to search for in folders, filenames and file content')
    esgroup.add_argument("--regex", nargs='+', help='Regex(s) to search for in folders, filenames and file content')
    sgroup.add_argument("--depth", type=int, default=10, help='Spider recursion depth (default: 10)')

    cgroup = parser.add_argument_group("Command Execution", "Options for executing commands")
    cgroup.add_argument('--exec-method', choices={"wmiexec", "smbexec", "atexec"}, default=None, help="Method to execute the command. Ignored if in MSSQL mode (default: wmiexec)")
    cgroup.add_argument('--force-ps32', action='store_true', help='Force the PowerShell command to run in a 32-bit process')
    cgroup.add_argument('--no-output', action='store_true', help='Do not retrieve command output')
    xxxgroup = cgroup.add_mutually_exclusive_group()
    xxxgroup.add_argument("-x", metavar="COMMAND", dest='execute', help="Execute the specified command")
    xxxgroup.add_argument("-X", metavar="PS_COMMAND", dest='ps_execute', help='Execute the specified PowerShell command')

    mgroup = parser.add_argument_group("MSSQL Interaction", "Options for interacting with MSSQL DBs")
    mgroup.add_argument("--mssql", action='store_true', help='Switches CME into MSSQL Mode. If credentials are provided will authenticate against all discovered MSSQL DBs')
    mgroup.add_argument("--mssql-query", metavar='QUERY', type=str, help='Execute the specifed query against the MSSQL DB')
    mgroup.add_argument("--mssql-auth", choices={'windows', 'normal'}, default='windows', help='MSSQL authentication type to use (default: windows)')

    logger = CMEAdapter(setup_logger())
    first_run_setup(logger)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    cme_path = os.path.expanduser('~/.cme')

    module  = None
    server  = None
    context = None
    targets = []

    args = parser.parse_args()

    if args.verbose:
        setup_debug_logger()

    logging.debug(vars(args))

    db_path = os.path.join(cme_path, 'cme.db')
    # set the database connection to autocommit w/ isolation level
    db_connection = sqlite3.connect(db_path, check_same_thread=False)
    db_connection.text_factory = str
    db_connection.isolation_level = None
    db = CMEDatabase(db_connection)

    if args.username:
        for user in args.username:
            if os.path.exists(user):
                args.username.remove(user)
                args.username.append(open(user, 'r'))

    if args.password:
        for passw in args.password:
            if os.path.exists(passw):
                args.password.remove(passw)
                args.password.append(open(passw, 'r'))

    elif args.hash:
        for ntlm_hash in args.hash:
            if os.path.exists(ntlm_hash):
                args.hash.remove(ntlm_hash)
                args.hash.append(open(ntlm_hash, 'r'))

    if args.cred_id:
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

    for target in args.target:
        if os.path.exists(target):
            with open(target, 'r') as target_file:
                for target_entry in target_file:
                    targets.extend(parse_targets(target_entry))
        else:
            targets.extend(parse_targets(target))

    if args.list_modules or args.show_options:
        loader = ModuleLoader(args, db, logger)
        modules = loader.get_modules()

        if args.list_modules:
            for m in modules:
                logger.info('{:<20} {}'.format(m, modules[m]['description']))
            sys.exit(0)

        elif args.module and args.show_options:
            for m in modules.keys():
                if args.module.lower() == m.lower():
                    logger.info('{} module options:\n{}'.format(m, modules[m]['options']))
            sys.exit(0)

    if args.module:
        if os.geteuid() != 0:
            logger.error("I'm sorry {}, I'm afraid I can't let you do that (cause I need root)".format(getuser()))
            sys.exit(1)

        loader = ModuleLoader(args, db, logger)
        modules = loader.get_modules()

        if args.module:
            for m in modules.keys():
                if args.module.lower() == m.lower():
                    module, context, server = loader.init_module(modules[m]['path'])

    try:
        '''
            Open all the greenlet (as supposed to redlet??) threads
            Whoever came up with that name has a fetish for traffic lights
        '''
        pool = Pool(args.threads)
        jobs = [pool.spawn(Connection, args, db, str(target), module, server) for target in targets]

        #Dumping the NTDS.DIT and/or spidering shares can take a long time, so we ignore the thread timeout
        if args.ntds or args.spider:
            joinall(jobs)
        elif not args.ntds:
            for job in jobs:
                job.join(timeout=args.timeout)
    except KeyboardInterrupt:
        pass

    if server:
        server.shutdown()

    logger.info('KTHXBYE!')
