#!/usr/bin/env python2

#This must be one of the first imports or else we get threading error on completion
from gevent import monkey
monkey.patch_all()

from gevent.pool import Pool
from gevent import joinall, sleep
from core.connector import connector
from core.database import CMEDatabase
from core.cmeserver import CMEServer
from threading import Thread
from logging import getLogger
from argparse import RawTextHelpFormatter
from core.logger import setup_logger, setup_debug_logger, CMEAdapter
from core.context import Context
from core.helpers import highlight
from core.targetparser import parse_targets
import getpass
import sqlite3
import imp
import argparse
import os
import logging
import sys

VERSION  = '3.0'
CODENAME = '\'So looong gay boy!\''

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
                                epilog='HA! Made you look!')

parser.add_argument("target", nargs='*', type=str, help="The target IP(s), range(s), CIDR(s), hostname(s), FQDN(s) or file(s) containg a list of targets")
parser.add_argument("-t", type=int, dest="threads", default=100, help="Set how many concurrent threads to use (defaults to 100)")
parser.add_argument('-id', metavar="CRED_ID", type=int, dest='cred_id', help='Database credential ID to use for authentication')
parser.add_argument("-u", metavar="USERNAME", dest='username', nargs='*', default=[], help="Username(s) or file(s) containing usernames")
parser.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, help="Domain name")
msgroup = parser.add_mutually_exclusive_group()
msgroup.add_argument("-p", metavar="PASSWORD", dest='password', nargs= '*', default=[], help="Password(s) or file(s) containing passwords")
msgroup.add_argument("-H", metavar="HASH", dest='hash', nargs='*', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
parser.add_argument("-m", "--module", metavar='MODULE', dest='module', help='Payload module to use')
parser.add_argument('-o', metavar='MODULE_OPTION', nargs='*', default=[], dest='module_options', help='Payload module options')
parser.add_argument('--module-info', action='store_true', dest='module_info', help='Display module info')
parser.add_argument("--share", metavar="SHARE", dest='share', default="C$", help="Specify a share (default: C$)")
parser.add_argument("--smb-port", dest='smb_port', type=int, choices={139, 445}, default=445, help="SMB port (default: 445)")
parser.add_argument("--mssql-port", dest='mssql_port', default=1433, type=int, metavar='PORT', help='MSSQL port (default: 1433)')
parser.add_argument("--server", choices={'http', 'https'}, default='https', help='Use the selected server (default: https)')
parser.add_argument("--server-host", type=str, default='0.0.0.0', metavar='HOST', help='IP to bind the server to (default: 0.0.0.0)')
parser.add_argument("--server-port", dest='server_port', metavar='PORT', type=int, help='Start the server on the specified port')
parser.add_argument("--local-auth", dest='local_auth', action='store_true', help='Authenticate locally to each target')
parser.add_argument("--timeout", default=20, type=int, help='Max timeout in seconds of each thread (default: 20)')
parser.add_argument("--verbose", action='store_true', dest='verbose', help="Enable verbose output")

rgroup = parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
rgroup.add_argument("--sam", action='store_true', help='Dump SAM hashes from target systems')
rgroup.add_argument("--lsa", action='store_true', help='Dump LSA secrets from target systems')
rgroup.add_argument("--ntds", choices={'vss', 'drsuapi'}, help="Dump the NTDS.dit from target DCs using the specifed method\n(drsuapi is the fastest)")
rgroup.add_argument("--ntds-history", action='store_true', help='Dump NTDS.dit password history')
rgroup.add_argument("--ntds-pwdLastSet", action='store_true', help='Shows the pwdLastSet attribute for each NTDS.dit account')
rgroup.add_argument("--wdigest", choices={'enable', 'disable'}, help="Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1")

egroup = parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
egroup.add_argument("--shares", action="store_true", dest="enum_shares", help="Enumerate shares and access")
egroup.add_argument('--uac', action='store_true', help='Checks UAC status')
egroup.add_argument("--sessions", action='store_true', dest='enum_sessions', help='Enumerate active sessions')
egroup.add_argument('--disks', action='store_true', dest='enum_disks', help='Enumerate disks')
egroup.add_argument("--users", action='store_true', dest='enum_users', help='Enumerate users')
egroup.add_argument("--rid-brute", nargs='?', const=4000, metavar='MAX_RID', dest='rid_brute', help='Enumerate users by bruteforcing RID\'s (default: 4000)')
egroup.add_argument("--pass-pol", action='store_true', dest='pass_pol', help='Dump password policy')
egroup.add_argument("--lusers", action='store_true', dest='enum_lusers', help='Enumerate logged on users')
egroup.add_argument("--wmi", metavar='QUERY', type=str, dest='wmi_query', help='Issues the specified WMI query')
egroup.add_argument("--wmi-namespace", metavar='NAMESPACE', dest='wmi_namespace', default='//./root/cimv2', help='WMI Namespace (default: //./root/cimv2)')

sgroup = parser.add_argument_group("Spidering", "Options for spidering shares")
sgroup.add_argument("--spider", metavar='FOLDER', nargs='?', const='.', type=str, help='Folder to spider (default: root directory)')
sgroup.add_argument("--content", dest='search_content', action='store_true', help='Enable file content searching')
sgroup.add_argument("--exclude-dirs", type=str, metavar='DIR_LIST', default='', dest='exclude_dirs', help='Directories to exclude from spidering')
esgroup = sgroup.add_mutually_exclusive_group()
esgroup.add_argument("--pattern", nargs='*', help='Pattern(s) to search for in folders, filenames and file content')
esgroup.add_argument("--regex", nargs='*', help='Regex(s) to search for in folders, filenames and file content')
sgroup.add_argument("--depth", type=int, default=10, help='Spider recursion depth (default: 10)')

cgroup = parser.add_argument_group("Command Execution", "Options for executing commands")
cgroup.add_argument('--exec-method', choices={"wmiexec", "smbexec", "atexec"}, default=None, help="Method to execute the command. Ignored if in MSSQL mode (default: wmiexec)")
cgroup.add_argument('--force-ps32', action='store_true', help='Force the PowerShell command to run in a 32-bit process')
cgroup.add_argument('--no-output', action='store_true', dest='no_output', help='Do not retrieve command output')
cgroup.add_argument("-x", metavar="COMMAND", dest='command', help="Execute the specified command")
cgroup.add_argument("-X", metavar="PS_COMMAND", dest='pscommand', help='Execute the specified PowerShell command')

mgroup = parser.add_argument_group("MSSQL Interaction", "Options for interacting with MSSQL DBs")
mgroup.add_argument("--mssql", action='store_true', help='Switches CME into MSSQL Mode. If credentials are provided will authenticate against all discovered MSSQL DBs')
mgroup.add_argument("--mssql-query", metavar='QUERY', type=str, help='Execute the specifed query against the MSSQL DB')

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

module  = None
server  = None
context = None
targets = []
server_port_dict = {'http': 80, 'https': 443}

args = parser.parse_args()

if args.verbose:
    setup_debug_logger()

logger = CMEAdapter(setup_logger())

if not os.path.exists('data/cme.db'):
    logger.error('Could not find CME database, did you run the setup_database.py script?')
    sys.exit(1)

# set the database connection to autocommit w/ isolation level
db_connection = sqlite3.connect('data/cme.db', check_same_thread=False)
db_connection.text_factory = str
db_connection.isolation_level = None
db = CMEDatabase(db_connection)

if args.cred_id:
    try:
        c_id, credtype, domain, username, password = db.get_credentials(filterTerm=args.cred_id)[0]
        args.username = [username]

        if not args.domain:
            args.domain = domain
        if credtype == 'hash':
            args.hash = [password]
        elif credtype == 'plaintext':
            args.password = [password]
    except IndexError:
        logger.error("Invalid database credential ID!")
        sys.exit(1)
else:
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

if args.module:
    if not os.path.exists(args.module):
        logger.error('Path to module invalid!')
        sys.exit(1)
    else:
        module = imp.load_source('payload_module', args.module).CMEModule()
        if not hasattr(module, 'name'):
            logger.error('Module missing the name variable!')
            sys.exit(1)

        elif not hasattr(module, 'options'):
            logger.error('Module missing the options function!')
            sys.exit(1)

        elif not hasattr(module, 'on_login') and not (module, 'on_admin_login'):
            logger.error('Module missing the on_login/on_admin_login function(s)!')
            sys.exit(1)

        if args.module_info:
            logger.info('{} module description:'.format(module.name))
            print module.__doc__
            logger.info('{} module options:'.format(module.name))
            print module.options.__doc__
            sys.exit(0)

        module_logger = CMEAdapter(getLogger('CME'), {'module': module.name.upper()})
        context = Context(db, module_logger, args)

        module_options = {}

        for option in args.module_options:
            key, value = option.split('=', 1)
            module_options[str(key).upper()] = value

        module.options(context, module_options)

        if hasattr(module, 'on_request') or hasattr(module, 'has_response'):

            if hasattr(module, 'required_server'):
                args.server = getattr(module, 'required_server')

            if not args.server_port:
                args.server_port = server_port_dict[args.server]

            if args.server_port <= 1024 and os.geteuid() is not 0:
                logger.error("I'm sorry {}, I'm afraid I can't let you do that".format(getpass.getuser()))
                sys.exit(1)

            server = CMEServer(module, context, args.server_host, args.server_port, args.server)
            server.start()

for target in args.target:
    if os.path.exists(target):
        with open(target, 'r') as target_file:
            for target_entry in target_file:
                targets.extend(parse_targets(target_entry))
    else:
        targets.extend(parse_targets(target))

try:
    '''
        Open all the greenlet (as supposed to redlet??) threads 
        Whoever came up with that name has a fetish for traffic lights
    '''
    pool = Pool(args.threads)
    jobs = [pool.spawn(connector, str(target), args, db, module, context, server) for target in targets]

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