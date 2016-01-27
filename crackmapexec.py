#!/usr/bin/env python2

#This must be one of the first imports or else we get threading error on completion
from gevent import monkey
monkey.patch_all()

from gevent.pool import Pool
from gevent import joinall, sleep

from core.logger import *
from core.greenlets import main_greenlet
from core.settings import init_args
from core.servers.mimikatz import http_server, https_server
from argparse import RawTextHelpFormatter
from netaddr import IPAddress, IPRange, IPNetwork, AddrFormatError
from logging import DEBUG

import re
import argparse
import sys
import os

VERSION  = '2.3'
CODENAME = '\'Pink Bubbles\''

if sys.platform == 'linux2':
    if os.geteuid() is not 0:
        print_error('I needz r00tz!')
        sys.exit(1)

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
""".format(red('Version'),
           yellow(VERSION),
           red('Codename'),
           yellow(CODENAME)),

                                formatter_class=RawTextHelpFormatter,
                                version='{} - {}'.format(VERSION, CODENAME),
                                epilog='Hut Hut! Wat Wat!')

parser.add_argument("target", nargs='*', type=str, help="The target IP(s), range(s), CIDR(s), hostname(s), FQDN(s) or file(s) containg a list of targets")
parser.add_argument("-t", type=int, dest="threads", default=100, help="Set how many concurrent threads to use (defaults to 100)")
parser.add_argument("-u", metavar="USERNAME", dest='user', nargs='*', default=[], type=str, help="Username(s) or file(s) containing usernames")
parser.add_argument("-p", metavar="PASSWORD", dest='passwd', nargs= '*', default=[], type=str, help="Password(s) or file(s) containing passwords")
parser.add_argument("-H", metavar="HASH", dest='hash', nargs='*', default=[], type=str, help='NTLM hash(es) or file(s) containing NTLM hashes')
parser.add_argument("-C", metavar="COMBO_FILE", dest='combo_file', type=str, default=None, help="Combo file containing a list of domain\\username:password or username:password entries")
parser.add_argument('-k', action="store", dest='aesKey', metavar="HEX_KEY", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
parser.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, help="Domain name")
parser.add_argument("-n", metavar='NAMESPACE', dest='namespace', default='//./root/cimv2', help='WMI Namespace (default: //./root/cimv2)')
parser.add_argument("-s", metavar="SHARE", dest='share', default="C$", help="Specify a share (default: C$)")
parser.add_argument('--kerb', action="store_true", dest='kerb', help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters')
parser.add_argument("--port", dest='port', type=int, choices={139, 445}, default=445, help="SMB port (default: 445)")
parser.add_argument("--server", choices={'http', 'https'}, default='http', help='Use the selected server (defaults to http)')
parser.add_argument("--server-port", metavar='PORT', type=int, help='Start the server on the specified port')
#How much fail can we limit? can we fail at failing to limit? da da da dum
parser.add_argument("--fail-limit", metavar='LIMIT', type=int, default=None, help='The max number of failed login attempts allowed per host (default: None)')
parser.add_argument("--gfail-limit", metavar='LIMIT', type=int, default=None, help='The max number of failed login attempts allowed globally (default: None)')
parser.add_argument("--verbose", action='store_true', dest='verbose', help="Enable verbose output")

rgroup = parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
rgroup.add_argument("--sam", action='store_true', help='Dump SAM hashes from target systems')
rgroup.add_argument("--lsa", action='store_true', help='Dump LSA secrets from target systems')
rgroup.add_argument("--gpp-passwords", action='store_true', help='Retrieve plaintext passwords and other information for accounts pushed through Group Policy Preferences')
rgroup.add_argument("--ntds", choices={'vss', 'drsuapi', 'ninja'}, help="Dump the NTDS.dit from target DCs using the specifed method\n(drsuapi is the fastest)")
rgroup.add_argument("--ntds-history", action='store_true', help='Dump NTDS.dit password history')
rgroup.add_argument("--ntds-pwdLastSet", action='store_true', help='Shows the pwdLastSet attribute for each NTDS.dit account')
rgroup.add_argument("--mimikatz", action='store_true', help='Run Invoke-Mimikatz (sekurlsa::logonpasswords) on target systems')
rgroup.add_argument("--mimikatz-cmd", metavar='MIMIKATZ_CMD', help='Run Invoke-Mimikatz with the specified command')
rgroup.add_argument("--enable-wdigest", action='store_true', help="Creates the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1")
rgroup.add_argument("--disable-wdigest", action='store_true', help="Deletes the 'UseLogonCredential' registry key")

egroup = parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
egroup.add_argument("--shares", action="store_true", dest="enum_shares", help="List shares")
egroup.add_argument('--check-uac', action='store_true', dest='check_uac', help='Checks UAC status')
egroup.add_argument("--sessions", action='store_true', dest='enum_sessions', help='Enumerate active sessions')
egroup.add_argument('--disks', action='store_true', dest='enum_disks', help='Enumerate disks')
egroup.add_argument("--users", action='store_true', dest='enum_users', help='Enumerate users')
egroup.add_argument("--rid-brute", nargs='?', const=4000, metavar='MAX_RID', dest='rid_brute', help='Enumerate users by bruteforcing RID\'s (defaults to 4000)')
egroup.add_argument("--pass-pol", action='store_true', dest='pass_pol', help='Dump password policy')
egroup.add_argument("--lusers", action='store_true', dest='enum_lusers', help='Enumerate logged on users')
egroup.add_argument("--powerview", metavar='POWERVIEW_CMD', dest='powerview', help='Run the specified PowerView command')
egroup.add_argument("--wmi", metavar='QUERY', type=str, dest='wmi_query', help='Issues the specified WMI query')

sgroup = parser.add_argument_group("Spidering", "Options for spidering shares")
sgroup.add_argument("--spider", metavar='FOLDER', nargs='?', const='.', type=str, help='Folder to spider (defaults to top level directory)')
sgroup.add_argument("--content", dest='search_content', action='store_true', help='Enable file content searching')
sgroup.add_argument("--exclude-dirs", type=str, metavar='DIR_LIST', default='', dest='exclude_dirs', help='Directories to exclude from spidering')
sgroup.add_argument("--pattern", type=str, help='Pattern to search for in folders, filenames and file content')
sgroup.add_argument("--patternfile", type=str, help='File containing patterns to search for in folders, filenames and file content')
sgroup.add_argument("--depth", type=int, default=10, help='Spider recursion depth (default: 10)')

cgroup = parser.add_argument_group("Command Execution", "Options for executing commands")
cgroup.add_argument('--execm', choices={"wmi", "smbexec", "atexec"}, default="wmi", help="Method to execute the command (default: wmi)")
cgroup.add_argument('--ps-arch', default='auto', choices={'32', '64', 'auto'}, help='Process architecture all PowerShell code/commands should run in (default: auto)')
cgroup.add_argument('--no-output', action='store_true', dest='no_output', help='Do not retrieve command output')
cgroup.add_argument("-x", metavar="COMMAND", dest='command', help="Execute the specified command")
cgroup.add_argument("-X", metavar="PS_COMMAND", dest='pscommand', help='Excute the specified powershell command')

xgroup = parser.add_argument_group("Shellcode/EXE/DLL/Meterpreter Injection", "Options for injecting Shellcode/EXE/DLL/Meterpreter in memory using PowerShell")
xgroup.add_argument("--inject", choices={'shellcode', 'exe', 'dll', 'met_reverse_https', 'met_reverse_http'}, help='Inject Shellcode, EXE, DLL or Meterpreter')
xgroup.add_argument("--path", type=str, help='Path to the Shellcode/EXE/DLL you want to inject on the target systems (ignored if injecting Meterpreter)')
xgroup.add_argument('--procid', type=int, help='Process ID to inject the Shellcode/EXE/DLL/Meterpreter into (if omitted, will inject within the running PowerShell process)')
xgroup.add_argument("--exeargs", type=str, help='Arguments to pass to the EXE being reflectively loaded (ignored if not injecting an EXE)')
xgroup.add_argument("--met-options", nargs=2, metavar=('LHOST', 'LPORT'), dest='met_options', help='Meterpreter options (ignored if not injecting Meterpreter)')

bgroup = parser.add_argument_group("Filesystem Interaction", "Options for interacting with filesystems")
bgroup.add_argument("--list", metavar='PATH', nargs='?', const='.', type=str, help='List contents of a directory (defaults to top level directory)')
bgroup.add_argument("--download", nargs=2, metavar=('SRC', 'DST'), help="Download a file from the remote systems")
bgroup.add_argument("--upload", nargs=2, metavar=('SRC', 'DST'), help="Upload a file to the remote systems")
bgroup.add_argument("--delete", metavar="PATH", help="Delete a remote file")

wgroup = parser.add_argument_group("Service Interaction", "Options for interacting with Windows services")
wgroup.add_argument("--service", choices={'list', 'start', 'stop', 'delete', 'status', 'config', 'create', 'change'})
wgroup.add_argument("--name", dest='service_name', metavar='NAME', help='Service name')
wgroup.add_argument("--display", dest='service_display_name', metavar='NAME', help='Service display name')
wgroup.add_argument("--bin-path", dest='service_bin_path', metavar='PATH', help='Binary path')
wgroup.add_argument("--service-type", metavar='TYPE', help='Service type')
wgroup.add_argument("--start-type", metavar='TYPE', help='Service start type')
wgroup.add_argument("--start-name", metavar='NAME', help='Name of the account under which the service should run')
wgroup.add_argument("--start-pass", metavar='PASS', help='Password of the account whose name was specified with the --start-name parameter')

mgroup = parser.add_argument_group("MSSQL Interaction", "Options for interacting with MSSQL DB's")
mgroup.add_argument("--mssql", action='store_true', help='Authenticate with the provided credentials against the MSSQL service')
mgroup.add_argument("--mssql-port", default=1433, metavar='PORT', help='MSSQL service port (default: 1433)')
mgroup.add_argument("--mssql-query", metavar='QUERY', type=str, help='Execute the specifed query against the MSSQL DB')

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()
patterns    = []
targets     = []

if args.server == 'http':
    if args.server_port:
        args.http_port = args.server_port
    else:
        args.server_port = 80

if args.server == 'https':
    if args.server_port:
        args.https_port = args.server_port
    else:
        args.server_port = 443

init_args(args)

if args.verbose:
    setup_logger('_'.join(args.target), DEBUG)
else:
    setup_logger('_'.join(args.target))

###################### Just a bunch of error checking to make sure everythings good to go ######################

if args.inject:
    if not args.inject.startswith('met_'):
        if not args.path:
            print_error("You must specify a '--path' to the Shellcode/EXE/DLL to inject")
            shutdown(1)

        elif args.path:
            if not os.path.exists(args.path):
                print_error('Unable to find Shellcode/EXE/DLL at specified path')
                shutdown(1)

    elif args.inject.startswith('met_'):
        if not args.met_options:
            print_error("You must specify Meterpreter's handler options using '--met-options'" )
            shutdown(1)

if args.spider:
    
    if not args.pattern and not args.patternfile:
        print_error("You must specify a --pattern or --patternfile")
        shutdown(1)

    if args.patternfile:
        if not os.path.exists(args.patternfile):
            print_error("Unable to find pattern file at specified path")
            shutdown(1)

        for line in args.patternfile.readlines():
            line = line.rstrip()
            patterns.append(re.compile(line, re.IGNORECASE))

    patterns.extend(re.compile(patt, re.IGNORECASE) for patt in args.pattern.split(','))

    args.pattern = patterns
    args.exclude_dirs = args.exclude_dirs.split(',')

if args.combo_file and not os.path.exists(args.combo_file):
    print_error('Unable to find combo file at specified path')
    shutdown(1)

if args.service:
    if args.service in ['start', 'stop', 'delete', 'status', 'config', 'change']:
        if not args.service_name:
            print_error('You must specify a --name')
            shutdown(1)

    elif args.service == 'create':
        if not args.service_name or not args.service_display_name or not args.service_bin_path:
            print_error('You must specify --name, --display and --bin-path')
            shutdown(1)

if args.ntds_history or args.ntds_pwdLastSet:
    if not args.ntds:
        print_error('--ntds-history and --ntds-pwdLastSet require --ntds')
        shutdown(1)

################################################################################################################

def populate_targets(target):
    if '-' in target:
        ip_range = target.split('-')
        try:
            hosts = IPRange(ip_range[0], ip_range[1])
        except AddrFormatError:
            try:
                start_ip = IPAddress(ip_range[0])

                start_ip_words = list(start_ip.words)
                start_ip_words[-1] = ip_range[1]
                start_ip_words = [str(v) for v in start_ip_words]

                end_ip = IPAddress('.'.join(start_ip_words))

                t = IPRange(start_ip, end_ip)
            except AddrFormatError:
                t = target
    else:
        try:
            t = IPNetwork(target)
        except AddrFormatError:
            t = target

    if type(t) == IPNetwork or type(t) == IPRange:
        targets.extend(list(t))
    else:
        targets.append(t)

for target in args.target:
    if os.path.exists(target):
        with open(target, 'r') as target_file:
            for target_entry in target_file:
                populate_targets(target_entry)
    else:
        populate_targets(target)

if args.mimikatz or args.powerview or args.gpp_passwords or args.mimikatz_cmd or args.inject or args.ntds == 'ninja':
    if args.server == 'http':
        http_server(args.server_port)

    elif args.server == 'https':
        https_server(args.server_port)

def concurrency(targets):
    '''
        Open all the greenlet (as supposed to redlet??) threads 
        Whoever came up with that name has a fetish for traffic lights
    '''
    try:
        pool = Pool(args.threads)
        jobs = [pool.spawn(main_greenlet, str(target)) for target in targets]
        joinall(jobs)
    except KeyboardInterrupt:
        shutdown(0)

concurrency(targets)

if args.mimikatz or args.powerview or args.gpp_passwords or args.mimikatz_cmd or args.inject or args.ntds == 'ninja':
    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        shutdown(0)