import argparse
import sys
from argparse import RawTextHelpFormatter
from cme.loaders.protocol_loader import protocol_loader
from cme.helpers.logger import highlight
from termcolor import colored

def gen_cli_args():

    VERSION  = '5.2.2'
    CODENAME = "The Dark Knight"

    p_loader =  protocol_loader()
    protocols = p_loader.get_protocols()

    parser = argparse.ArgumentParser(description=f"""
      ______ .______           ___        ______  __  ___ .___  ___.      ___      .______    _______ ___   ___  _______   ______
     /      ||   _  \         /   \      /      ||  |/  / |   \/   |     /   \     |   _  \  |   ____|\  \ /  / |   ____| /      |
    |  ,----'|  |_)  |       /  ^  \    |  ,----'|  '  /  |  \  /  |    /  ^  \    |  |_)  | |  |__    \  V  /  |  |__   |  ,----'
    |  |     |      /       /  /_\  \   |  |     |    <   |  |\/|  |   /  /_\  \   |   ___/  |   __|    >   <   |   __|  |  |
    |  `----.|  |\  \----. /  _____  \  |  `----.|  .  \  |  |  |  |  /  _____  \  |  |      |  |____  /  .  \  |  |____ |  `----.
     \______|| _| `._____|/__/     \__\  \______||__|\__\ |__|  |__| /__/     \__\ | _|      |_______|/__/ \__\ |_______| \______|

                                                A swiss army knife for pentesting networks
                                    Forged by @byt3bl33d3r and @mpgn_x64 using the powah of dank memes

                                           {colored("Exclusive release for Porchetta Industries users", "magenta")}

                                                   {highlight('Version', 'red')} : {highlight(VERSION)}
                                                   {highlight('Codename', 'red')}: {highlight(CODENAME)}
""",

    formatter_class=RawTextHelpFormatter)

    parser.add_argument("-t", type=int, dest="threads", default=100, help="set how many concurrent threads to use (default: 100)")
    parser.add_argument("--timeout", default=None, type=int, help='max timeout in seconds of each thread (default: None)')
    parser.add_argument("--jitter", metavar='INTERVAL', type=str, help='sets a random delay between each connection (default: None)')
    parser.add_argument("--darrell", action='store_true', help='give Darrell a hand')
    parser.add_argument("--verbose", action='store_true', help="enable verbose output")

    subparsers = parser.add_subparsers(title='protocols', dest='protocol', description='available protocols')

    std_parser = argparse.ArgumentParser(add_help=False)
    std_parser.add_argument("target", nargs='*', type=str, help="the target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets, NMap XML or .Nessus file(s)")
    std_parser.add_argument('-id', metavar="CRED_ID", nargs='+', default=[], type=str, dest='cred_id', help='database credential ID(s) to use for authentication')
    std_parser.add_argument("-u", metavar="USERNAME", dest='username', nargs='+', default=[], help="username(s) or file(s) containing usernames")
    std_parser.add_argument("-p", metavar="PASSWORD", dest='password', nargs='+', default=[], help="password(s) or file(s) containing passwords")
    std_parser.add_argument("-k", "--kerberos", action='store_true', help="Use Kerberos authentication from ccache file (KRB5CCNAME)")
    std_parser.add_argument("--export", metavar="EXPORT", nargs='+', help="Export result into a file, probably buggy")
    std_parser.add_argument("--aesKey",  metavar="AESKEY", nargs='+', help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    std_parser.add_argument("--kdcHost", metavar="KDCHOST", help="FQDN of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")

    fail_group = std_parser.add_mutually_exclusive_group()
    fail_group.add_argument("--gfail-limit", metavar='LIMIT', type=int, help='max number of global failed login attempts')
    fail_group.add_argument("--ufail-limit", metavar='LIMIT', type=int, help='max number of failed login attempts per username')
    fail_group.add_argument("--fail-limit", metavar='LIMIT', type=int, help='max number of failed login attempts per host')

    module_parser = argparse.ArgumentParser(add_help=False)
    mgroup = module_parser.add_mutually_exclusive_group()
    mgroup.add_argument("-M", "--module", metavar='MODULE', help='module to use')
    #mgroup.add_argument('-MC','--module-chain', metavar='CHAIN_COMMAND', help='Payload module chain command string to run')
    module_parser.add_argument('-o', metavar='MODULE_OPTION', nargs='+', default=[], dest='module_options', help='module options')
    module_parser.add_argument('-L', '--list-modules', action='store_true', help='list available modules')
    module_parser.add_argument('--options', dest='show_module_options', action='store_true', help='display module options')
    module_parser.add_argument("--server", choices={'http', 'https'}, default='https', help='use the selected server (default: https)')
    module_parser.add_argument("--server-host", type=str, default='0.0.0.0', metavar='HOST', help='IP to bind the server to (default: 0.0.0.0)')
    module_parser.add_argument("--server-port", metavar='PORT', type=int, help='start the server on the specified port')
    module_parser.add_argument("--connectback-host", type=str, metavar='CHOST', help='IP for the remote system to connect back to (default: same as server-host)')

    for protocol in protocols.keys():
        protocol_object = p_loader.load_protocol(protocols[protocol]['path'])
        subparsers = getattr(protocol_object, protocol).proto_args(subparsers, std_parser, module_parser)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    return args
