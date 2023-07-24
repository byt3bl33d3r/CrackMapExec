from argparse import _StoreTrueAction

def proto_args(parser, std_parser, module_parser):
    mssql_parser = parser.add_parser('mssql', help="own stuff using MSSQL", parents=[std_parser, module_parser])
    mssql_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
    mssql_parser.add_argument("--port", default=1433, type=int, metavar='PORT', help='MSSQL port (default: 1433)')
    mssql_parser.add_argument("-q", "--query", dest='mssql_query', metavar='QUERY', type=str, help='execute the specified query against the MSSQL DB')
    no_smb_arg = mssql_parser.add_argument("--no-smb", action=get_conditional_action(_StoreTrueAction), make_required=[], help='No smb connection')

    dgroup = mssql_parser.add_mutually_exclusive_group()
    domain_arg = dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, help="domain name")
    dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')
    no_smb_arg.make_required = [domain_arg]

    cgroup = mssql_parser.add_argument_group("Command Execution", "options for executing commands")
    cgroup.add_argument('--force-ps32', action='store_true', help='force the PowerShell command to run in a 32-bit process')
    cgroup.add_argument('--no-output', action='store_true', help='do not retrieve command output')
    xgroup = cgroup.add_mutually_exclusive_group()
    xgroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")
    xgroup.add_argument("-X", metavar="PS_COMMAND", dest='ps_execute', help='execute the specified PowerShell command')

    psgroup = mssql_parser.add_argument_group('Powershell Obfuscation', "Options for PowerShell script obfuscation")
    psgroup.add_argument('--obfs', action='store_true', help='Obfuscate PowerShell scripts')
    psgroup.add_argument('--clear-obfscripts', action='store_true', help='Clear all cached obfuscated PowerShell scripts')

    tgroup = mssql_parser.add_argument_group("Files", "Options for put and get remote files")
    tgroup.add_argument("--put-file", nargs=2, metavar="FILE", help='Put a local file into remote target, ex: whoami.txt C:\\Windows\\Temp\\whoami.txt')
    tgroup.add_argument("--get-file", nargs=2, metavar="FILE", help='Get a remote file, ex: C:\\Windows\\Temp\\whoami.txt whoami.txt')

    return parser

def get_conditional_action(baseAction):
    class ConditionalAction(baseAction):
        def __init__(self, option_strings, dest, **kwargs):
            x = kwargs.pop('make_required', [])
            super(ConditionalAction, self).__init__(option_strings, dest, **kwargs)
            self.make_required = x

        def __call__(self, parser, namespace, values, option_string=None):
            for x in self.make_required:
                x.required = True
            super(ConditionalAction, self).__call__(parser, namespace, values, option_string)

    return ConditionalAction