def proto_args(parser, std_parser, module_parser):
    winrm_parser = parser.add_parser("winrm", help="own stuff using WINRM", parents=[std_parser, module_parser])
    winrm_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")
    winrm_parser.add_argument("--port", type=int, default=0, help="Custom WinRM port")
    winrm_parser.add_argument("--ssl", action="store_true", help="Connect to SSL Enabled WINRM")
    winrm_parser.add_argument("--ignore-ssl-cert", action="store_true", help="Ignore Certificate Verification")
    winrm_parser.add_argument("--laps", dest="laps", metavar="LAPS", type=str, help="LAPS authentification", nargs="?", const="administrator")
    winrm_parser.add_argument("--http-timeout", dest="http_timeout", type=int, default=10, help="HTTP timeout for WinRM connections")
    dgroup = winrm_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, default=None, help="domain to authenticate to")
    dgroup.add_argument("--local-auth", action="store_true", help="authenticate locally to each target")

    cgroup = winrm_parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
    cegroup = cgroup.add_mutually_exclusive_group()
    cegroup.add_argument("--sam", action="store_true", help="dump SAM hashes from target systems")
    cegroup.add_argument("--lsa", action="store_true", help="dump LSA secrets from target systems")

    cgroup = winrm_parser.add_argument_group("Command Execution", "Options for executing commands")
    cgroup.add_argument("--no-output", action="store_true", help="do not retrieve command output")
    cgroup.add_argument("-x", metavar="COMMAND", dest="execute", help="execute the specified command")
    cgroup.add_argument("-X", metavar="PS_COMMAND", dest="ps_execute", help="execute the specified PowerShell command")

    return parser