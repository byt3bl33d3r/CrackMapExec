def proto_args(parser, std_parser, module_parser):
        smb_parser = parser.add_parser("smb", help="own stuff using SMB", parents=[std_parser, module_parser])
        smb_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[],
                                help="NTLM hash(es) or file(s) containing NTLM hashes")
        dgroup = smb_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action="store_true", help="authenticate locally to each target")
        smb_parser.add_argument("--port", type=int, choices={445, 139}, default=445, help="SMB port (default: 445)")
        smb_parser.add_argument("--share", metavar="SHARE", default="C$", help="specify a share (default: C$)")
        smb_parser.add_argument("--smb-server-port", default="445", help="specify a server port for SMB", type=int)
        smb_parser.add_argument("--gen-relay-list", metavar="OUTPUT_FILE",
                                help="outputs all hosts that don't require SMB signing to the specified file")
        smb_parser.add_argument("--smb-timeout", help="SMB connection timeout, default 2 secondes", type=int, default=2)
        smb_parser.add_argument("--laps", dest="laps", metavar="LAPS", type=str, help="LAPS authentification",
                                nargs="?", const="administrator")

        cgroup = smb_parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
        cgroup.add_argument("--sam", action="store_true", help="dump SAM hashes from target systems")
        cgroup.add_argument("--lsa", action="store_true", help="dump LSA secrets from target systems")
        cgroup.add_argument("--ntds", choices={"vss", "drsuapi"}, nargs="?", const="drsuapi",
                             help="dump the NTDS.dit from target DCs using the specifed method\n(default: drsuapi)")
        cgroup.add_argument("--dpapi", choices={"cookies","nosystem"}, nargs="*",
                             help="dump DPAPI secrets from target systems, can dump cookies if you add \"cookies\", will not dump SYSTEM dpapi if you add nosystem\n")
        # cgroup.add_argument("--ntds-history", action='store_true', help='Dump NTDS.dit password history')
        # cgroup.add_argument("--ntds-pwdLastSet", action='store_true', help='Shows the pwdLastSet attribute for each NTDS.dit account')

        ngroup = smb_parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
        ngroup.add_argument("--mkfile", action="store",
                            help="DPAPI option. File with masterkeys in form of {GUID}:SHA1")
        ngroup.add_argument("--pvk", action="store", help="DPAPI option. File with domain backupkey")
        ngroup.add_argument("--enabled", action="store_true", help="Only dump enabled targets from DC")
        ngroup.add_argument("--user", dest="userntds", type=str, help="Dump selected user from DC")

        egroup = smb_parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
        egroup.add_argument("--shares", action="store_true", help="enumerate shares and access")
        egroup.add_argument("--no-write-check", action="store_true", help="Skip write check on shares (avoid leaving traces when missing delete permissions)")

        egroup.add_argument("--filter-shares", nargs="+",
                            help="Filter share by access, option 'read' 'write' or 'read,write'")
        egroup.add_argument("--sessions", action="store_true", help="enumerate active sessions")
        egroup.add_argument("--disks", action="store_true", help="enumerate disks")
        egroup.add_argument("--loggedon-users-filter", action="store",
                            help="only search for specific user, works with regex")
        egroup.add_argument("--loggedon-users", action="store_true", help="enumerate logged on users")
        egroup.add_argument("--users", nargs="?", const="", metavar="USER",
                            help="enumerate domain users, if a user is specified than only its information is queried.")
        egroup.add_argument("--groups", nargs="?", const="", metavar="GROUP",
                            help="enumerate domain groups, if a group is specified than its members are enumerated")
        egroup.add_argument("--computers", nargs="?", const="", metavar="COMPUTER", help="enumerate computer users")
        egroup.add_argument("--local-groups", nargs="?", const="", metavar="GROUP",
                            help="enumerate local groups, if a group is specified then its members are enumerated")
        egroup.add_argument("--pass-pol", action="store_true", help="dump password policy")
        egroup.add_argument("--rid-brute", nargs="?", type=int, const=4000, metavar="MAX_RID",
                            help="enumerate users by bruteforcing RID's (default: 4000)")
        egroup.add_argument("--wmi", metavar="QUERY", type=str, help="issues the specified WMI query")
        egroup.add_argument("--wmi-namespace", metavar="NAMESPACE", default="root\\cimv2",
                            help="WMI Namespace (default: root\\cimv2)")

        sgroup = smb_parser.add_argument_group("Spidering", 'Options for spidering shares')
        sgroup.add_argument("--spider", metavar="SHARE", type=str, help="share to spider")
        sgroup.add_argument("--spider-folder", metavar="FOLDER", default=".", type=str,
                            help="folder to spider (default: root share directory)")
        sgroup.add_argument("--content", action="store_true", help="enable file content searching")
        sgroup.add_argument("--exclude-dirs", type=str, metavar="DIR_LIST", default="",
                            help="directories to exclude from spidering")
        segroup = sgroup.add_mutually_exclusive_group()
        segroup.add_argument("--pattern", nargs="+",
                             help="pattern(s) to search for in folders, filenames and file content")
        segroup.add_argument("--regex", nargs="+", help="regex(s) to search for in folders, filenames and file content")
        sgroup.add_argument("--depth", type=int, default=None,
                            help="max spider recursion depth (default: infinity & beyond)")
        sgroup.add_argument("--only-files", action="store_true", help="only spider files")

        tgroup = smb_parser.add_argument_group("Files", "Options for put and get remote files")
        tgroup.add_argument("--put-file", nargs=2, metavar="FILE", help="Put a local file into remote target, ex: whoami.txt \\\\Windows\\\\Temp\\\\whoami.txt")
        tgroup.add_argument("--get-file", nargs=2, metavar="FILE", help="Get a remote file, ex: \\\\Windows\\\\Temp\\\\whoami.txt whoami.txt")
        tgroup.add_argument("--append-host", action="store_true", help="append the host to the get-file filename")

        cgroup = smb_parser.add_argument_group("Command Execution", "Options for executing commands")
        cgroup.add_argument("--exec-method", choices={"wmiexec", "mmcexec", "smbexec", "atexec"}, default=None,
                            help="method to execute the command. Ignored if in MSSQL mode (default: wmiexec)")
        cgroup.add_argument("--dcom-timeout", help="DCOM connection timeout, default is 5 secondes", type=int, default=5)
        cgroup.add_argument("--get-output-tries", help="Number of times atexec/smbexec/mmcexec tries to get results, default is 5", type=int, default=5)
        cgroup.add_argument("--codec", default="utf-8",
                            help="Set encoding used (codec) from the target's output (default "
                                 "\"utf-8\"). If errors are detected, run chcp.com at the target, "
                                 "map the result with "
                                 "https://docs.python.org/3/library/codecs.html#standard-encodings and then execute "
                                 "again with --codec and the corresponding codec")
        cgroup.add_argument("--force-ps32", action="store_true",
                            help="force the PowerShell command to run in a 32-bit process")
        cgroup.add_argument("--no-output", action="store_true", help="do not retrieve command output")
        cegroup = cgroup.add_mutually_exclusive_group()
        cegroup.add_argument("-x", metavar="COMMAND", dest="execute", help="execute the specified command")
        cegroup.add_argument("-X", metavar="PS_COMMAND", dest="ps_execute", help="execute the specified PowerShell command")
        psgroup = smb_parser.add_argument_group("Powershell Obfuscation", "Options for PowerShell script obfuscation")
        psgroup.add_argument("--obfs", action="store_true", help="Obfuscate PowerShell scripts")
        psgroup.add_argument('--amsi-bypass', nargs=1, metavar="FILE", help='File with a custom AMSI bypass')
        psgroup.add_argument("--clear-obfscripts", action="store_true", help="Clear all cached obfuscated PowerShell scripts")

        return parser