def proto_args(parser, std_parser, module_parser):
    ssh_parser = parser.add_parser("ssh", help="own stuff using SSH", parents=[std_parser, module_parser])
    ssh_parser.add_argument("--key-file", type=str, help="Authenticate using the specified private key. Treats the password parameter as the key's passphrase.")
    ssh_parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")

    cgroup = ssh_parser.add_argument_group("Command Execution", "Options for executing commands")
    cgroup.add_argument("--no-output", action="store_true", help="do not retrieve command output")
    cgroup.add_argument("-x", metavar="COMMAND", dest="execute", help="execute the specified command")
    cgroup.add_argument("--remote-enum", action="store_true", help="executes remote commands for enumeration")

    return parser
