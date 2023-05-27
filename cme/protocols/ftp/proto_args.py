def proto_args(parser, std_parser, module_parser):
    ftp_parser = parser.add_parser('ftp', help="own stuff using FTP", parents=[std_parser, module_parser])
    ftp_parser.add_argument("--port", type=int, default=21, help="FTP port (default: 21)")

    # TODO: Create more options for the protocol
    # cgroup = ftp_parser.add_argument_group("FTP Access", "Options for enumerating your access")
    # cgroup.add_argument('--ls', metavar="COMMAND", dest='list_directory', help='List files in the directory')
    return parser