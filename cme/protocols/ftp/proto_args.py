def proto_args(parser, std_parser, module_parser):
    ftp_parser = parser.add_parser("ftp", help="own stuff using FTP", parents=[std_parser, module_parser])
    ftp_parser.add_argument(
        "--no-bruteforce",
        action="store_true",
        help="No spray when using file for username and password (user1 => password1, user2 => password2",
    )
    ftp_parser.add_argument("--port", type=int, default=21, help="FTP port (default: 21)")
    ftp_parser.add_argument(
        "--continue-on-success",
        action="store_true",
        help="continues authentication attempts even after successes",
    )

    cgroup = ftp_parser.add_argument_group("FTP Access", "Options for enumerating your access")
    cgroup.add_argument("--ls", action="store_true", help="List files in the directory")
    return parser