from argparse import _StoreTrueAction

def proto_args(parser, std_parser, module_parser):
    ldap_parser = parser.add_parser('ldap', help="own stuff using LDAP", parents=[std_parser, module_parser])
    ldap_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
    ldap_parser.add_argument("--port", type=int, choices={389, 636}, default=389, help="LDAP port (default: 389)")
    no_smb_arg = ldap_parser.add_argument("--no-smb", action=get_conditional_action(_StoreTrueAction), make_required=[], help='No smb connection')

    dgroup = ldap_parser.add_mutually_exclusive_group()
    domain_arg = dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, default=None, help="domain to authenticate to")
    dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')
    no_smb_arg.make_required = [domain_arg]

    egroup = ldap_parser.add_argument_group("Retrevie hash on the remote DC", "Options to get hashes from Kerberos")
    egroup.add_argument("--asreproast", help="Get AS_REP response ready to crack with hashcat")
    egroup.add_argument("--kerberoasting", help='Get TGS ticket ready to crack with hashcat')

    vgroup = ldap_parser.add_argument_group("Retrieve useful information on the domain", "Options to to play with Kerberos")
    vgroup.add_argument("--trusted-for-delegation", action="store_true", help="Get the list of users and computers with flag TRUSTED_FOR_DELEGATION")
    vgroup.add_argument("--password-not-required", action="store_true", help="Get the list of users with flag PASSWD_NOTREQD")
    vgroup.add_argument("--admin-count", action="store_true", help="Get objets that had the value adminCount=1")
    vgroup.add_argument("--users", action="store_true", help="Enumerate enabled domain users")
    vgroup.add_argument("--groups", action="store_true", help="Enumerate domain groups")
    vgroup.add_argument("--dc-list", action="store_true", help="Enumerate Domain Controllers")
    vgroup.add_argument("--get-sid", action="store_true", help="Get domain sid")

    ggroup = ldap_parser.add_argument_group("Retrevie gmsa on the remote DC", "Options to play with gmsa")
    ggroup.add_argument("--gmsa", action="store_true", help="Enumerate GMSA passwords")
    ggroup.add_argument("--gmsa-convert-id", help="Get the secret name of specific gmsa or all gmsa if no gmsa provided")
    ggroup.add_argument("--gmsa-decrypt-lsa", help="Decrypt the gmsa encrypted value from LSA")

    bgroup = ldap_parser.add_argument_group("Bloodhound scan", "Options to play with bloodhoud")
    bgroup.add_argument("--bloodhound", action="store_true", help="Perform bloodhound scan")
    bgroup.add_argument("-ns", '--nameserver', help="Custom DNS IP")
    bgroup.add_argument("-c", "--collection", help="Which information to collect. Supported: Group, LocalAdmin, Session, Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, Container, ObjectProps, ACL, All. You can specify more than one by separating them with a comma. (default: Default)'")

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