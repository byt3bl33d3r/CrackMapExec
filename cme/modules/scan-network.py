# Credit to https://twitter.com/snovvcrash/status/1550518555438891009
# Credit to https://github.com/dirkjanm/adidnsdump @_dirkjan
# module by @mpgn_x64

from os.path import expanduser
import codecs
import socket
from builtins import str
from datetime import datetime
from struct import unpack

import dns.name
import dns.resolver
from impacket.structure import Structure
from ldap3 import LEVEL


def get_dns_zones(connection, root, debug=False):
    connection.search(root, "(objectClass=dnsZone)", search_scope=LEVEL, attributes=["dc"])
    zones = []
    for entry in connection.response:
        if entry["type"] != "searchResEntry":
            continue
        zones.append(entry["attributes"]["dc"])
    return zones


def get_dns_resolver(server, context):
    # Create a resolver object
    dnsresolver = dns.resolver.Resolver()
    # Is our host an IP? In that case make sure the server IP is used
    # if not assume lookups are working already
    try:
        if server.startswith("ldap://"):
            server = server[7:]
        if server.startswith("ldaps://"):
            server = server[8:]
        socket.inet_aton(server)
        dnsresolver.nameservers = [server]
    except socket.error:
        context.info("Using System DNS to resolve unknown entries. Make sure resolving your" " target domain works here or specify an IP as target host to use that" " server for queries")
    return dnsresolver


def ldap2domain(ldap):
    return re.sub(",DC=", ".", ldap[ldap.lower().find("dc=") :], flags=re.I)[3:]


def new_record(rtype, serial):
    nr = DNS_RECORD()
    nr["Type"] = rtype
    nr["Serial"] = serial
    nr["TtlSeconds"] = 180
    # From authoritive zone
    nr["Rank"] = 240
    return nr


# From: https://docs.microsoft.com/en-us/windows/win32/dns/dns-constants
RECORD_TYPE_MAPPING = {
    0: "ZERO",
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    # 15: 'MX',
    # 16: 'TXT',
    28: "AAAA",
    33: "SRV",
}


def searchResEntry_to_dict(results):
    data = {}
    for attr in results["attributes"]:
        key = str(attr["type"])
        value = str(attr["vals"][0])
        data[key] = value
    return data


class CMEModule:
    name = "get-network"
    description = ""
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        ALL      Get DNS and IP (default: false)
        ONLY_HOSTS    Get DNS only (no ip) (default: false)
        """

        self.showall = False
        self.showhosts = False
        self.showip = True

        if module_options and "ALL" in module_options:
            if module_options["ALL"].lower() == "true" or module_options["ALL"] == "1":
                self.showall = True
            else:
                print("Could not parse ALL option.")
        if module_options and "IP" in module_options:
            if module_options["IP"].lower() == "true" or module_options["IP"] == "1":
                self.showip = True
            else:
                print("Could not parse ONLY_HOSTS option.")
        if module_options and "ONLY_HOSTS" in module_options:
            if module_options["ONLY_HOSTS"].lower() == "true" or module_options["ONLY_HOSTS"] == "1":
                self.showhosts = True
            else:
                print("Could not parse ONLY_HOSTS option.")

    def on_login(self, context, connection):
        zone = ldap2domain(connection.baseDN)
        dnsroot = "CN=MicrosoftDNS,DC=DomainDnsZones,%s" % connection.baseDN
        searchtarget = "DC=%s,%s" % (zone, dnsroot)
        context.log.display("Querying zone for records")
        sfilter = "(DC=*)"

        try:
            list_sites = connection.ldapConnection.search(
                searchBase=searchtarget,
                searchFilter=sfilter,
                attributes=["dnsRecord", "dNSTombstoned", "name"],
                sizeLimit=100000,
            )
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, giving up and processing the" " data received")
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                list_sites = e.getAnswers()
                pass
            else:
                raise
        targetentry = None
        dnsresolver = get_dns_resolver(connection.host, context.log)

        outdata = []

        for item in list_sites:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            site = searchResEntry_to_dict(item)
            recordname = site["name"]

            if "dnsRecord" in site:
                record = bytes(site["dnsRecord"].encode("latin1"))
                dr = DNS_RECORD(record)
                if RECORD_TYPE_MAPPING[dr["Type"]] == "A":
                    if dr["Type"] == 1:
                        address = DNS_RPC_RECORD_A(dr["Data"])
                        if str(recordname) != "DomainDnsZones" and str(recordname) != "ForestDnsZones":
                            outdata.append(
                                {
                                    "name": recordname,
                                    "type": RECORD_TYPE_MAPPING[dr["Type"]],
                                    "value": address.formatCanonical(),
                                }
                            )
                    if dr["Type"] in [a for a in RECORD_TYPE_MAPPING if RECORD_TYPE_MAPPING[a] in ["CNAME", "NS", "PTR"]]:
                        address = DNS_RPC_RECORD_NODE_NAME(dr["Data"])
                        if str(recordname) != "DomainDnsZones" and str(recordname) != "ForestDnsZones":
                            outdata.append(
                                {
                                    "name": recordname,
                                    "type": RECORD_TYPE_MAPPING[dr["Type"]],
                                    "value": address[list(address.fields)[0]].toFqdn(),
                                }
                            )
                    elif dr["Type"] == 28:
                        address = DNS_RPC_RECORD_AAAA(dr["Data"])
                        if str(recordname) != "DomainDnsZones" and str(recordname) != "ForestDnsZones":
                            outdata.append(
                                {
                                    "name": recordname,
                                    "type": RECORD_TYPE_MAPPING[dr["Type"]],
                                    "value": address.formatCanonical(),
                                }
                            )

        context.log.highlight("Found %d records" % len(outdata))
        path = expanduser("~/.cme/logs/{}_network_{}.log".format(connection.domain, datetime.now().strftime("%Y-%m-%d_%H%M%S")))
        with codecs.open(path, "w", "utf-8") as outfile:
            for row in outdata:
                if self.showhosts:
                    outfile.write("{}\n".format(row["name"] + "." + connection.domain))
                elif self.showall:
                    outfile.write("{} \t {}\n".format(row["name"] + "." + connection.domain, row["value"]))
                else:
                    outfile.write("{}\n".format(row["value"]))
        context.log.success("Dumped {} records to {}".format(len(outdata), path))
        if not self.showall and not self.showhosts:
            context.log.display("To extract CIDR from the {} ip, run  the following command: cat" " your_file | mapcidr -aa -silent | mapcidr -a -silent".format(len(outdata)))


class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """

    structure = (
        ("DataLength", "<H-Data"),
        ("Type", "<H"),
        ("Version", "B=5"),
        ("Rank", "B"),
        ("Flags", "<H=0"),
        ("Serial", "<L"),
        ("TtlSeconds", ">L"),
        ("Reserved", "<L=0"),
        ("TimeStamp", "<L=0"),
        ("Data", ":"),
    )


# Note that depending on whether we use RPC or LDAP all the DNS_RPC_XXXX
# structures use DNS_RPC_NAME when communication is over RPC,
# but DNS_COUNT_NAME is the way they are stored in LDAP.
#
# Since LDAP is the primary goal of this script we use that, but for use
# over RPC the DNS_COUNT_NAME in the structures must be replaced with DNS_RPC_NAME,
# which is also consistent with how MS-DNSP describes it.


class DNS_RPC_NAME(Structure):
    """
    DNS_RPC_NAME
    Used for FQDNs in RPC communication.
    MUST be converted to DNS_COUNT_NAME for LDAP
    [MS-DNSP] section 2.2.2.2.1
    """

    structure = (("cchNameLength", "B-dnsName"), ("dnsName", ":"))


class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    [MS-DNSP] section 2.2.2.2.2
    """

    structure = (("Length", "B-RawName"), ("LabelCount", "B"), ("RawName", ":"))

    def toFqdn(self):
        ind = 0
        labels = []
        for i in range(self["LabelCount"]):
            nextlen = unpack("B", self["RawName"][ind : ind + 1])[0]
            labels.append(self["RawName"][ind + 1 : ind + 1 + nextlen].decode("utf-8"))
            ind += nextlen + 1
        # For the final dot
        labels.append("")
        return ".".join(labels)


class DNS_RPC_NODE(Structure):
    """
    DNS_RPC_NODE
    [MS-DNSP] section 2.2.2.2.3
    """

    structure = (
        ("wLength", ">H"),
        ("wRecordCount", ">H"),
        ("dwFlags", ">L"),
        ("dwChildCount", ">L"),
        ("dnsNodeName", ":"),
    )


class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """

    structure = (("address", ":"),)

    def formatCanonical(self):
        return socket.inet_ntoa(self["address"])

    def fromCanonical(self, canonical):
        self["address"] = socket.inet_aton(canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.2
    """

    structure = (("nameNode", ":", DNS_COUNT_NAME),)


class DNS_RPC_RECORD_SOA(Structure):
    """
    DNS_RPC_RECORD_SOA
    [MS-DNSP] section 2.2.2.2.4.3
    """

    structure = (
        ("dwSerialNo", ">L"),
        ("dwRefresh", ">L"),
        ("dwRetry", ">L"),
        ("dwExpire", ">L"),
        ("dwMinimumTtl", ">L"),
        ("namePrimaryServer", ":", DNS_COUNT_NAME),
        ("zoneAdminEmail", ":", DNS_COUNT_NAME),
    )


class DNS_RPC_RECORD_NULL(Structure):
    """
    DNS_RPC_RECORD_NULL
    [MS-DNSP] section 2.2.2.2.4.4
    """

    structure = (("bData", ":"),)


# Some missing structures here that I skipped


class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    """
    DNS_RPC_RECORD_NAME_PREFERENCE
    [MS-DNSP] section 2.2.2.2.4.8
    """

    structure = (("wPreference", ">H"), ("nameExchange", ":", DNS_COUNT_NAME))


# Some missing structures here that I skipped


class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA
    [MS-DNSP] section 2.2.2.2.4.17
    """

    structure = (("ipv6Address", "16s"),)

    def formatCanonical(self):
        return socket.inet_ntop(socket.AF_INET6, self["ipv6Address"])


class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV
    [MS-DNSP] section 2.2.2.2.4.18
    """

    structure = (
        ("wPriority", ">H"),
        ("wWeight", ">H"),
        ("wPort", ">H"),
        ("nameTarget", ":", DNS_COUNT_NAME),
    )


class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """

    structure = (("entombedTime", "<Q"),)

    def toDatetime(self):
        microseconds = int(self["entombedTime"] / 10)
        try:
            return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=microseconds)
        except OverflowError:
            return None
