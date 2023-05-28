import binascii
import codecs
import json
import re
import datetime
from enum import Enum
from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string
from cme.helpers.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control

OBJECT_TYPES_GUID = {}
OBJECT_TYPES_GUID.update(SCHEMA_OBJECTS)
OBJECT_TYPES_GUID.update(EXTENDED_RIGHTS)

# Universal SIDs
WELL_KNOWN_SIDS = {
    "S-1-0": "Null Authority",
    "S-1-0-0": "Nobody",
    "S-1-1": "World Authority",
    "S-1-1-0": "Everyone",
    "S-1-2": "Local Authority",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3": "Creator Authority",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-2": "Creator Owner Server",
    "S-1-3-3": "Creator Group Server",
    "S-1-3-4": "Owner Rights",
    "S-1-5-80-0": "All Services",
    "S-1-4": "Non-unique Authority",
    "S-1-5": "NT Authority",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "This Organization",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority",
    "S-1-5-20": "NT Authority",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authority",
    "S-1-5-80": "NT Service",
    "S-1-5-83-0": "NT VIRTUAL MACHINE\Virtual Machines",
    "S-1-16-0": "Untrusted Mandatory Level",
    "S-1-16-4096": "Low Mandatory Level",
    "S-1-16-8192": "Medium Mandatory Level",
    "S-1-16-8448": "Medium Plus Mandatory Level",
    "S-1-16-12288": "High Mandatory Level",
    "S-1-16-16384": "System Mandatory Level",
    "S-1-16-20480": "Protected Process Mandatory Level",
    "S-1-16-28672": "Secure Process Mandatory Level",
    "S-1-5-32-554": "BUILTIN\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\Remote Desktop Users",
    "S-1-5-32-557": "BUILTIN\Incoming Forest Trust Builders",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-558": "BUILTIN\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\Distributed COM Users",
    "S-1-5-32-569": "BUILTIN\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\RDS Management Servers",
    "S-1-5-32-578": "BUILTIN\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\Remote Management Users",
}


# GUID rights enum
# GUID thats permits to identify extended rights in an ACE
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-rightsguid
class RIGHTS_GUID(Enum):
    WriteMembers = "bf9679c0-0de6-11d0-a285-00aa003049e2"
    ResetPassword = "00299570-246d-11d0-a768-00aa006e0529"
    DS_Replication_Get_Changes = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    DS_Replication_Get_Changes_All = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


# ACE flags enum
# New ACE at the end of SACL for inheritance and access return system-audit
# https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addauditaccessobjectace
class ACE_FLAGS(Enum):
    CONTAINER_INHERIT_ACE = ldaptypes.ACE.CONTAINER_INHERIT_ACE
    FAILED_ACCESS_ACE_FLAG = ldaptypes.ACE.FAILED_ACCESS_ACE_FLAG
    INHERIT_ONLY_ACE = ldaptypes.ACE.INHERIT_ONLY_ACE
    INHERITED_ACE = ldaptypes.ACE.INHERITED_ACE
    NO_PROPAGATE_INHERIT_ACE = ldaptypes.ACE.NO_PROPAGATE_INHERIT_ACE
    OBJECT_INHERIT_ACE = ldaptypes.ACE.OBJECT_INHERIT_ACE
    SUCCESSFUL_ACCESS_ACE_FLAG = ldaptypes.ACE.SUCCESSFUL_ACCESS_ACE_FLAG


# ACE flags enum
# For an ACE, flags that indicate if the ObjectType and the InheritedObjecType are set with a GUID
# Since these two flags are the same for Allowed and Denied access, the same class will be used from 'ldaptypes'
# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace
class OBJECT_ACE_FLAGS(Enum):
    ACE_OBJECT_TYPE_PRESENT = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    ACE_INHERITED_OBJECT_TYPE_PRESENT = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT


# Access Mask enum
# Access mask permits to encode principal's rights to an object. This is the rights the principal behind the specified SID has
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b
# https://docs.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum?redirectedfrom=MSDN
class ACCESS_MASK(Enum):
    # Generic Rights
    GenericRead = 0x80000000  # ADS_RIGHT_GENERIC_READ
    GenericWrite = 0x40000000  # ADS_RIGHT_GENERIC_WRITE
    GenericExecute = 0x20000000  # ADS_RIGHT_GENERIC_EXECUTE
    GenericAll = 0x10000000  # ADS_RIGHT_GENERIC_ALL

    # Maximum Allowed access type
    MaximumAllowed = 0x02000000

    # Access System Acl access type
    AccessSystemSecurity = 0x01000000  # ADS_RIGHT_ACCESS_SYSTEM_SECURITY

    # Standard access types
    Synchronize = 0x00100000  # ADS_RIGHT_SYNCHRONIZE
    WriteOwner = 0x00080000  # ADS_RIGHT_WRITE_OWNER
    WriteDACL = 0x00040000  # ADS_RIGHT_WRITE_DAC
    ReadControl = 0x00020000  # ADS_RIGHT_READ_CONTROL
    Delete = 0x00010000  # ADS_RIGHT_DELETE

    # Specific rights
    AllExtendedRights = 0x00000100  # ADS_RIGHT_DS_CONTROL_ACCESS
    ListObject = 0x00000080  # ADS_RIGHT_DS_LIST_OBJECT
    DeleteTree = 0x00000040  # ADS_RIGHT_DS_DELETE_TREE
    WriteProperties = 0x00000020  # ADS_RIGHT_DS_WRITE_PROP
    ReadProperties = 0x00000010  # ADS_RIGHT_DS_READ_PROP
    Self = 0x00000008  # ADS_RIGHT_DS_SELF
    ListChildObjects = 0x00000004  # ADS_RIGHT_ACTRL_DS_LIST
    DeleteChild = 0x00000002  # ADS_RIGHT_DS_DELETE_CHILD
    CreateChild = 0x00000001  # ADS_RIGHT_DS_CREATE_CHILD


# Simple permissions enum
# Simple permissions are combinaisons of extended permissions
# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc783530(v=ws.10)?redirectedfrom=MSDN
class SIMPLE_PERMISSIONS(Enum):
    FullControl = 0xF01FF
    Modify = 0x0301BF
    ReadAndExecute = 0x0200A9
    ReadAndWrite = 0x02019F
    Read = 0x20094
    Write = 0x200BC


# Mask ObjectType field enum
# Possible values for the Mask field in object-specific ACE (permitting to specify extended rights in the ObjectType field for example)
# Since these flags are the same for Allowed and Denied access, the same class will be used from 'ldaptypes'
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
class ALLOWED_OBJECT_ACE_MASK_FLAGS(Enum):
    ControlAccess = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
    CreateChild = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD
    DeleteChild = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_DELETE_CHILD
    ReadProperty = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP
    WriteProperty = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
    Self = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_SELF


class CMEModule:
    """
    Module to read and backup the Discretionary Access Control List of one or multiple objects.
    This module is essentially inspired from the dacledit.py script of Impacket that we have coauthored, @_nwodtuhs and me.
    It has been converted to an LDAPConnection session, and improvements on the filtering and the ability to specify multiple targets have been added.
    It could be interesting to implement the write/remove functions here, but a ldap3 session instead of a LDAPConnection one is required to write.
    """

    name = "daclread"
    description = "Read and backup the Discretionary Access Control List of objects. Based on the work of @_nwodtuhs and @BlWasp_. Be carefull, this module cannot read the DACLS recursively, more explains in the  options."
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """
        Be carefull, this module cannot read the DACLS recursively. For example, if an object has particular rights because it belongs to a group, the module will not be able to see it directly, you have to check the group rights manually.
        TARGET          The objects that we want to read or backup the DACLs, sepcified by its SamAccountName
        TARGET_DN       The object that we want to read or backup the DACL, specified by its DN (usefull to target the domain itself)
        PRINCIPAL       The trustee that we want to filter on
        ACTION          The action to realise on the DACL (read, backup)
        ACE_TYPE        The type of ACE to read (Allowed or Denied)
        RIGHTS          An interesting right to filter on ('FullControl', 'ResetPassword', 'WriteMembers', 'DCSync')
        RIGHTS_GUID     A right GUID that specify a particular rights to filter on
        """
        self.context = context

        if not module_options:
            context.log.fail("Select an option, example: -M daclread -o TARGET=Administrator ACTION=read")
            exit(1)

        if module_options and "TARGET" in module_options:
            if re.search(r"^(.+)\/([^\/]+)$", module_options["TARGET"]) is not None:
                try:
                    self.target_file = open(module_options["TARGET"], "r")
                    self.target_sAMAccountName = None
                except Exception as e:
                    context.log.fail("The file doesn't exist or cannot be openned.")
            else:
                self.target_sAMAccountName = module_options["TARGET"]
                self.target_file = None
            self.target_DN = None
        self.target_SID = None
        if module_options and "TARGET_DN" in module_options:
            self.target_DN = module_options["TARGET_DN"]
            self.target_sAMAccountName = None
            self.target_file = None

        if module_options and "PRINCIPAL" in module_options:
            self.principal_sAMAccountName = module_options["PRINCIPAL"]
        else:
            self.principal_sAMAccountName = None
        self.principal_sid = None

        if module_options and "ACTION" in module_options:
            self.action = module_options["ACTION"]
        else:
            self.action = "read"
        if module_options and "ACE_TYPE" in module_options:
            self.ace_type = module_options["ACE_TYPE"]
        else:
            self.ace_type = "allowed"
        if module_options and "RIGHTS" in module_options:
            self.rights = module_options["RIGHTS"]
        else:
            self.rights = None
        if module_options and "RIGHTS_GUID" in module_options:
            self.rights_guid = module_options["RIGHTS_GUID"]
        else:
            self.rights_guid = None
        self.filename = None

    def on_login(self, context, connection):
        """
        On a successful LDAP login we perform a search for the targets' SID, their Security Decriptors and the principal's SID if there is one specified
        """

        context.log.highlight("Be carefull, this module cannot read the DACLS recursively.")
        self.baseDN = connection.ldapConnection._baseDN
        self.ldap_session = connection.ldapConnection

        # Searching for the principal SID
        if self.principal_sAMAccountName is not None:
            _lookedup_principal = self.principal_sAMAccountName
            try:
                self.principal_sid = format_sid(
                    self.ldap_session.search(
                        searchBase=self.baseDN,
                        searchFilter="(sAMAccountName=%s)" % escape_filter_chars(_lookedup_principal),
                        attributes=["objectSid"],
                    )[0][
                        1
                    ][0][
                        1
                    ][0]
                )
                context.log.highlight("Found principal SID to filter on: %s" % self.principal_sid)
            except Exception as e:
                context.log.fail("Principal SID not found in LDAP (%s)" % _lookedup_principal)
                exit(1)

        # Searching for the targets SID and their Security Decriptors
        # If there is only one target
        if (self.target_sAMAccountName or self.target_DN) and self.target_file is None:
            # Searching for target account with its security descriptor
            try:
                self.search_target_principal_security_descriptor(context, connection)
                # Extract security descriptor data
                self.target_principal_dn = self.target_principal[0]
                self.principal_raw_security_descriptor = str(self.target_principal[1][0][1][0]).encode("latin-1")
                self.principal_security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=self.principal_raw_security_descriptor)
                context.log.highlight("Target principal found in LDAP (%s)" % self.target_principal[0])
            except Exception as e:
                context.log.fail("Target SID not found in LDAP (%s)" % self.target_sAMAccountName)
                exit(1)

            if self.action == "read":
                self.read(context)
            if self.action == "backup":
                self.backup(context)

        # If there are multiple targets
        else:
            targets = self.target_file.readlines()
            for target in targets:
                try:
                    self.target_sAMAccountName = target.strip()
                    # Searching for target account with its security descriptor
                    self.search_target_principal_security_descriptor(context, connection)
                    # Extract security descriptor data
                    self.target_principal_dn = self.target_principal[0]
                    self.principal_raw_security_descriptor = str(self.target_principal[1][0][1][0]).encode("latin-1")
                    self.principal_security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=self.principal_raw_security_descriptor)
                    context.log.highlight("Target principal found in LDAP (%s)" % self.target_sAMAccountName)
                except Exception as e:
                    context.log.fail("Target SID not found in LDAP (%s)" % self.target_sAMAccountName)
                    continue

                if self.action == "read":
                    self.read(context)
                if self.action == "backup":
                    self.backup(context)

    # Main read funtion
    # Prints the parsed DACL
    def read(self, context):
        parsed_dacl = self.parse_dacl(context, self.principal_security_descriptor["Dacl"])
        self.print_parsed_dacl(context, parsed_dacl)
        return

    # Permits to export the DACL of the targets
    # This function is called before any writing action (write, remove or restore)
    def backup(self, context):
        backup = {}
        backup["sd"] = binascii.hexlify(self.principal_raw_security_descriptor).decode("latin-1")
        backup["dn"] = str(self.target_principal_dn)
        if not self.filename:
            self.filename = "dacledit-%s-%s.bak" % (
                datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                self.target_sAMAccountName,
            )
        with codecs.open(self.filename, "w", "latin-1") as outfile:
            json.dump(backup, outfile)
        context.log.highlight("DACL backed up to %s", self.filename)
        self.filename = None

    # Attempts to retrieve the DACL in the Security Descriptor of the specified target
    def search_target_principal_security_descriptor(self, context, connection):
        _lookedup_principal = ""
        # Set SD flags to only query for DACL
        controls = security_descriptor_control(sdflags=0x04)
        if self.target_sAMAccountName is not None:
            _lookedup_principal = self.target_sAMAccountName
            target = self.ldap_session.search(
                searchBase=self.baseDN,
                searchFilter="(sAMAccountName=%s)" % escape_filter_chars(_lookedup_principal),
                attributes=["nTSecurityDescriptor"],
                searchControls=controls,
            )
        if self.target_DN is not None:
            _lookedup_principal = self.target_DN
            target = self.ldap_session.search(
                searchBase=self.baseDN,
                searchFilter="(distinguishedName=%s)" % _lookedup_principal,
                attributes=["nTSecurityDescriptor"],
                searchControls=controls,
            )
        try:
            self.target_principal = target[0]
        except Exception as e:
            context.log.fail("Principal not found in LDAP (%s), probably an LDAP session issue." % _lookedup_principal)
            exit(0)

    # Attempts to retieve the SID and Distinguisehd Name from the sAMAccountName
    # Not used for the moment
    #   - samname : a sAMAccountName
    def get_user_info(self, context, samname):
        self.ldap_session.search(
            searchBase=self.baseDN,
            searchFilter="(sAMAccountName=%s)" % escape_filter_chars(samname),
            attributes=["objectSid"],
        )
        try:
            dn = self.ldap_session.entries[0].entry_dn
            sid = format_sid(self.ldap_session.entries[0]["objectSid"].raw_values[0])
            return dn, sid
        except Exception as e:
            context.log.fail("User not found in LDAP: %s" % samname)
            return False

    # Attempts to resolve a SID and return the corresponding samaccountname
    #   - sid : the SID to resolve
    def resolveSID(self, context, sid):
        # Tries to resolve the SID from the well known SIDs
        if sid in WELL_KNOWN_SIDS.keys():
            return WELL_KNOWN_SIDS[sid]
        # Tries to resolve the SID from the LDAP domain dump
        else:
            try:
                dn = self.ldap_session.search(
                    searchBase=self.baseDN,
                    searchFilter="(objectSid=%s)" % sid,
                    attributes=["sAMAccountName"],
                )[
                    0
                ][0]
                samname = self.ldap_session.search(
                    searchBase=self.baseDN,
                    searchFilter="(objectSid=%s)" % sid,
                    attributes=["sAMAccountName"],
                )[0][
                    1
                ][0][
                    1
                ][0]
                return samname
            except Exception as e:
                context.log.debug("SID not found in LDAP: %s" % sid)
                return ""

    # Parses a full DACL
    #   - dacl : the DACL to parse, submitted in a Security Desciptor format
    def parse_dacl(self, context, dacl):
        parsed_dacl = []
        context.log.debug("Parsing DACL")
        i = 0
        for ace in dacl["Data"]:
            parsed_ace = self.parse_ace(context, ace)
            parsed_dacl.append(parsed_ace)
            i += 1
        return parsed_dacl

    # Parses an access mask to extract the different values from a simple permission
    # https://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
    #   - fsr : the access mask to parse
    def parse_perms(self, fsr):
        _perms = []
        for PERM in SIMPLE_PERMISSIONS:
            if (fsr & PERM.value) == PERM.value:
                _perms.append(PERM.name)
                fsr = fsr & (not PERM.value)
        for PERM in ACCESS_MASK:
            if fsr & PERM.value:
                _perms.append(PERM.name)
        return _perms

    # Parses a specified ACE and extract the different values (Flags, Access Mask, Trustee, ObjectType, InheritedObjectType)
    #   - ace : the ACE to parse
    def parse_ace(self, context, ace):
        # For the moment, only the Allowed and Denied Access ACE are supported
        if ace["TypeName"] in [
            "ACCESS_ALLOWED_ACE",
            "ACCESS_ALLOWED_OBJECT_ACE",
            "ACCESS_DENIED_ACE",
            "ACCESS_DENIED_OBJECT_ACE",
        ]:
            parsed_ace = {}
            parsed_ace["ACE Type"] = ace["TypeName"]
            # Retrieves ACE's flags
            _ace_flags = []
            for FLAG in ACE_FLAGS:
                if ace.hasFlag(FLAG.value):
                    _ace_flags.append(FLAG.name)
            parsed_ace["ACE flags"] = ", ".join(_ace_flags) or "None"

            # For standard ACE
            # Extracts the access mask (by parsing the simple permissions) and the principal's SID
            if ace["TypeName"] in ["ACCESS_ALLOWED_ACE", "ACCESS_DENIED_ACE"]:
                parsed_ace["Access mask"] = "%s (0x%x)" % (
                    ", ".join(self.parse_perms(ace["Ace"]["Mask"]["Mask"])),
                    ace["Ace"]["Mask"]["Mask"],
                )
                parsed_ace["Trustee (SID)"] = "%s (%s)" % (
                    self.resolveSID(context, ace["Ace"]["Sid"].formatCanonical()) or "UNKNOWN",
                    ace["Ace"]["Sid"].formatCanonical(),
                )

            # For object-specific ACE
            elif ace["TypeName"] in [
                "ACCESS_ALLOWED_OBJECT_ACE",
                "ACCESS_DENIED_OBJECT_ACE",
            ]:
                # Extracts the mask values. These values will indicate the ObjectType purpose
                _access_mask_flags = []
                for FLAG in ALLOWED_OBJECT_ACE_MASK_FLAGS:
                    if ace["Ace"]["Mask"].hasPriv(FLAG.value):
                        _access_mask_flags.append(FLAG.name)
                parsed_ace["Access mask"] = ", ".join(_access_mask_flags)
                # Extracts the ACE flag values and the trusted SID
                _object_flags = []
                for FLAG in OBJECT_ACE_FLAGS:
                    if ace["Ace"].hasFlag(FLAG.value):
                        _object_flags.append(FLAG.name)
                parsed_ace["Flags"] = ", ".join(_object_flags) or "None"
                # Extracts the ObjectType GUID values
                if ace["Ace"]["ObjectTypeLen"] != 0:
                    obj_type = bin_to_string(ace["Ace"]["ObjectType"]).lower()
                    try:
                        parsed_ace["Object type (GUID)"] = "%s (%s)" % (
                            OBJECT_TYPES_GUID[obj_type],
                            obj_type,
                        )
                    except KeyError:
                        parsed_ace["Object type (GUID)"] = "UNKNOWN (%s)" % obj_type
                # Extracts the InheritedObjectType GUID values
                if ace["Ace"]["InheritedObjectTypeLen"] != 0:
                    inh_obj_type = bin_to_string(ace["Ace"]["InheritedObjectType"]).lower()
                    try:
                        parsed_ace["Inherited type (GUID)"] = "%s (%s)" % (
                            OBJECT_TYPES_GUID[inh_obj_type],
                            inh_obj_type,
                        )
                    except KeyError:
                        parsed_ace["Inherited type (GUID)"] = "UNKNOWN (%s)" % inh_obj_type
                # Extract the Trustee SID (the object that has the right over the DACL bearer)
                parsed_ace["Trustee (SID)"] = "%s (%s)" % (
                    self.resolveSID(context, ace["Ace"]["Sid"].formatCanonical()) or "UNKNOWN",
                    ace["Ace"]["Sid"].formatCanonical(),
                )

        else:
            # If the ACE is not an access allowed
            context.log.debug("ACE Type (%s) unsupported for parsing yet, feel free to contribute" % ace["TypeName"])
            parsed_ace = {}
            parsed_ace["ACE type"] = ace["TypeName"]
            _ace_flags = []
            for FLAG in ACE_FLAGS:
                if ace.hasFlag(FLAG.value):
                    _ace_flags.append(FLAG.name)
            parsed_ace["ACE flags"] = ", ".join(_ace_flags) or "None"
            parsed_ace["DEBUG"] = "ACE type not supported for parsing by dacleditor.py, feel free to contribute"
        return parsed_ace

    # Prints a full DACL by printing each parsed ACE
    #   - parsed_dacl : a parsed DACL from parse_dacl()
    def print_parsed_dacl(self, context, parsed_dacl):
        context.log.debug("Printing parsed DACL")
        i = 0
        # If a specific right or a specific GUID has been specified, only the ACE with this right will be printed
        # If an ACE type has been specified, only the ACE with this type will be specified
        # If a principal has been specified, only the ACE where he is the trustee will be printed
        for parsed_ace in parsed_dacl:
            print_ace = True
            # Filter on specific rights
            if self.rights is not None:
                try:
                    if (self.rights == "FullControl") and (self.rights not in parsed_ace["Access mask"]):
                        print_ace = False
                    if (self.rights == "DCSync") and (("Object type (GUID)" not in parsed_ace) or (RIGHTS_GUID.DS_Replication_Get_Changes_All.value not in parsed_ace["Object type (GUID)"])):
                        print_ace = False
                    if (self.rights == "WriteMembers") and (("Object type (GUID)" not in parsed_ace) or (RIGHTS_GUID.WriteMembers.value not in parsed_ace["Object type (GUID)"])):
                        print_ace = False
                    if (self.rights == "ResetPassword") and (("Object type (GUID)" not in parsed_ace) or (RIGHTS_GUID.ResetPassword.value not in parsed_ace["Object type (GUID)"])):
                        print_ace = False
                except Exception as e:
                    context.log.fail("Error filtering ACE, probably because of ACE type unsupported for parsing yet (%s)" % e)

            # Filter on specific right GUID
            if self.rights_guid is not None:
                try:
                    if ("Object type (GUID)" not in parsed_ace) or (self.rights_guid not in parsed_ace["Object type (GUID)"]):
                        print_ace = False
                except Exception as e:
                    context.log.fail("Error filtering ACE, probably because of ACE type unsupported for parsing yet (%s)" % e)

            # Filter on ACE type
            if self.ace_type == "allowed":
                try:
                    if ("ACCESS_ALLOWED_OBJECT_ACE" not in parsed_ace["ACE Type"]) and ("ACCESS_ALLOWED_ACE" not in parsed_ace["ACE Type"]):
                        print_ace = False
                except Exception as e:
                    context.log.fail("Error filtering ACE, probably because of ACE type unsupported for parsing yet (%s)" % e)
            else:
                try:
                    if ("ACCESS_DENIED_OBJECT_ACE" not in parsed_ace["ACE Type"]) and ("ACCESS_DENIED_ACE" not in parsed_ace["ACE Type"]):
                        print_ace = False
                except Exception as e:
                    context.log.fail("Error filtering ACE, probably because of ACE type unsupported for parsing yet (%s)" % e)

            # Filter on trusted principal
            if self.principal_sid is not None:
                try:
                    if self.principal_sid not in parsed_ace["Trustee (SID)"]:
                        print_ace = False
                except Exception as e:
                    context.log.fail("Error filtering ACE, probably because of ACE type unsupported for parsing yet (%s)" % e)
            if print_ace:
                self.context.log.highlight("%-28s" % "ACE[%d] info" % i)
                self.print_parsed_ace(parsed_ace)
            i += 1

    # Prints properly a parsed ACE
    #   - parsed_ace : a parsed ACE from parse_ace()
    def print_parsed_ace(self, parsed_ace):
        elements_name = list(parsed_ace.keys())
        for attribute in elements_name:
            self.context.log.highlight("    %-26s: %s" % (attribute, parsed_ace[attribute]))

    # Retrieves the GUIDs for the specified rights
    def build_guids_for_rights(self):
        _rights_guids = []
        if self.rights_guid is not None:
            _rights_guids = [self.rights_guid]
        elif self.rights == "WriteMembers":
            _rights_guids = [RIGHTS_GUID.WriteMembers.value]
        elif self.rights == "ResetPassword":
            _rights_guids = [RIGHTS_GUID.ResetPassword.value]
        elif self.rights == "DCSync":
            _rights_guids = [
                RIGHTS_GUID.DS_Replication_Get_Changes.value,
                RIGHTS_GUID.DS_Replication_Get_Changes_All.value,
            ]
        self.context.log.highlight("Built GUID: %s", _rights_guids)
        return _rights_guids
