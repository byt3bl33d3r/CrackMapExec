#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldap import LDAPSearchError


class CMEModule:
    """
    Find PKI Enrollment Services in Active Directory and Certificate Templates Names.

    Module by Tobias Neitzel (@qtc_de) and Sam Freeside (@snovvcrash)
    """

    name = "adcs"
    description = "Find PKI Enrollment Services in Active Directory and Certificate Templates Names"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.server = None
        self.regex = None

    def options(self, context, module_options):
        """
        SERVER             PKI Enrollment Server to enumerate templates for. Default is None, use CN name
        BASE_DN            The base domain name for the LDAP query
        """
        self.context = context
        self.regex = re.compile("(https?://.+)")

        self.server = None
        self.base_dn = None
        if module_options and "SERVER" in module_options:
            self.server = module_options["SERVER"]
        if module_options and "BASE_DN" in module_options:
            self.base_dn = module_options["BASE_DN"]

    def on_login(self, context, connection):
        """
        On a successful LDAP login we perform a search for all PKI Enrollment Server or Certificate Templates Names.
        """
        if self.server is None:
            search_filter = "(objectClass=pKIEnrollmentService)"
        else:
            search_filter = f"(distinguishedName=CN={self.server},CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,"
            self.context.log.highlight("Using PKI CN: {}".format(self.server))

        context.log.display("Starting LDAP search with search filter '{}'".format(search_filter))

        try:
            sc = ldap.SimplePagedResultsControl()
            base_dn_root = connection.ldapConnection._baseDN if self.base_dn is None else self.base_dn

            if self.server is None:
                resp = connection.ldapConnection.search(
                    searchFilter=search_filter,
                    attributes=[],
                    sizeLimit=0,
                    searchControls=[sc],
                    perRecordCallback=self.process_servers,
                    searchBase="CN=Configuration," + base_dn_root,
                )
            else:
                resp = connection.ldapConnection.search(
                    searchFilter=search_filter + base_dn_root + ")",
                    attributes=["certificateTemplates"],
                    sizeLimit=0,
                    searchControls=[sc],
                    perRecordCallback=self.process_templates,
                    searchBase="CN=Configuration," + base_dn_root,
                )
        except LDAPSearchError as e:
            context.log.fail("Obtained unexpected exception: {}".format(str(e)))

    def process_servers(self, item):
        """
        Function that is called to process the items obtain by the LDAP search when listing PKI Enrollment Servers.
        """
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return

        urls = []
        host_name = None
        cn = None

        try:
            for attribute in item["attributes"]:
                if str(attribute["type"]) == "dNSHostName":
                    host_name = attribute["vals"][0].asOctets().decode("utf-8")
                if str(attribute["type"]) == "cn":
                    cn = attribute["vals"][0].asOctets().decode("utf-8")
                elif str(attribute["type"]) == "msPKI-Enrollment-Servers":
                    values = attribute["vals"]

                    for value in values:
                        value = value.asOctets().decode("utf-8")
                        match = self.regex.search(value)
                        if match:
                            urls.append(match.group(1))
        except Exception as e:
            entry = host_name or "item"
            self.context.log.fail("Skipping {}, cannot process LDAP entry due to error: '{}'".format(entry, str(e)))

        if host_name:
            self.context.log.highlight("Found PKI Enrollment Server: {}".format(host_name))
        if cn:
            self.context.log.highlight("Found CN: {}".format(cn))
        for url in urls:
            self.context.log.highlight("Found PKI Enrollment WebService: {}".format(url))

    def process_templates(self, item):
        """
        Function that is called to process the items obtain by the LDAP search when listing Certificate Templates Names for a specific PKI Enrollment Server.
        """
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return

        templates = []
        template_name = None

        try:
            for attribute in item["attributes"]:
                if str(attribute["type"]) == "certificateTemplates":
                    for val in attribute["vals"]:
                        template_name = val.asOctets().decode("utf-8")
                        templates.append(template_name)
        except Exception as e:
            entry = template_name or "item"
            self.context.log.fail(f"Skipping {entry}, cannot process LDAP entry due to error: '{e}'")

        if templates:
            for t in templates:
                self.context.log.highlight("Found Certificate Template: {}".format(t))
