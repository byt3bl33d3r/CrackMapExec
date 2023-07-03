#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.ldap import ldapasn1 as ldapasn1_impacket


def searchResEntry_to_dict(results):
    data = {}
    for attr in results["attributes"]:
        key = str(attr["type"])
        value = str(attr["vals"][0])
        data[key] = value
    return data


class CMEModule:
    """
    Retrieves the different Sites and Subnets of an Active Directory

    Authors:
      Podalirius: @podalirius_
    """

    def options(self, context, module_options):
        """
        showservers    Toggle printing of servers (default: true)
        """

        self.showservers = True
        self.base_dn = None

        if module_options and "SHOWSERVERS" in module_options:
            if module_options["SHOWSERVERS"].lower() == "true" or module_options["SHOWSERVERS"] == "1":
                self.showservers = True
            elif module_options["SHOWSERVERS"].lower() == "false" or module_options["SHOWSERVERS"] == "0":
                self.showservers = False
            else:
                print("Could not parse showservers option.")
        if module_options and "BASE_DN" in module_options:
            self.base_dn = module_options["BASE_DN"]

    name = "subnets"
    description = "Retrieves the different Sites and Subnets of an Active Directory"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def on_login(self, context, connection):
        dn = connection.ldapConnection._baseDN if self.base_dn is None else self.base_dn

        context.log.display("Getting the Sites and Subnets from domain")

        try:
            list_sites = connection.ldapConnection.search(
                searchBase="CN=Configuration,%s" % dn,
                searchFilter="(objectClass=site)",
                attributes=["distinguishedName", "name", "description"],
                sizeLimit=999,
            )
        except LDAPSearchError as e:
            context.log.fail(str(e))
            exit()
        for site in list_sites:
            if isinstance(site, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            site = searchResEntry_to_dict(site)
            site_dn = site["distinguishedName"]
            site_name = site["name"]
            site_description = ""
            if "description" in site.keys():
                site_description = site["description"]
            # Getting subnets of this site
            list_subnets = connection.ldapConnection.search(
                searchBase="CN=Sites,CN=Configuration,%s" % dn,
                searchFilter="(siteObject=%s)" % site_dn,
                attributes=["distinguishedName", "name"],
                sizeLimit=999,
            )
            if len([subnet for subnet in list_subnets if isinstance(subnet, ldapasn1_impacket.SearchResultEntry)]) == 0:
                context.log.highlight('Site "%s"' % site_name)
            else:
                for subnet in list_subnets:
                    if isinstance(subnet, ldapasn1_impacket.SearchResultEntry) is not True:
                        continue
                    subnet = searchResEntry_to_dict(subnet)
                    subnet_dn = subnet["distinguishedName"]
                    subnet_name = subnet["name"]

                    if self.showservers:
                        # Getting machines in these subnets
                        list_servers = connection.ldapConnection.search(
                            searchBase=site_dn,
                            searchFilter="(objectClass=server)",
                            attributes=["cn"],
                            sizeLimit=999,
                        )
                        if len([server for server in list_servers if isinstance(server, ldapasn1_impacket.SearchResultEntry)]) == 0:
                            if len(site_description) != 0:
                                context.log.highlight('Site "%s" (Subnet:%s) (description:"%s")' % (site_name, subnet_name, site_description))
                            else:
                                context.log.highlight('Site "%s" (Subnet:%s)' % (site_name, subnet_name))
                        else:
                            for server in list_servers:
                                if isinstance(server, ldapasn1_impacket.SearchResultEntry) is not True:
                                    continue
                                server = searchResEntry_to_dict(server)["cn"]
                                if len(site_description) != 0:
                                    context.log.highlight(
                                        'Site "%s" (Subnet:%s) (description:"%s") (Server:%s)'
                                        % (
                                            site_name,
                                            subnet_name,
                                            site_description,
                                            server,
                                        )
                                    )
                                else:
                                    context.log.highlight('Site "%s" (Subnet:%s) (Server:%s)' % (site_name, subnet_name, server))
                    else:
                        if len(site_description) != 0:
                            context.log.highlight('Site "%s" (Subnet:%s) (description:"%s")' % (site_name, subnet_name, site_description))
                        else:
                            context.log.highlight('Site "%s" (Subnet:%s)' % (site_name, subnet_name))
