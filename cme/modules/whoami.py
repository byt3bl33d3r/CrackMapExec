class CMEModule:
    """
    Basic enumeration of provided user information and privileges
    Module by spyr0 (@spyr0-sec)
    """

    name = "whoami"
    description = "Get details of provided user"
    supported_protocols = ["ldap"]
    opsec_safe = True  # Does the module touch disk?
    multiple_hosts = True  # Does it make sense to run this module on multiple hosts at a time?

    def options(self, context, module_options):
        """
        USER  Enumerate information about a different SamAccountName
        """
        self.username = None
        if "USER" in module_options:
            self.username = module_options["USER"]

    def on_login(self, context, connection):
        searchBase = connection.ldapConnection._baseDN
        if self.username is None:
            searchFilter = f"(sAMAccountName={connection.username})"
        else:
            searchFilter = f"(sAMAccountName={format(self.username)})"

        context.log.debug(f"Using naming context: {searchBase} and {searchFilter} as search filter")

        # Get attributes of provided user
        r = connection.ldapConnection.search(
            searchBase=searchBase,
            searchFilter=searchFilter,
            attributes=[
                "name",
                "sAmAccountName",
                "description",
                "distinguishedName",
                "pwdLastSet",
                "logonCount",
                "lastLogon",
                "userAccountControl",
                "servicePrincipalName",
                "memberOf",
            ],
            sizeLimit=999,
        )
        for response in r[0]["attributes"]:
            if "userAccountControl" in str(response["type"]):
                if str(response["vals"][0]) == "512":
                    context.log.highlight(f"Enabled: Yes")
                    context.log.highlight(f"Password Never Expires: No")
                elif str(response["vals"][0]) == "514":
                    context.log.highlight(f"Enabled: No")
                    context.log.highlight(f"Password Never Expires: No")
                elif str(response["vals"][0]) == "66048":
                    context.log.highlight(f"Enabled: Yes")
                    context.log.highlight(f"Password Never Expires: Yes")
                elif str(response["vals"][0]) == "66050":
                    context.log.highlight(f"Enabled: No")
                    context.log.highlight(f"Password Never Expires: Yes")
            elif "lastLogon" in str(response["type"]):
                if str(response["vals"][0]) == "1601":
                    context.log.highlight(f"Last logon: Never")
                else:
                    context.log.highlight(f"Last logon: {response['vals'][0]}")
            elif "memberOf" in str(response["type"]):
                for group in response["vals"]:
                    context.log.highlight(f"Member of: {group}")
            elif "servicePrincipalName" in str(response["type"]):
                context.log.highlight(f"Service Account Name(s) found - Potentially Kerberoastable user!")
                for spn in response["vals"]:
                    context.log.highlight(f"Service Account Name: {spn}")
            else:
                context.log.highlight(response["type"] + ": " + response["vals"][0])
