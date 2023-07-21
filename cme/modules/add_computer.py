#!/usr/bin/env python3

# -*- coding: utf-8 -*-

import ldap3
from impacket.dcerpc.v5 import samr, epm, transport

class CMEModule:
    '''
    Module by CyberCelt: @Cyb3rC3lt
     Initial module:
        https://github.com/Cyb3rC3lt/CrackMapExec-Modules
    Thanks to the guys at impacket for the original code
    '''

    name = 'add-computer'
    description = 'Adds or deletes a domain computer'
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        '''
        add-computer: Specify add-computer to call the module using smb
        NAME: Specify the NAME option to name the Computer to be added
        PASSWORD: Specify the PASSWORD option to supply a password for the Computer to be added
        DELETE: Specify DELETE to remove a Computer
        CHANGEPW: Specify CHANGEPW to modify a Computer password
        Usage: cme smb $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" PASSWORD="Password1"
               cme smb $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" DELETE=True
               cme smb $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" PASSWORD="Password2" CHANGEPW=True
        '''

        self.__baseDN = None
        self.__computerGroup = None
        self.__method = "SAMR"
        self.__noAdd = False
        self.__delete = False
        self.noLDAPRequired = False

        if 'DELETE' in module_options:
            self.__delete = True

        if 'CHANGEPW' in module_options and ('NAME' not in module_options or 'PASSWORD' not in module_options):
            context.log.error('NAME  and PASSWORD options are required!')
        elif 'CHANGEPW' in module_options:
                self.__noAdd = True

        if 'NAME' in module_options:
            self.__computerName = module_options['NAME']
            if self.__computerName[-1] != '$':
                self.__computerName += '$'
        else:
            context.log.error('NAME option is required!')
            exit(1)

        if 'PASSWORD' in module_options:
            self.__computerPassword = module_options['PASSWORD']
        elif 'PASSWORD' not in module_options and not self.__delete:
            context.log.error('PASSWORD option is required!')
            exit(1)

    def on_login(self, context, connection):

        #Set some variables
        self.__domain = connection.domain
        self.__domainNetbios = connection.domain
        self.__kdcHost = connection.hostname + "." + connection.domain
        self.__target = self.__kdcHost
        self.__username = connection.username
        self.__password = connection.password
        self.__targetIp = connection.host
        self.__port = context.smb_server_port
        self.__aesKey = context.aesKey
        self.__hashes = context.hash
        self.__doKerberos = connection.kerberos
        self.__nthash = ""
        self.__lmhash = ""

        if context.hash and ":" in context.hash[0]:
            hashList = context.hash[0].split(":")
            self.__nthash = hashList[-1]
            self.__lmhash = hashList[0]
        elif context.hash and ":" not in context.hash[0]:
            self.__nthash = context.hash[0]
            self.__lmhash = "00000000000000000000000000000000"

        # First try to add via SAMR over SMB
        self.doSAMRAdd(context)

        # If SAMR fails now try over LDAPS
        if not self.noLDAPRequired:
         self.doLDAPSAdd(connection,context)
        else:
            exit(1)

    def doSAMRAdd(self,context):

        if self.__targetIp is not None:
            stringBinding = epm.hept_map(self.__targetIp, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        else:
            stringBinding = epm.hept_map(self.__target, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_dport(self.__port)

        if self.__targetIp is not None:
            rpctransport.setRemoteHost(self.__targetIp)
            rpctransport.setRemoteName(self.__target)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)

        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        dce = rpctransport.get_dce_rpc()
        servHandle = None
        domainHandle = None
        userHandle = None
        try:
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            samrConnectResponse = samr.hSamrConnect5(dce, '\\\\%s\x00' % self.__target,
                samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN )
            servHandle = samrConnectResponse['ServerHandle']

            samrEnumResponse = samr.hSamrEnumerateDomainsInSamServer(dce, servHandle)
            domains = samrEnumResponse['Buffer']['Buffer']
            domainsWithoutBuiltin = list(filter(lambda x : x['Name'].lower() != 'builtin', domains))

            if len(domainsWithoutBuiltin) > 1:
                domain = list(filter(lambda x : x['Name'].lower() == self.__domainNetbios, domains))
                if len(domain) != 1:
                    context.log.highlight(u'{}'.format(
                        'This domain does not exist: "' + self.__domainNetbios + '"'))
                    logging.critical("Available domain(s):")
                    for domain in domains:
                        logging.error(" * %s" % domain['Name'])
                    raise Exception()
                else:
                    selectedDomain = domain[0]['Name']
            else:
                selectedDomain = domainsWithoutBuiltin[0]['Name']

            samrLookupDomainResponse = samr.hSamrLookupDomainInSamServer(dce, servHandle, selectedDomain)
            domainSID = samrLookupDomainResponse['DomainId']

            if logging.getLogger().level == logging.DEBUG:
                logging.info("Opening domain %s..." % selectedDomain)
            samrOpenDomainResponse = samr.hSamrOpenDomain(dce, servHandle, samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER , domainSID)
            domainHandle = samrOpenDomainResponse['DomainHandle']

            if self.__noAdd or self.__delete:
                try:
                    checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000073:
                        context.log.highlight(u'{}'.format(
                            self.__computerName + ' not found in domain ' + selectedDomain))
                        self.noLDAPRequired = True
                        raise Exception()
                    else:
                        raise

                userRID = checkForUser['RelativeIds']['Element'][0]
                if self.__delete:
                    access = samr.DELETE
                    message = "delete"
                else:
                    access = samr.USER_FORCE_PASSWORD_CHANGE
                    message = "set the password for"
                try:
                    openUser = samr.hSamrOpenUser(dce, domainHandle, access, userRID)
                    userHandle = openUser['UserHandle']
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000022:
                        context.log.highlight(u'{}'.format(
                            self.__username + ' does not have the right to ' + message + " " + self.__computerName))
                        self.noLDAPRequired = True
                        raise Exception()
                    else:
                        raise
            else:
                if self.__computerName is not None:
                    try:
                        checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                        self.noLDAPRequired = True
                        context.log.highlight(u'{}'.format(
                            'Computer account already exists with the name: "' + self.__computerName + '"'))
                        raise Exception()
                    except samr.DCERPCSessionError as e:
                        if e.error_code != 0xc0000073:
                            raise
                else:
                    foundUnused = False
                    while not foundUnused:
                        self.__computerName = self.generateComputerName()
                        try:
                            checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                        except samr.DCERPCSessionError as e:
                            if e.error_code == 0xc0000073:
                                foundUnused = True
                            else:
                                raise
                try:
                    createUser = samr.hSamrCreateUser2InDomain(dce, domainHandle, self.__computerName, samr.USER_WORKSTATION_TRUST_ACCOUNT, samr.USER_FORCE_PASSWORD_CHANGE,)
                    self.noLDAPRequired = True
                    context.log.highlight('Successfully added the machine account: "' + self.__computerName + '" with Password: "' + self.__computerPassword + '"')
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000022:
                        context.log.highlight(u'{}'.format(
                            'The following user does not have the right to create a computer account: "' + self.__username + '"'))
                        raise Exception()
                    elif e.error_code == 0xc00002e7:
                        context.log.highlight(u'{}'.format(
                            'The following user exceeded their machine account quota: "' + self.__username + '"'))
                        raise Exception()
                    else:
                        raise
                userHandle = createUser['UserHandle']

            if self.__delete:
                samr.hSamrDeleteUser(dce, userHandle)
                context.log.highlight(u'{}'.format('Successfully deleted the "' + self.__computerName + '" Computer account'))
                self.noLDAPRequired=True
                userHandle = None
            else:
                samr.hSamrSetPasswordInternal4New(dce, userHandle, self.__computerPassword)
                if self.__noAdd:
                    context.log.highlight(u'{}'.format(
                        'Successfully set the password of machine "' + self.__computerName + '" with password "' + self.__computerPassword + '"'))
                    self.noLDAPRequired=True
                else:
                    checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                    userRID = checkForUser['RelativeIds']['Element'][0]
                    openUser = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, userRID)
                    userHandle = openUser['UserHandle']
                    req = samr.SAMPR_USER_INFO_BUFFER()
                    req['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
                    req['Control']['UserAccountControl'] = samr.USER_WORKSTATION_TRUST_ACCOUNT
                    samr.hSamrSetInformationUser2(dce, userHandle, req)
                    if not self.noLDAPRequired:
                       context.log.highlight(u'{}'.format(
                        'Successfully added the machine account "' + self.__computerName + '" with Password: "' + self.__computerPassword + '"'))
                    self.noLDAPRequired = True

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
        finally:
            if userHandle is not None:
                samr.hSamrCloseHandle(dce, userHandle)
            if domainHandle is not None:
                samr.hSamrCloseHandle(dce, domainHandle)
            if servHandle is not None:
                samr.hSamrCloseHandle(dce, servHandle)
            dce.disconnect()

    def doLDAPSAdd(self, connection, context):
        ldap_domain = connection.domain.replace(".", ",dc=")
        spns = [
            'HOST/%s' % self.__computerName,
            'HOST/%s.%s' % (self.__computerName, connection.domain),
            'RestrictedKrbHost/%s' % self.__computerName,
            'RestrictedKrbHost/%s.%s' % (self.__computerName, connection.domain),
        ]
        ucd = {
            'dnsHostName': '%s.%s' % (self.__computerName, connection.domain),
            'userAccountControl': 0x1000,
            'servicePrincipalName': spns,
            'sAMAccountName': self.__computerName,
            'unicodePwd': ('"%s"' % self.__computerPassword).encode('utf-16-le')
        }
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2, ciphers='ALL:@SECLEVEL=0')
        ldapServer = ldap3.Server(connection.host, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
        c = Connection(ldapServer, connection.username + '@' + connection.domain, connection.password)
        c.bind()

        if (self.__delete):
            result = c.delete("cn=" + self.__computerName + ",cn=Computers,dc=" + ldap_domain)
            if result:
                context.log.highlight(u'{}'.format('Successfully deleted the "' + self.__computerName + '" Computer account'))
            elif result == False and c.last_error == "noSuchObject":
                context.log.highlight(u'{}'.format('Computer named "' + self.__computerName + '" was not found'))
            elif result == False and c.last_error == "insufficientAccessRights":
                context.log.highlight(
                    u'{}'.format('Insufficient Access Rights to delete the Computer "' + self.__computerName + '"'))
            else:
                context.log.highlight(u'{}'.format(
                    'Unable to delete the "' + self.__computerName + '" Computer account. The error was: ' + c.last_error))
        else:
            result = c.add("cn=" + self.__computerName + ",cn=Computers,dc=" + ldap_domain,
                           ['top', 'person', 'organizationalPerson', 'user', 'computer'], ucd)
            if result:
                context.log.highlight('Successfully added the machine account: "' + self.__computerName + '" with Password: "' + self.__computerPassword + '"')
                context.log.highlight(u'{}'.format('You can try to verify this with the CME command:'))
                context.log.highlight(u'{}'.format(
                    'cme ldap ' + connection.host + ' -u ' + connection.username + ' -p ' + connection.password + ' -M group-mem -o GROUP="Domain Computers"'))
            elif result == False and c.last_error == "entryAlreadyExists":
                context.log.highlight(u'{}'.format('The Computer account "' + self.__computerName + '" already exists'))
            elif not result:
                context.log.highlight(u'{}'.format(
                    'Unable to add the "' + self.__computerName + '" Computer account. The error was: ' + c.last_error))
        c.unbind()
