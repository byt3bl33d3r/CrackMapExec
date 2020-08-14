import logging


# Todo 
# add functions to change pd display options on the fly

class database:

    def __init__(self, conn):
        self.conn = conn

    @staticmethod
    def db_schema(db_conn):
    #AZ Tables
        db_conn.execute('''CREATE TABLE "AppRoleAssignments" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            "creationTimestamp" DATETIME,
            id TEXT,
            "principalDisplayName" TEXT,
            "principalId" TEXT,
            "principalType" TEXT,
            "resourceDisplayName" TEXT,
            "resourceId" TEXT,
            PRIMARY KEY ("objectId")
            )''')


        db_conn.execute('''CREATE TABLE "ApplicationRefs" (
            "appCategory" TEXT,
            "appContextId" TEXT,
            "appData" TEXT,
            "appId" TEXT NOT NULL,
            "appRoles" TEXT,
            "availableToOtherTenants" BOOLEAN,
            "displayName" TEXT,
            "errorUrl" TEXT,
            homepage TEXT,
            "identifierUris" TEXT,
            "knownClientApplications" TEXT,
            "logoutUrl" TEXT,
            "logoUrl" TEXT,
            "mainLogo" BLOB,
            "oauth2Permissions" TEXT,
            "publisherDomain" TEXT,
            "publisherName" TEXT,
            "publicClient" BOOLEAN,
            "replyUrls" TEXT,
            "requiredResourceAccess" TEXT,
            "samlMetadataUrl" TEXT,
            "supportsConvergence" BOOLEAN,
            PRIMARY KEY ("appId")
            )''')

        db_conn.execute('''CREATE TABLE "Applications" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            "addIns" TEXT,
            "allowActAsForAllClients" BOOLEAN,
            "allowPassthroughUsers" BOOLEAN,
            "appBranding" TEXT,
            "appCategory" TEXT,
            "appData" TEXT,
            "appId" TEXT,
            "applicationTemplateId" TEXT,
            "appMetadata" TEXT,
            "appRoles" TEXT,
            "availableToOtherTenants" BOOLEAN,
            "displayName" TEXT,
            "encryptedMsiApplicationSecret" BLOB,
            "errorUrl" TEXT,
            "groupMembershipClaims" TEXT,
            homepage TEXT,
            "identifierUris" TEXT,
            "informationalUrls" TEXT,
            "isDeviceOnlyAuthSupported" BOOLEAN,
            "keyCredentials" TEXT,
            "knownClientApplications" TEXT,
            logo BLOB,
            "logoUrl" TEXT,
            "logoutUrl" TEXT,
            "mainLogo" BLOB,
            "oauth2AllowIdTokenImplicitFlow" BOOLEAN,
            "oauth2AllowImplicitFlow" BOOLEAN,
            "oauth2AllowUrlPathMatching" BOOLEAN,
            "oauth2Permissions" TEXT,
            "oauth2RequirePostResponse" BOOLEAN,
            "optionalClaims" TEXT,
            "parentalControlSettings" TEXT,
            "passwordCredentials" TEXT,
            "publicClient" BOOLEAN,
            "publisherDomain" TEXT,
            "recordConsentConditions" TEXT,
            "replyUrls" TEXT,
            "requiredResourceAccess" TEXT,
            "samlMetadataUrl" TEXT,
            "supportsConvergence" BOOLEAN,
            "tokenEncryptionKeyId" TEXT,
            "trustedCertificateSubjects" TEXT,
            "verifiedPublisher" TEXT,
            PRIMARY KEY ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE "Contacts" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            city TEXT,
            "cloudAudioConferencingProviderInfo" TEXT,
            "cloudMSRtcIsSipEnabled" BOOLEAN,
            "cloudMSRtcOwnerUrn" TEXT,
            "cloudMSRtcPolicyAssignments" TEXT,
            "cloudMSRtcPool" TEXT,
            "cloudMSRtcServiceAttributes" TEXT,
            "cloudRtcUserPolicies" TEXT,
            "cloudSipLine" TEXT,
            "companyName" TEXT,
            country TEXT,
            department TEXT,
            "dirSyncEnabled" BOOLEAN,
            "displayName" TEXT,
            "facsimileTelephoneNumber" TEXT,
            "givenName" TEXT,
            "jobTitle" TEXT,
            "lastDirSyncTime" DATETIME,
            mail TEXT,
            "mailNickname" TEXT,
            mobile TEXT,
            "physicalDeliveryOfficeName" TEXT,
            "postalCode" TEXT,
            "provisioningErrors" TEXT,
            "proxyAddresses" TEXT,
            "sipProxyAddress" TEXT,
            state TEXT,
            "streetAddress" TEXT,
            surname TEXT,
            "telephoneNumber" TEXT,
            "thumbnailPhoto" BLOB,
            PRIMARY KEY ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE "Devices" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            "accountEnabled" BOOLEAN,
            "alternativeSecurityIds" TEXT,
            "approximateLastLogonTimestamp" DATETIME,
            "bitLockerKey" TEXT,
            capabilities TEXT,
            "complianceExpiryTime" DATETIME,
            "compliantApplications" TEXT,
            "compliantAppsManagementAppId" TEXT,
            "deviceCategory" TEXT,
            "deviceId" TEXT,
            "deviceKey" TEXT,
            "deviceManufacturer" TEXT,
            "deviceManagementAppId" TEXT,
            "deviceMetadata" TEXT,
            "deviceModel" TEXT,
            "deviceObjectVersion" BIGINT,
            "deviceOSType" TEXT,
            "deviceOSVersion" TEXT,
            "deviceOwnership" TEXT,
            "devicePhysicalIds" TEXT,
            "deviceSystemMetadata" TEXT,
            "deviceTrustType" TEXT,
            "dirSyncEnabled" BOOLEAN,
            "displayName" TEXT,
            "domainName" TEXT,
            "enrollmentProfileName" TEXT,
            "enrollmentType" TEXT,
            "exchangeActiveSyncId" TEXT,
            "isCompliant" BOOLEAN,
            "isManaged" BOOLEAN,
            "isRooted" BOOLEAN,
            "keyCredentials" TEXT,
            "lastDirSyncTime" DATETIME,
            "localCredentials" TEXT,
            "managementType" TEXT,
            "onPremisesSecurityIdentifier" TEXT,
            "organizationalUnit" TEXT,
            "profileType" TEXT,
            reserved1 TEXT,
            "systemLabels" TEXT,
            PRIMARY KEY ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE "DirectoryRoles" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            "cloudSecurityIdentifier" TEXT,
            description TEXT,
            "displayName" TEXT,
            "isSystem" BOOLEAN,
            "roleDisabled" BOOLEAN,
            "roleTemplateId" TEXT,
            PRIMARY KEY ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE "ExtensionPropertys" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            "appDisplayName" TEXT,
            name TEXT,
            "dataType" TEXT,
            "isSyncedFromOnPremises" BOOLEAN,
            "targetObjects" TEXT,
            PRIMARY KEY ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE "Groups" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            "appMetadata" TEXT,
            classification TEXT,
            "cloudSecurityIdentifier" TEXT,
            "createdDateTime" DATETIME,
            "createdByAppId" TEXT,
            description TEXT,
            "dirSyncEnabled" BOOLEAN,
            "displayName" TEXT,
            "exchangeResources" TEXT,
            "expirationDateTime" DATETIME,
            "externalGroupIds" TEXT,
            "externalGroupProviderId" TEXT,
            "externalGroupState" TEXT,
            "creationOptions" TEXT,
            "groupTypes" TEXT,
            "isAssignableToRole" BOOLEAN,
            "isMembershipRuleLocked" BOOLEAN,
            "isPublic" BOOLEAN,
            "lastDirSyncTime" DATETIME,
            "licenseAssignment" TEXT,
            mail TEXT,
            "mailNickname" TEXT,
            "mailEnabled" BOOLEAN,
            "membershipRule" TEXT,
            "membershipRuleProcessingState" TEXT,
            "membershipTypes" TEXT,
            "onPremisesSecurityIdentifier" TEXT,
            "preferredDataLocation" TEXT,
            "preferredLanguage" TEXT,
            "primarySMTPAddress" TEXT,
            "provisioningErrors" TEXT,
            "proxyAddresses" TEXT,
            "renewedDateTime" DATETIME,
            "securityEnabled" BOOLEAN,
            "sharepointResources" TEXT,
            "targetAddress" TEXT,
            theme TEXT,
            visibility TEXT,
            "wellKnownObject" TEXT,
            PRIMARY KEY ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE "OAuth2PermissionGrants" (
            "clientId" TEXT,
            "consentType" TEXT,
            "expiryTime" DATETIME,
            "objectId" TEXT NOT NULL,
            "principalId" TEXT,
            "resourceId" TEXT,
            scope TEXT,
            "startTime" DATETIME,
            PRIMARY KEY ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE "Policys" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            "displayName" TEXT,
            "keyCredentials" TEXT,
            "policyType" BIGINT,
            "policyDetail" TEXT,
            "policyIdentifier" TEXT,
            "tenantDefaultPolicy" BIGINT,
            PRIMARY KEY ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE "RoleAssignments" (
            id TEXT NOT NULL,
            "principalId" TEXT,
            "resourceScopes" TEXT,
            "roleDefinitionId" TEXT,
            PRIMARY KEY (id)
            )''')

        db_conn.execute('''CREATE TABLE "RoleDefinitions" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            description TEXT,
            "displayName" TEXT,
            "isBuiltIn" BOOLEAN,
            "isEnabled" BOOLEAN,
            "resourceScopes" TEXT,
            "rolePermissions" TEXT,
            "templateId" TEXT,
            version TEXT,
            PRIMARY KEY ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE "ServicePrincipals" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            "accountEnabled" BOOLEAN,
            "addIns" TEXT,
            "alternativeNames" TEXT,
            "appBranding" TEXT,
            "appCategory" TEXT,
            "appData" TEXT,
            "appDisplayName" TEXT,
            "appId" TEXT,
            "applicationTemplateId" TEXT,
            "appMetadata" TEXT,
            "appOwnerTenantId" TEXT,
            "appRoleAssignmentRequired" BOOLEAN,
            "appRoles" TEXT,
            "authenticationPolicy" TEXT,
            "displayName" TEXT,
            "errorUrl" TEXT,
            homepage TEXT,
            "informationalUrls" TEXT,
            "keyCredentials" TEXT,
            "logoutUrl" TEXT,
            "managedIdentityResourceId" TEXT,
            "microsoftFirstParty" BOOLEAN,
            "notificationEmailAddresses" TEXT,
            "oauth2Permissions" TEXT,
            "passwordCredentials" TEXT,
            "preferredSingleSignOnMode" TEXT,
            "preferredTokenSigningKeyEndDateTime" DATETIME,
            "preferredTokenSigningKeyThumbprint" TEXT,
            "publisherName" TEXT,
            "replyUrls" TEXT,
            "samlMetadataUrl" TEXT,
            "samlSingleSignOnSettings" TEXT,
            "servicePrincipalNames" TEXT,
            tags TEXT,
            "tokenEncryptionKeyId" TEXT,
            "servicePrincipalType" TEXT,
            "useCustomTokenSigningKey" BOOLEAN,
            "verifiedPublisher" TEXT,
            PRIMARY KEY ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE "TenantDetails" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            "assignedPlans" TEXT,
            "authorizedServiceInstance" TEXT,
            city TEXT,
            "cloudRtcUserPolicies" TEXT,
            "companyLastDirSyncTime" DATETIME,
            "companyTags" TEXT,
            "compassEnabled" BOOLEAN,
            country TEXT,
            "countryLetterCode" TEXT,
            "dirSyncEnabled" BOOLEAN,
            "displayName" TEXT,
            "isMultipleDataLocationsForServicesEnabled" BOOLEAN,
            "marketingNotificationEmails" TEXT,
            "postalCode" TEXT,
            "preferredLanguage" TEXT,
            "privacyProfile" TEXT,
            "provisionedPlans" TEXT,
            "provisioningErrors" TEXT,
            "releaseTrack" TEXT,
            "replicationScope" TEXT,
            "securityComplianceNotificationMails" TEXT,
            "securityComplianceNotificationPhones" TEXT,
            "selfServePasswordResetPolicy" TEXT,
            state TEXT,
            street TEXT,
            "technicalNotificationMails" TEXT,
            "telephoneNumber" TEXT,
            "tenantType" TEXT,
            "verifiedDomains" TEXT,
            "windowsCredentialsEncryptionCertificate" BLOB,
            PRIMARY KEY ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE "Users" (
            "objectType" TEXT,
            "objectId" TEXT NOT NULL,
            "deletionTimestamp" DATETIME,
            "acceptedAs" TEXT,
            "acceptedOn" DATETIME,
            "accountEnabled" BOOLEAN,
            "ageGroup" TEXT,
            "alternativeSecurityIds" TEXT,
            "signInNames" TEXT,
            "signInNamesInfo" TEXT,
            "appMetadata" TEXT,
            "assignedLicenses" TEXT,
            "assignedPlans" TEXT,
            city TEXT,
            "cloudAudioConferencingProviderInfo" TEXT,
            "cloudMSExchRecipientDisplayType" BIGINT,
            "cloudMSRtcIsSipEnabled" BOOLEAN,
            "cloudMSRtcOwnerUrn" TEXT,
            "cloudMSRtcPolicyAssignments" TEXT,
            "cloudMSRtcPool" TEXT,
            "cloudMSRtcServiceAttributes" TEXT,
            "cloudRtcUserPolicies" TEXT,
            "cloudSecurityIdentifier" TEXT,
            "cloudSipLine" TEXT,
            "cloudSipProxyAddress" TEXT,
            "companyName" TEXT,
            "consentProvidedForMinor" TEXT,
            country TEXT,
            "createdDateTime" DATETIME,
            "creationType" TEXT,
            department TEXT,
            "dirSyncEnabled" BOOLEAN,
            "displayName" TEXT,
            "employeeId" TEXT,
            "extensionAttribute1" TEXT,
            "extensionAttribute2" TEXT,
            "extensionAttribute3" TEXT,
            "extensionAttribute4" TEXT,
            "extensionAttribute5" TEXT,
            "extensionAttribute6" TEXT,
            "extensionAttribute7" TEXT,
            "extensionAttribute8" TEXT,
            "extensionAttribute9" TEXT,
            "extensionAttribute10" TEXT,
            "extensionAttribute11" TEXT,
            "extensionAttribute12" TEXT,
            "extensionAttribute13" TEXT,
            "extensionAttribute14" TEXT,
            "extensionAttribute15" TEXT,
            "facsimileTelephoneNumber" TEXT,
            "givenName" TEXT,
            "hasOnPremisesShadow" BOOLEAN,
            "immutableId" TEXT,
            "invitedAsMail" TEXT,
            "invitedOn" DATETIME,
            "inviteReplyUrl" TEXT,
            "inviteResources" TEXT,
            "inviteTicket" TEXT,
            "isCompromised" BOOLEAN,
            "isResourceAccount" BOOLEAN,
            "jobTitle" TEXT,
            "jrnlProxyAddress" TEXT,
            "lastDirSyncTime" DATETIME,
            "lastPasswordChangeDateTime" DATETIME,
            "legalAgeGroupClassification" TEXT,
            mail TEXT,
            "mailNickname" TEXT,
            mobile TEXT,
            "msExchRecipientTypeDetails" BIGINT,
            "msExchRemoteRecipientType" BIGINT,
            "msExchMailboxGuid" TEXT,
            "netId" TEXT,
            "onPremisesDistinguishedName" TEXT,
            "onPremisesPasswordChangeTimestamp" DATETIME,
            "onPremisesSecurityIdentifier" TEXT,
            "onPremisesUserPrincipalName" TEXT,
            "otherMails" TEXT,
            "passwordPolicies" TEXT,
            "passwordProfile" TEXT,
            "physicalDeliveryOfficeName" TEXT,
            "postalCode" TEXT,
            "preferredDataLocation" TEXT,
            "preferredLanguage" TEXT,
            "primarySMTPAddress" TEXT,
            "provisionedPlans" TEXT,
            "provisioningErrors" TEXT,
            "proxyAddresses" TEXT,
            "refreshTokensValidFromDateTime" DATETIME,
            "releaseTrack" TEXT,
            "searchableDeviceKey" TEXT,
            "selfServePasswordResetData" TEXT,
            "shadowAlias" TEXT,
            "shadowDisplayName" TEXT,
            "shadowLegacyExchangeDN" TEXT,
            "shadowMail" TEXT,
            "shadowMobile" TEXT,
            "shadowOtherMobile" TEXT,
            "shadowProxyAddresses" TEXT,
            "shadowTargetAddress" TEXT,
            "shadowUserPrincipalName" TEXT,
            "showInAddressList" BOOLEAN,
            "sipProxyAddress" TEXT,
            "smtpAddresses" TEXT,
            state TEXT,
            "streetAddress" TEXT,
            surname TEXT,
            "telephoneNumber" TEXT,
            "thumbnailPhoto" BLOB,
            "usageLocation" TEXT,
            "userPrincipalName" TEXT,
            "userState" TEXT,
            "userStateChangedOn" DATETIME,
            "userType" TEXT,
            "strongAuthenticationDetail" TEXT,
            "windowsInformationProtectionKey" TEXT,
            PRIMARY KEY ("objectId")
            )''')

# Relationship Tables
        db_conn.execute('''CREATE TABLE lnk_application_owner_serviceprincipal (
            "Application" TEXT,
            "ServicePrincipal" TEXT,
            FOREIGN KEY("Application") REFERENCES "Applications" ("objectId"),
            FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE lnk_application_owner_user (
            "Application" TEXT,
            "User" TEXT,
            FOREIGN KEY("Application") REFERENCES "Applications" ("objectId"),
            FOREIGN KEY("User") REFERENCES "Users" ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE lnk_device_owner (
            "Device" TEXT,
            "User" TEXT,
            FOREIGN KEY("Device") REFERENCES "Devices" ("objectId"),
            FOREIGN KEY("User") REFERENCES "Users" ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE lnk_group_member_contact (
            "Group" TEXT,
            "Contact" TEXT,
            FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"),
            FOREIGN KEY("Contact") REFERENCES "Contacts" ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE lnk_group_member_device (
            "Group" TEXT,
            "Device" TEXT,
            FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"),
            FOREIGN KEY("Device") REFERENCES "Devices" ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE lnk_group_member_group (
            "Group" TEXT,
            "childGroup" TEXT,
            FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"),
            FOREIGN KEY("childGroup") REFERENCES "Groups" ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE lnk_group_member_user (
            "Group" TEXT,
            "User" TEXT,
            FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"),
            FOREIGN KEY("User") REFERENCES "Users" ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE lnk_role_member_serviceprincipal (
            "DirectoryRole" TEXT,
            "ServicePrincipal" TEXT,
            FOREIGN KEY("DirectoryRole") REFERENCES "DirectoryRoles" ("objectId"),
            FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE lnk_role_member_user (
            "DirectoryRole" TEXT,
            "User" TEXT,
            FOREIGN KEY("DirectoryRole") REFERENCES "DirectoryRoles" ("objectId"),
            FOREIGN KEY("User") REFERENCES "Users" ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE lnk_serviceprincipal_owner_serviceprincipal (
            "ServicePrincipal" TEXT,
            "childServicePrincipal" TEXT,
            FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId"),
            FOREIGN KEY("childServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
            )''')

        db_conn.execute('''CREATE TABLE lnk_serviceprincipal_owner_user (
            "ServicePrincipal" TEXT,
            "User" TEXT,
            FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId"),
            FOREIGN KEY("User") REFERENCES "Users" ("objectId")
            )''')


    def add_user(self, user_id_json):
        """Check if this user has already been added to the database, if not add them in.

        userObj is a json object containing all user info retrieved from azure
        """

        #displayName = str(userObj['displayName'])
        #mail = str(userObj['mail'])
        #mailNickname = str(userObj['mailNickname'])
        objectId = str(user_id_json['objectId'])
        #onPremisesSecurityIdentifier = str(userObj['onPremisesSecurityIdentifier'])
        #otherMails = str(userObj['otherMails'])
        #telephoneNumber = str(userObj['telephoneNumber'])
        #userPrincipalName = str(userObj['userPrincipalName'])

        #plans = []
        #for plan in userObj["assignedPlans"]:
        #    plans.append(plan["service"])

        #assignedPlans = str(plans)


        cur = self.conn.cursor()
        print('here')

        cur.execute('SELECT * FROM users WHERE objectId=?', [objectId])
        results = cur.fetchall()

        if not len(results):
            #cur.execute("INSERT INTO users (assignedPlans, displayName, mail, mailNickname, objectId, sid, otherMails, telephoneNumber, userPrincipalName) VALUES (?,?,?,?,?,?,?,?,?)", [assignedPlans, displayName, mail, mailNickname, objectId, onPremisesSecurityIdentifier, otherMails, telephoneNumber, userPrincipalName])
            cur.execute('INSERT INTO "Users" ("objectType", "objectId", "deletionTimestamp", "acceptedAs", "acceptedOn", "accountEnabled", "ageGroup", "alternativeSecurityIds", "signInNames", "signInNamesInfo", "appMetadata", "assignedLicenses", "assignedPlans", city, "cloudAudioConferencingProviderInfo", "cloudMSExchRecipientDisplayType", "cloudMSRtcIsSipEnabled", "cloudMSRtcOwnerUrn", "cloudMSRtcPolicyAssignments", "cloudMSRtcPool", "cloudMSRtcServiceAttributes", "cloudRtcUserPolicies", "cloudSecurityIdentifier", "cloudSipLine", "cloudSipProxyAddress", "companyName", "consentProvidedForMinor", country, "createdDateTime", "creationType", department, "dirSyncEnabled", "displayName", "employeeId", "extensionAttribute1", "extensionAttribute2", "extensionAttribute3", "extensionAttribute4", "extensionAttribute5", "extensionAttribute6", "extensionAttribute7", "extensionAttribute8", "extensionAttribute9", "extensionAttribute10", "extensionAttribute11", "extensionAttribute12", "extensionAttribute13", "extensionAttribute14", "extensionAttribute15", "facsimileTelephoneNumber", "givenName", "hasOnPremisesShadow", "immutableId", "invitedAsMail", "invitedOn", "inviteReplyUrl", "inviteResources", "inviteTicket", "isCompromised", "isResourceAccount", "jobTitle", "jrnlProxyAddress", "lastDirSyncTime", "lastPasswordChangeDateTime", "legalAgeGroupClassification", mail, "mailNickname", mobile, "msExchRecipientTypeDetails", "msExchRemoteRecipientType", "msExchMailboxGuid", "netId", "onPremisesDistinguishedName", "onPremisesPasswordChangeTimestamp", "onPremisesSecurityIdentifier", "onPremisesUserPrincipalName", "otherMails", "passwordPolicies", "passwordProfile", "physicalDeliveryOfficeName", "postalCode", "preferredDataLocation", "preferredLanguage", "primarySMTPAddress", "provisionedPlans", "provisioningErrors", "proxyAddresses", "refreshTokensValidFromDateTime", "releaseTrack", "searchableDeviceKey", "selfServePasswordResetData", "shadowAlias", "shadowDisplayName", "shadowLegacyExchangeDN", "shadowMail", "shadowMobile", "shadowOtherMobile", "shadowProxyAddresses", "shadowTargetAddress", "shadowUserPrincipalName", "showInAddressList", "sipProxyAddress", "smtpAddresses", state, "streetAddress", surname, "telephoneNumber", "thumbnailPhoto", "usageLocation", "userPrincipalName", "userState", "userStateChangedOn", "userType", "strongAuthenticationDetail", "windowsInformationProtectionKey") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [ user_id_json.get("objectType", ""), user_id_json.get("objectId", ""), user_id_json.get("deletionTimestamp", ""), user_id_json.get("acceptedAs", ""), user_id_json.get("acceptedOn", ""), user_id_json.get("accountEnabled", ""), user_id_json.get("ageGroup", ""), user_id_json.get("alternativeSecurityIds", ""), json.dumps(user_id_json.get("signInNames", "")),  user_id_json.get("signInNamesInfo", ""), user_id_json.get("appMetadata", ""),  json.dumps(user_id_json.get("assignedLicenses", "")), json.dumps(user_id_json.get("assignedPlans", "")), user_id_json.get("city", ""), user_id_json.get("cloudAudioConferencingProviderInfo", ""), user_id_json.get("cloudMSExchRecipientDisplayType", ""), user_id_json.get("cloudMSRtcIsSipEnabled", ""), user_id_json.get("cloudMSRtcOwnerUrn", ""), user_id_json.get("cloudMSRtcPolicyAssignments", ""), user_id_json.get("cloudMSRtcPool", ""), user_id_json.get("cloudMSRtcServiceAttributes", ""), user_id_json.get("cloudRtcUserPolicies", ""), user_id_json.get("cloudSecurityIdentifier", ""), user_id_json.get("cloudSipLine", ""), user_id_json.get("cloudSipProxyAddress", ""), user_id_json.get("companyName", ""), user_id_json.get("consentProvidedForMinor", ""), user_id_json.get("country", ""), user_id_json.get("createdDateTime", ""), user_id_json.get("creationType", ""), user_id_json.get("department", ""), user_id_json.get("dirSyncEnabled", ""), user_id_json.get("displayName", ""), user_id_json.get("employeeId", ""), user_id_json.get("extensionAttribute1", ""), user_id_json.get("extensionAttribute2", ""), user_id_json.get("extensionAttribute3", ""), user_id_json.get("extensionAttribute4", ""), user_id_json.get("extensionAttribute5", ""), user_id_json.get("extensionAttribute6", ""), user_id_json.get("extensionAttribute7", ""), user_id_json.get("extensionAttribute8", ""), user_id_json.get("extensionAttribute9", ""), user_id_json.get("extensionAttribute10", ""), user_id_json.get("extensionAttribute11", ""), user_id_json.get("extensionAttribute12", ""), user_id_json.get("extensionAttribute13", ""), user_id_json.get("extensionAttribute14", ""), user_id_json.get("extensionAttribute15", ""), user_id_json.get("facsimileTelephoneNumber", ""), user_id_json.get("givenName", ""), user_id_json.get("hasOnPremisesShadow", ""), user_id_json.get("immutableId", ""), user_id_json.get("invitedAsMail", ""), user_id_json.get("invitedOn", ""), user_id_json.get("inviteReplyUrl", ""), user_id_json.get("inviteResources", ""), user_id_json.get("inviteTicket", ""), user_id_json.get("isCompromised", ""), user_id_json.get("isResourceAccount", ""), user_id_json.get("jobTitle", ""), user_id_json.get("jrnlProxyAddress", ""), user_id_json.get("lastDirSyncTime", ""), user_id_json.get("lastPasswordChangeDateTime", ""), user_id_json.get("legalAgeGroupClassification", ""), user_id_json.get("mail", ""), user_id_json.get("mailNickname", ""), user_id_json.get("mobile", ""), user_id_json.get("msExchRecipientTypeDetails", ""), user_id_json.get("msExchRemoteRecipientType", ""), user_id_json.get("msExchMailboxGuid", ""), user_id_json.get("netId", ""), user_id_json.get("onPremisesDistinguishedName", ""), user_id_json.get("onPremisesPasswordChangeTimestamp", ""), user_id_json.get("onPremisesSecurityIdentifier", ""), user_id_json.get("onPremisesUserPrincipalName", ""), json.dumps(user_id_json.get("otherMails", "")), user_id_json.get("passwordPolicies", ""), user_id_json.get("passwordProfile", ""), user_id_json.get("physicalDeliveryOfficeName", ""), user_id_json.get("postalCode", ""), user_id_json.get("preferredDataLocation", ""), user_id_json.get("preferredLanguage", ""), user_id_json.get("primarySMTPAddress", ""), json.dumps(user_id_json.get("provisionedPlans", "")), json.dumps(user_id_json.get("provisioningErrors", "")), json.dumps(user_id_json.get("proxyAddresses", "")), user_id_json.get("refreshTokensValidFromDateTime", ""), user_id_json.get("releaseTrack", ""), user_id_json.get("searchableDeviceKey", ""), user_id_json.get("selfServePasswordResetData", ""), user_id_json.get("shadowAlias", ""), user_id_json.get("shadowDisplayName", ""), user_id_json.get("shadowLegacyExchangeDN", ""), user_id_json.get("shadowMail", ""), user_id_json.get("shadowMobile", ""), user_id_json.get("shadowOtherMobile", ""), user_id_json.get("shadowProxyAddresses", ""), user_id_json.get("shadowTargetAddress", ""), user_id_json.get("shadowUserPrincipalName", ""), user_id_json.get("showInAddressList", ""), user_id_json.get("sipProxyAddress", ""), user_id_json.get("smtpAddresses", ""), user_id_json.get("state", ""), user_id_json.get("streetAddress", ""), user_id_json.get("surname", ""), user_id_json.get("telephoneNumber", ""), user_id_json.get("thumbnailPhoto", ""), user_id_json.get("usageLocation", ""), user_id_json.get("userPrincipalName", ""), user_id_json.get("userState", ""), user_id_json.get("userStateChangedOn", ""), user_id_json.get("userType", ""), user_id_json.get("strongAuthenticationDetail", ""), user_id_json.get("windowsInformationProtectionKey", "") ] )
        cur.close()

        return cur.lastrowid


    def add_app(self, app_json):
        """Check if this app has already been added to the database, if not add it in.
        """

        cur = self.conn.cursor()

        objectId = str(app_json['objectId'])

        cur.execute('SELECT * FROM Applications WHERE objectId=?', [objectId])
        results = cur.fetchall()

        if not len(results):
            #cur.execute("INSERT INTO apps (DisplayName, appId, Homepage, objectId, allowGuestsSignIn, keyCredentials, passwordCredentials, wwwHomepage) VALUES (?,?,?,?,?,?,?,?)", [DisplayName, appId, homepage, objectId, allowGuestsSignIn, keyCredentials, passwordCredentials, wwwHomepage])
            cur.execute('INSERT INTO "Applications" ("objectType", "objectId", "deletionTimestamp", "addIns", "allowActAsForAllClients", "allowPassthroughUsers", "appBranding", "appCategory", "appData", "appId", "applicationTemplateId", "appMetadata", "appRoles", "availableToOtherTenants", "displayName", "encryptedMsiApplicationSecret", "errorUrl", "groupMembershipClaims", "homepage", "identifierUris", "informationalUrls", "isDeviceOnlyAuthSupported", "keyCredentials", "knownClientApplications", "logo", "logoUrl", "logoutUrl", "mainLogo", "oauth2AllowIdTokenImplicitFlow", "oauth2AllowImplicitFlow", "oauth2AllowUrlPathMatching", "oauth2Permissions", "oauth2RequirePostResponse", "optionalClaims", "parentalControlSettings", "passwordCredentials", "publicClient", "publisherDomain", "recordConsentConditions", "replyUrls", "requiredResourceAccess", "samlMetadataUrl", "supportsConvergence", "tokenEncryptionKeyId", "trustedCertificateSubjects", "verifiedPublisher") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',[ app_json.get("objectType", ""), app_json.get("objectId", ""), app_json.get("deletionTimestamp", ""), json.dumps(app_json.get("addIns", "")), app_json.get("allowActAsForAllClients", ""), app_json.get("allowPassthroughUsers", ""), app_json.get("appBranding", ""), app_json.get("appCategory", ""), app_json.get("appData", ""), app_json.get("appId", ""), app_json.get("applicationTemplateId", ""), app_json.get("appMetadata", ""), json.dumps(app_json.get("appRoles", "")), app_json.get("availableToOtherTenants", ""), app_json.get("displayName", ""), app_json.get("encryptedMsiApplicationSecret", ""), app_json.get("errorUrl", ""), app_json.get("groupMembershipClaims", ""), app_json.get("homepage", ""), json.dumps(app_json.get("identifierUris", "")), json.dumps(app_json.get("informationalUrls", "")), app_json.get("isDeviceOnlyAuthSupported", ""), json.dumps(app_json.get("keyCredentials", "")), json.dumps(app_json.get("knownClientApplications", "")), app_json.get("logo", ""), app_json.get("logoUrl", ""), app_json.get("logoutUrl", ""), app_json.get("mainLogo", ""), app_json.get("oauth2AllowIdTokenImplicitFlow", ""), app_json.get("oauth2AllowImplicitFlow", ""), app_json.get("oauth2AllowUrlPathMatching", ""), json.dumps(app_json.get("oauth2Permissions", "")), app_json.get("oauth2RequirePostResponse", ""), app_json.get("optionalClaims", ""), json.dumps(app_json.get("parentalControlSettings", "")), json.dumps(app_json.get("passwordCredentials", "")), app_json.get("publicClient", ""), app_json.get("publisherDomain", ""), app_json.get("recordConsentConditions", ""), json.dumps(app_json.get("replyUrls", "")), json.dumps(app_json.get("requiredResourceAccess", "")), app_json.get("samlMetadataUrl", ""), app_json.get("supportsConvergence", ""), app_json.get("tokenEncryptionKeyId", ""), app_json.get("trustedCertificateSubjects", ""), app_json.get("verifiedPublisher", "")])
        cur.close()

        return cur.lastrowid