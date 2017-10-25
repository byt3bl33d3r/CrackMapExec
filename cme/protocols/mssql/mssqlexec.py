import logging


class MSSQLEXEC:

    def __init__(self, connection):
        self.mssql_conn = connection
        self.outputBuffer = ''

    def execute(self, command, output=False):
        try:
            self.enable_xp_cmdshell()
            self.mssql_conn.sql_query("exec master..xp_cmdshell '{}'".format(command))

            if output:
                self.mssql_conn.printReplies()
                self.mssql_conn.colMeta[0]['TypeData'] = 80*2
                self.mssql_conn.printRows()
                self.outputBuffer = self.mssql_conn._MSSQL__rowsPrinter.getMessage()
                if len(self.outputBuffer):
                    self.outputBuffer = self.outputBuffer.split('\n', 2)[2]

            self.disable_xp_cmdshell()
            return self.outputBuffer

        except Exception as e:
            logging.debug('Error executing command via mssqlexec: {}'.format(e))

    def enable_xp_cmdshell(self):
        self.mssql_conn.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")

    def disable_xp_cmdshell(self):
        self.mssql_conn.sql_query("exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure 'show advanced options', 0 ;RECONFIGURE;")
