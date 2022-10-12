#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @dmcxblue

class CMEModule:

    name = 'enum_unquoted_paths'
    description = "Get Unquoted Service Paths"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        '''     

    def on_admin_login(self, context, connection):

        command = 'powershell.exe -c "powershell.exe -Enc "RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAC0AYwBsAGEAcwBzACAAVwBpAG4AMwAyAF8AUwBlAHIAdgBpAGMAZQAgAC0AUAByAG8AcABlAHIAdAB5ACAATgBhAG0AZQAsACAARABpAHMAcABsAGEAeQBOAGEAbQBlACwAIABQAGEAdABoAE4AYQBtAGUALAAgAFMAdABhAHIAdABNAG8AZABlACAAfAAgAFcAaABlAHIAZQAgAHsAJABfAC4AUwB0AGEAcgB0AE0AbwBkAGUAIAAtAGUAcQAgACIAQQB1AHQAbwAiACAALQBhAG4AZAAgACQAXwAuAFAAYQB0AGgATgBhAG0AZQAgAC0AbgBvAHQAbABpAGsAZQAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwAqACIAIAAtAGEAbgBkACAAJABfAC4AUABhAHQAaABOAGEAbQBlACAALQBuAG8AdABsAGkAawBlACAAJwAiACoAJwB9ACAAfAAgAHMAZQBsAGUAYwB0ACAAUABhAHQAaABOAGEAbQBlACwARABpAHMAcABsAGEAeQBOAGEAbQBlACwATgBhAG0AZQA="'
        context.log.info('Searching for Unquoted Service Paths')
        p = connection.execute(command, True)
        context.log.highlight(p)
