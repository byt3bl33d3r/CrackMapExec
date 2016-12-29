from impacket.smbconnection import SessionError
from cme.helpers import gen_random_string
import random
import string
import ntpath

class ShareEnum:

    def __init__(self, connection):
        self.smbconnection = connection.conn
        self.logger = connection.logger
        self.permissions = {}
        self.root = ntpath.normpath("\\" + gen_random_string())

    def enum(self):
        for share in self.smbconnection.listShares():
            share_name = share['shi1_netname'][:-1]
            self.permissions[share_name] = []

            try:
                self.smbconnection.listPath(share_name, '*')
                self.permissions[share_name].append('READ')
            except SessionError:
                pass

            try:
                self.smbconnection.createDirectory(share_name, self.root)
                self.smbconnection.deleteDirectory(share_name, self.root)
                self.permissions[share_name].append('WRITE')
            except SessionError:
                pass

        self.logger.success('Enumerating shares')
        self.logger.highlight(u'{:<15} {}'.format('SHARE', 'Permissions'))
        self.logger.highlight(u'{:<15} {}'.format('-----', '-----------'))
        for share, perm in self.permissions.iteritems():
            if not perm:
                self.logger.highlight(u'{:<15} {}'.format(share, 'NO ACCESS'))
            else:
                self.logger.highlight(u'{:<15} {}'.format(share, ', '.join(perm)))
