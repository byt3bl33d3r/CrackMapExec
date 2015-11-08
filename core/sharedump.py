from logger import *
from impacket.smbconnection import SessionError
import random
import string
import ntpath
import settings

class SHAREDUMP:

	def __init__(self, smbconnection):
		self.__smbconnection = smbconnection
		self.__permdir = ''.join(random.sample(string.ascii_letters, 10))

	def dump(self, host):
		permissions = {}
		root = ntpath.normpath("\\{}".format(self.__permdir))

		for share in self.__smbconnection.listShares():
		    share_name = share['shi1_netname'][:-1]
		    permissions[share_name] = []

		    try:
		        if self.__smbconnection.listPath(share_name, '*', settings.args.passwd):
		            permissions[share_name].append('READ')
		    except SessionError:
		        pass

		    try:
		        if self.__smbconnection.createDirectory(share_name, root):
		            self.__smbconnection.deleteDirectory(share_name, root)
		            permissions[share_name].append('WRITE')
		    except SessionError:
		        pass

		print_succ('{}:{} Available shares:'.format(host, settings.args.port))
		print_att('{:>15} {:>15}'.format('SHARE', 'Permissions'))
		print_att('{:>15} {:>15}'.format('-----', '-----------'))
		for share, perm in permissions.iteritems():
		    if not perm:
		        print_att(u'{:>15} {:>15}'.format(share, 'NO ACCESS'))
		    else:
		        print_att(u'{:>15} {:>15}'.format(share, ', '.join(perm)))