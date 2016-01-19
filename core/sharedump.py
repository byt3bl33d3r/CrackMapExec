from impacket.smbconnection import SessionError
import random
import string
import ntpath
import settings

class SHAREDUMP:

	def __init__(self, smbconnection, logger):
		self.__smbconnection = smbconnection
		self.__permdir = ''.join(random.sample(string.ascii_letters, 10))
		self.__logger = logger

	def dump(self, host):
		permissions = {}
		root = ntpath.normpath("\\{}".format(self.__permdir))

		for share in self.__smbconnection.listShares():
		    share_name = share['shi1_netname'][:-1]
		    permissions[share_name] = []

		    try:
		        if self.__smbconnection.listPath(share_name, '*'):
		            permissions[share_name].append('READ')
		    except SessionError:
		        pass

		    try:
		        if self.__smbconnection.createDirectory(share_name, root):
		            self.__smbconnection.deleteDirectory(share_name, root)
		            permissions[share_name].append('WRITE')
		    except SessionError:
		        pass

		self.__logger.success('Enumerating shares')
		self.__logger.results('{:<10} {}'.format('SHARE', 'Permissions'))
		self.__logger.results('{:<10} {}'.format('-----', '-----------'))
		for share, perm in permissions.iteritems():
		    if not perm:
		        self.__logger.results(u'{:<10} {}'.format(share, 'NO ACCESS'))
		    else:
		        self.__logger.results(u'{:<10} {}'.format(share, ', '.join(perm)))