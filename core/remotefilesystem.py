from logger import *
from time import strftime, localtime
import settings

class RemoteFileSystem:

    def __init__(self, host, smbconnection):
        self.__host = host
        self.__smbconnection = smbconnection

    def download(self):
        out = open(settings.args.download.split('\\')[-1], 'wb')
        self.__smbconnection.getFile(settings.args.share,  settings.args.download, out.write)
        print_succ("{}:{} Downloaded file".format(self.__host, settings.args.port))

    def upload(self):
        up = open(settings.args.upload[0] , 'rb')
        self.__smbconnection.putFile(settings.args.share, settings.args.upload[1], up.read)
        print_succ("{}:{} Uploaded file".format(self.__host, settings.args.port))

    def delete(self):
        self.__smbconnection.deleteFile(settings.args.share, settings.args.delete)
        print_succ("{}:{} Deleted file".format(self.__host, settings.args.port))

    def list(self):
        if settings.args.list == '.':
            path = '*'
        else:
            path = settings.args.list + '/*'

        dir_list = self.__smbconnection.listPath(settings.args.share, path)
        #so we get a pretty output
        if path == '*':
            path = settings.args.share
        elif path != '*':
            path = settings.args.share + '/' + path[:-2]

        print_succ("{}:{} Contents of {}:".format(self.__host, settings.args.port, path))
        for f in dir_list:
            print_att(u"{}rw-rw-rw- {:>7} {} {}".format('d' if f.is_directory() > 0 else '-', 
                                                        f.get_filesize(),
                                                        strftime('%Y-%m-%d %H:%M', localtime(f.get_mtime_epoch())), 
                                                        f.get_longname()))