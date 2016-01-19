from time import strftime, localtime
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA
import settings

class RemoteFile:
    def __init__(self, smbConnection, fileName, share='ADMIN$', access = FILE_READ_DATA | FILE_WRITE_DATA ):
        self.__smbConnection = smbConnection
        self.__share = share
        self.__access = access
        self.__fileName = fileName
        self.__tid = self.__smbConnection.connectTree(share)
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        self.__fid = self.__smbConnection.openFile(self.__tid, self.__fileName, desiredAccess = self.__access)

    def seek(self, offset, whence):
        # Implement whence, for now it's always from the beginning of the file
        if whence == 0:
            self.__currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data =  self.__smbConnection.readFile(self.__tid, self.__fid, self.__currentOffset, bytesToRead)
            self.__currentOffset += len(data)
            return data
        return ''

    def close(self):
        if self.__fid is not None:
            self.__smbConnection.closeFile(self.__tid, self.__fid)
            self.__fid = None

    def delete(self):
        self.__smbConnection.deleteFile(self.__share, self.__fileName)

    def tell(self):
        return self.__currentOffset

    def __str__(self):
        return "\\\\{}\\{}\\{}".format(self.__smbConnection.getRemoteHost(), self.__share, self.__fileName)

class RemoteFileSystem:

    def __init__(self, host, smbconnection, logger):
        self.__host = host
        self.__smbconnection = smbconnection
        self.__logger = logger

    def download(self):
        out = open(settings.args.download[1], 'wb')
        self.__smbconnection.getFile(settings.args.share,  settings.args.download[0], out.write)
        self.__logger.success("Downloaded file")

    def upload(self):
        up = open(settings.args.upload[0] , 'rb')
        self.__smbconnection.putFile(settings.args.share, settings.args.upload[1], up.read)
        self.__logger.success("Uploaded file")

    def delete(self):
        self.__smbconnection.deleteFile(settings.args.share, settings.args.delete)
        self.__logger.success("Deleted file")

    def list(self):
        if settings.args.list == '.':
            path = '*'
        else:
            path = settings.args.list + '/*'

        dir_list = self.__smbconnection.listPath(settings.args.share.decode('utf-8'), path.decode('utf-8'))
        #normalize output
        if path == '*':
            path = settings.args.share
        elif path != '*':
            path = settings.args.share + '/' + path[:-2]

        self.__logger.success(u"Contents of {}:".format(path.decode('utf-8')))
        for f in dir_list:
            self.__logger.results(u"{}rw-rw-rw- {:>7} {} {}".format('d' if f.is_directory() > 0 else '-', 
                                                            f.get_filesize(),
                                                            strftime('%Y-%m-%d %H:%M', localtime(f.get_mtime_epoch())), 
                                                            f.get_longname()))