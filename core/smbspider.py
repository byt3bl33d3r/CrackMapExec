from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA

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


def spider(smb_conn, ip, share, subfolder, patt, depth):
    if subfolder == '' or subfolder == '.':
        subfolder = '*'

    elif subfolder.startswith('*/'):
        subfolder = subfolder[2:] + '/*'

    else:
        subfolder = subfolder.replace('/*/', '/') + '/*'

    try:
        filelist = smb_conn.listPath(share, subfolder)
        dir_list(filelist, ip, subfolder, patt, share, smb_conn)
        if depth == 0:
            return
    except SessionError:
        if args.verbose: traceback.print_exc()
        return

    for result in filelist:
        if result.is_directory() and result.get_longname() != '.' and result.get_longname() != '..':
            if subfolder == '*':
                spider(smb_conn, ip, share, subfolder.replace('*', '') + result.get_longname(), patt, depth-1)
            elif subfolder != '*' and (subfolder[:-2].split('/')[-1] not in args.exclude_dirs):
                spider(smb_conn, ip, share, subfolder.replace('*', '') + result.get_longname(), patt, depth-1)
    return

def dir_list(files, ip, path, pattern, share, smb):
    for result in files:
        for instance in pattern:
            if re.findall(instance, result.get_longname()):
                if result.is_directory():
                    print_att("//{}/{}{} [dir]".format(ip, path.replace('*', ''), result.get_longname()))
                else:
                    print_att("//{}/{}{} [lastm:'{}' size:{}]".format(ip,
                                                                     path.replace('*', ''),
                                                                     result.get_longname(),
                                                                     strftime('%Y-%m-%d %H:%M', localtime(result.get_mtime_epoch())),
                                                                     result.get_filesize()))

            if args.search_content:
                if not result.is_directory():
                    search_content(smb, path, result, share, instance, ip)

    return

def search_content(smb, path, result, share, pattern, ip):
    try:
        rfile = RemoteFile(smb, path.replace('*', '') + result.get_longname(), share, access = FILE_READ_DATA)
        rfile.open()

        while True:
            try:
                contents = rfile.read(4096)
            except SessionError as e:
                if 'STATUS_END_OF_FILE' in str(e):
                    return

            if re.findall(pattern, contents):
                print_att("//{}/{}{} [lastm:'{}' size:{} offset:{} pattern:{}]".format(ip, 
                                                                                      path.replace('*', ''),
                                                                                      result.get_longname(), 
                                                                                      strftime('%Y-%m-%d %H:%M', localtime(result.get_mtime_epoch())), 
                                                                                      result.get_filesize(), 
                                                                                      rfile.tell(), 
                                                                                      pattern.pattern))
                rfile.close()
                return

    except SessionError as e:
        if args.verbose: traceback.print_exc()
        if 'STATUS_SHARING_VIOLATION' in str(e):
            pass

    except Exception as e:
        if args.verbose: traceback.print_exc()
        print_error(str(e))