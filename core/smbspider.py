import re
import settings
import traceback

from logger import *
from time import time, strftime, localtime
from impacket.smbconnection import SessionError
from remotefilesystem import RemoteFile
from impacket.smb3structs import FILE_READ_DATA

class SMBSPIDER:

    def __init__(self, host, smbconnection):
        self.__smbconnection = smbconnection
        self.__start_time = time()
        self.__host = host
        print_status("{}:{} Started spidering".format(self.__host, settings.args.port))

    def spider(self, subfolder, depth):
        '''
            Apperently spiders don't like stars! (*)
            who knew?
        '''

        if subfolder == '' or subfolder == '.':
            subfolder = '*'

        elif subfolder.startswith('*/'):
            subfolder = subfolder[2:] + '/*'

        else:
            subfolder = subfolder.replace('/*/', '/') + '/*'

        try:
            filelist = self.__smbconnection.listPath(settings.args.share, subfolder)
            self.dir_list(filelist, subfolder)
            if depth == 0:
                return
        except SessionError:
            if settings.args.verbose: traceback.print_exc()
            return

        for result in filelist:
            if result.is_directory() and result.get_longname() != '.' and result.get_longname() != '..':
                if subfolder == '*':
                    self.spider(subfolder.replace('*', '') + result.get_longname(), depth-1)
                elif subfolder != '*' and (subfolder[:-2].split('/')[-1] not in settings.args.exclude_dirs):
                    self.spider(subfolder.replace('*', '') + result.get_longname(), depth-1)
        return

    def dir_list(self, files, path):
        path = path.replace('*', '')
        for result in files:
            for pattern in settings.args.pattern:
                if re.findall(pattern, result.get_longname()):
                    if result.is_directory():
                        print_att(u"//{}/{}{} [dir]".format(self.__host, path, result.get_longname()))
                    else:
                        print_att(u"//{}/{}{} [lastm:'{}' size:{}]".format(self.__host,
                                                                           path,
                                                                           result.get_longname(),
                                                                           strftime('%Y-%m-%d %H:%M', localtime(result.get_mtime_epoch())),
                                                                           result.get_filesize()))

                if settings.args.search_content:
                    if not result.is_directory():
                        self.search_content(path, result, pattern)

        return

    def search_content(self, path, result, pattern):
        path = path.replace('*', '') 
        try:
            rfile = RemoteFile(self.__smbconnection, 
                               path + result.get_longname(), 
                               settings.args.share,
                               access = FILE_READ_DATA)
            rfile.open()

            while True:
                try:
                    contents = rfile.read(4096)
                except SessionError as e:
                    if 'STATUS_END_OF_FILE' in str(e):
                        return

                if re.findall(pattern, contents):
                    print_att(u"//{}/{}{} [lastm:'{}' size:{} offset:{} pattern:{}]".format(self.__host,
                                                                                            path,
                                                                                            result.get_longname(),
                                                                                            strftime('%Y-%m-%d %H:%M', localtime(result.get_mtime_epoch())), 
                                                                                            result.get_filesize(),
                                                                                            rfile.tell(),
                                                                                            pattern.pattern))
                    rfile.close()
                    return

        except SessionError as e:
            if 'STATUS_SHARING_VIOLATION' in str(e):
                pass
            if settings.args.verbose: traceback.print_exc()

        except Exception as e:
            print_error(str(e))
            if settings.args.verbose: traceback.print_exc()

    def finish(self):
        print_status("{}:{} Done spidering (Completed in {})".format(self.__host, 
                                                                     settings.args.port, 
                                                                     time() - self.__start_time))