from time import time, strftime, localtime
from cme.remotefile import RemoteFile
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError
import re
import traceback

class SMBSpider:

    def __init__(self, logger, connection, args):
        self.logger = logger
        self.smbconnection = connection.conn
        self.start_time = time()
        self.args = args
        self.logger.info("Started spidering")

    def spider(self, subfolder, depth):
        '''
            Apperently spiders don't like stars *!
            who knew? damn you spiders
        '''

        if subfolder == '' or subfolder == '.':
            subfolder = '*'

        elif subfolder.startswith('*/'):
            subfolder = subfolder[2:] + '/*'

        else:
            subfolder = subfolder.replace('/*/', '/') + '/*'

        try:
            filelist = self.smbconnection.listPath(self.args.share, subfolder)
            self.dir_list(filelist, subfolder)
            if depth == 0:
                return
        except SessionError as e:
            pass

        for result in filelist:
            if result.is_directory() and result.get_longname() != '.' and result.get_longname() != '..':
                if subfolder == '*':
                    self.spider(subfolder.replace('*', '') + result.get_longname(), depth-1)
                elif subfolder != '*' and (subfolder[:-2].split('/')[-1] not in self.args.exclude_dirs):
                    self.spider(subfolder.replace('*', '') + result.get_longname(), depth-1)
        return

    def dir_list(self, files, path):
        path = path.replace('*', '')
        for result in files:
            if self.args.pattern:
                for pattern in self.args.pattern:
                    if result.get_longname().lower().find(pattern.lower()) != -1:
                        if result.is_directory():
                            self.logger.highlight(u"//{}/{}{} [dir]".format(self.args.share, path, result.get_longname()))
                        else:
                            self.logger.highlight(u"//{}/{}{} [lastm:'{}' size:{}]".format(self.args.share,
                                                                                           path,
                                                                                           result.get_longname(),
                                                                                           strftime('%Y-%m-%d %H:%M', localtime(result.get_mtime_epoch())),
                                                                                           result.get_filesize()))

            elif self.args.regex:
                for regex in self.args.regex:
                    if re.findall(regex, result.get_longname()):
                        if result.is_directory():
                            self.logger.highlight(u"//{}/{}{} [dir]".format(self.args.share, path, result.get_longname()))
                        else:
                            self.logger.highlight(u"//{}/{}{} [lastm:'{}' size:{}]".format(self.args.share,
                                                                                           path,
                                                                                           result.get_longname(),
                                                                                           strftime('%Y-%m-%d %H:%M', localtime(result.get_mtime_epoch())),
                                                                                           result.get_filesize()))

            if self.args.search_content:
                if not result.is_directory():
                    self.search_content(path, result)

        return

    def search_content(self, path, result):
        path = path.replace('*', '') 
        try:
            rfile = RemoteFile(self.smbconnection, 
                               path + result.get_longname(), 
                               self.args.share,
                               access = FILE_READ_DATA)
            rfile.open()

            while True:
                try:
                    contents = rfile.read(4096)
                except SessionError as e:
                    if 'STATUS_END_OF_FILE' in str(e):
                        break

                except Exception:
                    traceback.print_exc()
                    break

                if self.args.pattern:
                    for pattern in self.args.pattern:
                        if contents.lower().find(pattern.lower()) != -1:
                            self.logger.highlight(u"//{}/{}{} [lastm:'{}' size:{} offset:{} pattern:'{}']".format(self.args.share,
                                                                                                                path,
                                                                                                                result.get_longname(),
                                                                                                                strftime('%Y-%m-%d %H:%M', localtime(result.get_mtime_epoch())), 
                                                                                                                result.get_filesize(),
                                                                                                                rfile.tell(),
                                                                                                                pattern))

                elif self.args.regex:
                    for regex in self.args.regex:
                        if re.findall(pattern, contents):
                            self.logger.highlight(u"//{}/{}{} [lastm:'{}' size:{} offset:{} regex:'{}']".format(self.args.share,
                                                                                                              path,
                                                                                                              result.get_longname(),
                                                                                                              strftime('%Y-%m-%d %H:%M', localtime(result.get_mtime_epoch())), 
                                                                                                              result.get_filesize(),
                                                                                                              rfile.tell(),
                                                                                                              regex.pattern))
            rfile.close()
            return

        except SessionError as e:
            if 'STATUS_SHARING_VIOLATION' in str(e):
                pass

        except Exception:
            traceback.print_exc()

    def finish(self):
        self.logger.info("Done spidering (Completed in {})".format(time() - self.start_time))