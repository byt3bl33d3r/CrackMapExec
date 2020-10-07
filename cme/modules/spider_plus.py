import json
import errno
import os
import time
import logging
import traceback
from cme.protocols.smb.remotefile import RemoteFile
from impacket import smb
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError


CHUNK_SIZE = 4096

suffixes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB']
def humansize(nbytes):
    i = 0
    while nbytes >= 1024 and i < len(suffixes)-1:
        nbytes /= 1024.
        i += 1
    f = ('%.2f' % nbytes).rstrip('0').rstrip('.')
    return '%s %s' % (f, suffixes[i])

def humaclock(time):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time))

def make_dirs(path):
    """
    Create the directory structure. We handle an exception `os.errno.EEXIST` that
    may occured while the OS is creating the directories.
    """

    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

        pass

get_list_from_option = lambda opt: list(map(lambda o: o.lower(), filter(bool, opt.split(','))))


class SMBSpiderPlus:

    def __init__(self, smb, logger, read_only, exclude_dirs, exclude_exts, max_file_size, output_folder):
        self.smb = smb
        self.host = self.smb.conn.getRemoteHost()
        self.conn_retry = 5
        self.logger = logger
        self.results = {}

        self.read_only = read_only
        self.exclude_dirs = exclude_dirs
        self.exclude_exts = exclude_exts
        self.max_file_size = max_file_size
        self.output_folder = output_folder

        # Make sure the output_folder exists
        make_dirs(self.output_folder)

    def reconnect(self):
        if self.conn_retry > 0:
            self.conn_retry -= 1
            self.logger.info(f"Reconnect to server {self.conn_retry}")

            # Renogociate the session
            time.sleep(3)
            self.smb.create_conn_obj()
            self.smb.login()
            return True

        return False

    def list_path(self, share, subfolder):
        filelist = []
        try:
            # Get file list for the current folder
            filelist = self.smb.conn.listPath(share, subfolder + '*')

        except SessionError as e:
            self.logger.debug(f'Failed listing files on share "{share}" in directory {subfolder}.')
            self.logger.debug(str(e))

            if 'STATUS_ACCESS_DENIED' in str(e):
                self.logger.debug(f"Cannot list files in directory \"{subfolder}\"")

            elif 'STATUS_OBJECT_PATH_NOT_FOUND' in str(e):
                self.logger.debug(f"The directory {subfolder} does not exist.")

            elif self.reconnect():
                filelist = self.list_path(share, subfolder)

        return filelist

    def get_remote_file(self, share, path):
        try:
            remote_file = RemoteFile(self.smb.conn, path, share, access=FILE_READ_DATA)
            return remote_file
        except SessionError:
            if self.reconnect():
                return self.get_remote_file(share, path)

            return None

    def read_chunk(self, remote_file, chunk_size=CHUNK_SIZE):
        """
        Read the next chunk of data from the remote file.
        We retry 3 times if there is a SessionError that is not a `STATUS_END_OF_FILE`.
        """

        chunk = ''
        retry = 3

        while retry > 0:
            retry -= 1
            try:
                chunk = remote_file.read(chunk_size)
                break

            except SessionError:
                if self.reconnect():
                    # Little hack to reset the smb connection instance
                    remote_file.__smbConnection = self.smb.conn
                    return self.read_chunk(remote_file)

            except Exception:
                traceback.print_exc()
                break

        return chunk

    def spider(self):
        self.logger.debug("Enumerating shares for spidering")
        shares = self.smb.shares()

        try:
            # Get all available shares for the SMB connection
            for share in shares:
                perms = share['access']
                name = share['name']

                self.logger.debug(f"Share \"{name}\" has perms {perms}")

                # We only want to spider readable shares
                if not 'READ' in perms:
                    continue

                # `exclude_dirs` is applied to the shares name
                if name.lower() in self.exclude_dirs:
                    self.logger.debug(f"Share \"{name}\" has been excluded.")
                    continue

                try:
                    # Start the spider at the root of the share folder
                    self.results[name] = {}
                    self._spider(name, '')
                except SessionError:
                    traceback.print_exc()
                    self.logger.error(f"Got a session error while spidering")
                    self.reconnect()

        except Exception as e:
            traceback.print_exc()
            self.logger.error(f"Error enumerating shares: {str(e)}")

        # Save the server shares metadatas if we want to grep on filenames
        self.dump_folder_metadata(self.results)

        return self.results

    def _spider(self, share, subfolder):
        self.logger.debug(f'Spider share "{share}" on folder "{subfolder}"')

        filelist = self.list_path(share, subfolder + '*')
        if share.lower() in self.exclude_dirs:
            self.logger.debug(f'The directory has been excluded')
            return

        # For each entry:
        # - It's a directory then we spider it (skipping `.` and `..`)
        # - It's a file then we apply the checks
        for result in filelist:
            next_path = subfolder + result.get_longname()
            next_path_lower = next_path.lower()
            self.logger.debug(f'Current file on share "{share}": {next_path}')

            # Exclude the current result if it's in the exlude_dirs list
            if any(map(lambda d: d in next_path_lower, self.exclude_dirs)):
                self.logger.debug(f'The path "{next_path}" has been excluded')
                continue

            if result.is_directory():
                if result.get_longname() in ['.', '..']:
                    continue
                self._spider(share, next_path + '/')

            else:
                # Record the file metadata
                self.results[share][next_path] = {
                    'size': humansize(result.get_filesize()),
                    #'ctime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.get_ctime())),
                    'ctime_epoch': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.get_ctime_epoch())),
                    #'mtime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.get_mtime())),
                    'mtime_epoch': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.get_mtime_epoch())),
                    #'atime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.get_atime())),
                    'atime_epoch': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.get_atime_epoch()))
                }

                # The collection logic is here. You can add more checks based
                # on the file size, content, name, date...

                # Check the file extension. We check here to prevent the creation
                # of a RemoteFile object that perform a remote connection.
                file_extension = next_path[next_path.rfind('.')+1:]
                if file_extension in self.exclude_exts:
                    self.logger.debug(f'The file "{next_path}" has an excluded extension')
                    continue

                # If there is not results in the file but the size is correct,
                # then we save it
                if result.get_filesize() > self.max_file_size:
                    self.logger.debug(f'File {result.get_longname()} has size {result.get_filesize()}')
                    continue

                ## You can add more checks here: date, ...
                if self.read_only == True:
                    continue

                # The file passes the checks, then we fetch it!
                remote_file = self.get_remote_file(share, next_path)

                if not remote_file:
                    self.logger.error(f'Cannot open remote file "{next_path}".')
                    continue

                try:
                    remote_file.open()

                    ## TODO: add checks on the file content here
                    self.save_file(remote_file)

                    remote_file.close()

                except SessionError as e:
                    if 'STATUS_SHARING_VIOLATION' in str(e):
                        pass
                except Exception as e:
                    traceback.print_exc()
                    self.logger.error(f'Error reading file {next_path}: {str(e)}')

    def save_file(self, remote_file):
        # Reset the remote_file to point to the begining of the file
        remote_file.seek(0, 0)

        # remove the "\\" before the remote host part
        file_path = str(remote_file)[2:]
        # The remote_file.file_name contains '/'
        file_path = file_path.replace('/', os.path.sep)
        file_path = file_path.replace('\\', os.path.sep)
        filename = file_path.split(os.path.sep)[-1]
        directory = os.path.join(self.output_folder, file_path[:-len(filename)])

        # Create the subdirectories based on the share name and file path
        self.logger.debug(f'Create directory "{directory}"')
        make_dirs(directory)

        with open(os.path.join(directory, filename), 'wb') as fd:
            while True:
                chunk = self.read_chunk(remote_file)
                if not chunk:
                    break
                fd.write(chunk)

    def dump_folder_metadata(self, results):
        # Save the remote host shares metadatas to a json file
        # TODO: use the json file as an input to save only the new or modified
        # files since the last time.
        path = os.path.join(self.output_folder, f'{self.host}.json')
        with open(path, 'w', encoding='utf-8') as fd:
            fd.write(json.dumps(results, indent=4, sort_keys=True))


class CMEModule:
    '''
        Spider plus module
        Module by @vincd
    '''

    name = 'spider_plus'
    description = 'List files on the target server (excluding `DIR` directories and `EXT` extensions) and save them to the `OUTPUT` directory if they are smaller then `SIZE`'
    supported_protocols = ['smb']
    opsec_safe= True # Does the module touch disk?
    multiple_hosts = True # Does it make sense to run this module on multiple hosts at a time?

    def options(self, context, module_options):

        """
            READ_ONLY           Only list files and put the name into a JSON (default: True)
            EXCLUDE_EXTS        Extension file to exclude (Default: ico,lnk)
            EXCLUDE_DIR         Directory to exclude (Default: print$)
            MAX_FILE_SIZE       Max file size allowed to dump (Default: 51200)
            OUTPUT_FOLDER       Path of the remote folder where the dump will occur (Default: /tmp/cme_spider_plus)
        """

        self.read_only = module_options.get('READ_ONLY', True)
        self.exclude_exts = get_list_from_option(module_options.get('EXCLUDE_EXTS', 'ico,lnk'))
        self.exlude_dirs = get_list_from_option(module_options.get('EXCLUDE_DIR', 'print$'))
        self.max_file_size = int(module_options.get('SIZE', 50 * 1024))
        self.output_folder = module_options.get('OUTPUT', os.path.join('/tmp', 'cme_spider_plus'))

    def on_login(self, context, connection):

        context.log.info('Started spidering plus with option:')
        context.log.info('       DIR: {dir}'.format(dir=self.exlude_dirs))
        context.log.info('       EXT: {ext}'.format(ext=self.exclude_exts))
        context.log.info('      SIZE: {size}'.format(size=self.max_file_size))
        context.log.info('    OUTPUT: {output}'.format(output=self.output_folder))

        spider = SMBSpiderPlus(
            connection,
            context.log,
            self.read_only,
            self.exlude_dirs,
            self.exclude_exts,
            self.max_file_size,
            self.output_folder,
        )

        spider.spider()
