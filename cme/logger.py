import logging
import sys
import re
from cme.helpers.misc import called_from_cmd_args
from termcolor import colored
from datetime import datetime

#The following hooks the FileHandler.emit function to remove ansi chars before logging to a file
#There must be a better way of doing this, but this way we might save some penguins!

ansi_escape = re.compile(r'\x1b[^m]*m')

def antiansi_emit(self, record):

    if self.stream is None:
        self.stream = self._open()

    record.msg = ansi_escape.sub('', record.message)
    logging.StreamHandler.emit(self, record)

logging.FileHandler.emit = antiansi_emit

####################################################################

class CMEAdapter(logging.LoggerAdapter):

    # For Impacket's TDS library
    message = ''

    def __init__(self, logger_name='CME', extra=None):
        self.logger = logging.getLogger(logger_name)
        self.extra = extra

    def process(self, msg, kwargs):
        if self.extra is None:
            return u'{}'.format(msg), kwargs

        if 'module' in self.extra.keys():
            if len(self.extra['module']) > 8:
                self.extra['module'] = self.extra['module'][:8] + '...'

        #If the logger is being called when hooking the 'options' module function
        if len(self.extra) == 1 and ('module' in self.extra.keys()):
            return u'{:<64} {}'.format(colored(self.extra['module'], 'cyan', attrs=['bold']), msg), kwargs

        #If the logger is being called from CMEServer
        if len(self.extra) == 2 and ('module' in self.extra.keys()) and ('host' in self.extra.keys()):
            return u'{:<24} {:<39} {}'.format(colored(self.extra['module'], 'cyan', attrs=['bold']), self.extra['host'], msg), kwargs

        #If the logger is being called from a protocol
        if 'module' in self.extra.keys():
            module_name = colored(self.extra['module'], 'cyan', attrs=['bold'])
        else:
            module_name = colored(self.extra['protocol'], 'blue', attrs=['bold'])

        return u'{:<24} {:<15} {:<6} {:<16} {}'.format(module_name,
                                                    self.extra['host'],
                                                    self.extra['port'],
                                                    self.extra['hostname'] if self.extra['hostname'] else 'NONE',
                                                    msg), kwargs

    def info(self, msg, *args, **kwargs):
        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass

        msg, kwargs = self.process(u'{} {}'.format(colored("[*]", 'blue', attrs=['bold']), msg), kwargs)
        self.logger.info(msg, *args, **kwargs)

    def error(self, msg, color='red', *args, **kwargs):
        msg, kwargs = self.process(u'{} {}'.format(colored("[-]", color, attrs=['bold']), msg), kwargs)
        self.logger.error(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        pass

    def success(self, msg, *args, **kwargs):
        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass

        msg, kwargs = self.process(u'{} {}'.format(colored("[+]", 'green', attrs=['bold']), msg), kwargs)
        self.logger.info(msg, *args, **kwargs)

    def highlight(self, msg, *args, **kwargs):
        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass

        msg, kwargs = self.process(u'{}'.format(colored(msg, 'yellow', attrs=['bold'])), kwargs)
        self.logger.info(msg, *args, **kwargs)

    # For Impacket's TDS library
    def logMessage(self,message):
        CMEAdapter.message += message.strip().replace('NULL', '') + '\n'

    def getMessage(self):
        out = CMEAdapter.message
        CMEAdapter.message = ''
        return out

def setup_debug_logger():
    debug_output_string = "{} %(message)s".format(colored('DEBUG', 'magenta', attrs=['bold']))
    formatter = logging.Formatter(debug_output_string)
    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.propagate = False
    root_logger.addHandler(streamHandler)
    #root_logger.addHandler(fileHandler)
    root_logger.setLevel(logging.DEBUG)
    return root_logger

def setup_logger(level=logging.INFO, log_to_file=False, log_prefix=None, logger_name='CME'):

    formatter = logging.Formatter("%(message)s")

    if log_to_file:
        if not log_prefix:
            log_prefix = 'log'

        log_filename = '{}_{}.log'.format(log_prefix.replace('/', '_'), datetime.now().strftime('%Y-%m-%d'))
        fileHandler = logging.FileHandler('./logs/{}'.format(log_filename))
        fileHandler.setFormatter(formatter)

    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)

    cme_logger = logging.getLogger(logger_name)
    cme_logger.propagate = False
    cme_logger.addHandler(streamHandler)

    if log_to_file:
        cme_logger.addHandler(fileHandler)

    cme_logger.setLevel(level)

    return cme_logger
