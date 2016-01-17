import logging
import sys
import re
from termcolor import colored
from datetime import datetime

if sys.platform == 'win32':
    import colorama
    colorama.init()

ansi_escape = re.compile(r'\x1b[^m]*m')

def antiansi_emit(self, record):

    if self.stream is None:
        self.stream = self._open()

    record.msg = ansi_escape.sub('', record.message)
    logging.StreamHandler.emit(self, record)

logging.FileHandler.emit = antiansi_emit

class CMEAdapter(logging.LoggerAdapter):

    def __init__(self, logger, extra, action=None):
        self.logger = logger
        self.extra = extra
        self.action = action

    def process(self, msg, kwargs):
        return '{} {}:{} {} {}'.format(colored(self.extra['service'], 'blue', attrs=['bold']), 
                                       self.extra['host'],
                                       self.extra['port'],
                                       self.extra['hostname'],
                                       msg), kwargs

    def info(self, msg, *args, **kwargs):
        msg, kwargs = self.process(colored("[*] ", 'blue', attrs=['bold']) + msg, kwargs)
        self.logger.info(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        msg, kwargs = self.process(colored("[-] ", 'red', attrs=['bold']) + msg, kwargs)
        self.logger.info(msg, *args, **kwargs)

    def success(self, msg, *args, **kwargs):
        msg, kwargs = self.process(colored("[+] ", 'green', attrs=['bold']) + msg, kwargs)
        self.logger.info(msg, *args, **kwargs)

    def results(self, msg, *args, **kwargs):
        msg, kwargs = self.process(colored(msg, 'yellow', attrs=['bold']), kwargs)
        self.logger.info(msg, *args, **kwargs)

    def logMessage(self, message):
        self.results(message)

def setup_logger(target, level=logging.INFO):

    formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%m-%d-%Y %H:%M:%S")
    fileHandler = logging.FileHandler('./logs/{}_{}.log'.format(target.replace('/', '_'), datetime.now().strftime('%Y-%m-%d')))
    fileHandler.setFormatter(formatter)

    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)

    if level == logging.DEBUG:
        root_logger = logging.getLogger()
        root_logger.propagate = False
        root_logger.addHandler(streamHandler)
        root_logger.addHandler(fileHandler)
        root_logger.setLevel(level)

    cme_logger = logging.getLogger('CME')
    cme_logger.propagate = False
    cme_logger.addHandler(streamHandler)
    cme_logger.addHandler(fileHandler)
    cme_logger.setLevel(level)

def print_error(message):
    print colored("[-] ", 'red', attrs=['bold']) + message

def print_info(message):
    print colored("[*] ", 'blue', attrs=['bold']) + message

def print_success(message):
    print colored("[+] ", 'green', attrs=['bold']) + message

def print_results(message):
    print colored(message, 'yellow', attrs=['bold'])

def print_message(message):
    print message

def yellow(text):
    return colored(text, 'yellow', attrs=['bold'])

def green(text):
    return colored(text, 'green', attrs=['bold'])

def blue(text):
    return colored(text, 'blue', attrs=['bold'])

def red(text):
    return colored(text, 'red', attrs=['bold'])

def shutdown(exit_code):
    print_info('KTHXBYE!')
    sys.exit(int(exit_code))
