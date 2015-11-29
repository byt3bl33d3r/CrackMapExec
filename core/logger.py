import logging
import sys
import re
import os
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

def setup_logger(target, level=logging.INFO):

    formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%m-%d-%Y %H:%M:%S")
    if not os.path.exists('./logs/'):
        os.makedirs('./logs/')
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

    #A logger on crack? keeps getting better
    crack_logger = logging.getLogger('crack')
    crack_logger.propagate = False
    crack_logger.addHandler(streamHandler)
    crack_logger.addHandler(fileHandler)
    crack_logger.setLevel(level)

def print_error(message):
    clog = logging.getLogger('crack')
    clog.info(colored("[-] ", 'red', attrs=['bold']) + message)

def print_status(message):
    clog = logging.getLogger('crack')
    clog.info(colored("[*] ", 'blue', attrs=['bold']) + message)

def print_succ(message):
    clog = logging.getLogger('crack')
    clog.info(colored("[+] ", 'green', attrs=['bold']) + message)

def print_att(message):
    clog = logging.getLogger('crack')
    clog.info(colored(message, 'yellow', attrs=['bold']))

def print_message(message):
    clog = logging.getLogger('crack')
    clog.info(message)

def yellow(text):
    return colored(text, 'yellow', attrs=['bold'])

def green(text):
    return colored(text, 'green', attrs=['bold'])

def blue(text):
    return colored(text, 'blue', attrs=['bold'])

def red(text):
    return colored(text, 'red', attrs=['bold'])

def shutdown(exit_code):
    print_status("KTHXBYE")
    sys.exit(int(exit_code))

def root_error():
    print colored("[-] ", 'red', attrs=['bold']) + "I needz r00t!"
    sys.exit(1)
