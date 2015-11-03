import logging
import sys
import re
from termcolor import colored
from datetime import datetime

ansi_escape = re.compile(r'\x1b[^m]*m')

def antiansi_emit(self, record):

    if self.stream is None:
        self.stream = self._open()

    record.msg = ansi_escape.sub('', record.message)
    logging.StreamHandler.emit(self, record)

logging.FileHandler.emit = antiansi_emit

def setup_logger(target, level=logging.INFO):

    formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%m-%d-%Y %H:%M:%S")

    fileHandler = logging.FileHandler('./logs/{}_{}.log'.format(target.replace('/', '_'), datetime.now().strftime('%Y-%m-%d')))
    fileHandler.setFormatter(formatter)

    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.propagate = False
    root_logger.addHandler(streamHandler)
    root_logger.addHandler(fileHandler)
    root_logger.setLevel(level)

def print_error(message):
    logging.info(colored("[-] ", 'red', attrs=['bold']) + message)

def print_status(message):
    logging.info(colored("[*] ", 'blue', attrs=['bold']) + message)

def print_succ(message):
    logging.info(colored("[+] ", 'green', attrs=['bold']) + message)

def print_att(message):
    logging.info(colored(message, 'yellow', attrs=['bold']))

def yellow(text):
    return colored(text, 'yellow', attrs=['bold'])

def green(text):
    return colored(text, 'green', attrs=['bold'])

def red(text):
    return colored(text, 'red', attrs=['bold'])
