#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os.path
import sys
import re
from cme.helpers.misc import called_from_cmd_args
from cme.console import cme_console
from termcolor import colored
from datetime import datetime
from rich.text import Text
from rich.logging import RichHandler

# The following hooks the FileHandler.emit function to remove ansi chars before logging to a file
# There must be a better way of doing this, but this way we might save some penguins!
ansi_escape = re.compile(r'\x1b[^m]*m')


def antiansi_emit(self, record):

    if self.stream is None:
        self.stream = self._open()

    record.msg = ansi_escape.sub('', record.message)
    logging.StreamHandler.emit(self, record)


logging.FileHandler.emit = antiansi_emit


class CMEAdapter(logging.LoggerAdapter):
    # For Impacket's TDS library
    message = ''

    def __init__(self, logger_name='CME', extra=None):
        logging.basicConfig(
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(
                console=cme_console,
                rich_tracebacks=True
            )]
        )
        self.logger = logging.getLogger("rich")
        self.extra = extra
        self.outputfile = None

    # def process(self, msg, kwargs):
    #     """
    #     Used to process log strings for outputting
    #     """
    #     # print(self.extra)
    #     if self.extra is None:
    #         return u'{}'.format(msg), kwargs
    #
    #     if 'module' in self.extra.keys():
    #         if len(self.extra['module']) > 8:
    #             self.extra['module'] = self.extra['module'][:8] + '...'
    #
    #     # If the logger is being called when hooking the 'options' module function
    #     if len(self.extra) == 1 and ('module' in self.extra.keys()):
    #         return u'{:<64} {}'.format(colored(self.extra['module'], 'cyan', attrs=['bold']), msg), kwargs
    #
    #     # If the logger is being called from CMEServer
    #     if len(self.extra) == 2 and ('module' in self.extra.keys()) and ('host' in self.extra.keys()):
    #         return u'{:<24} {:<39} {}'.format(colored(self.extra['module'], 'cyan', attrs=['bold']), self.extra['host'], msg), kwargs
    #
    #     # If the logger is being called from a protocol
    #     if 'module' in self.extra.keys():
    #         module_name = colored(self.extra['module'], 'cyan', attrs=['bold'])
    #     else:
    #         module_name = colored(self.extra['protocol'], 'blue', attrs=['bold'])
    #     return u'{:<24} {:<15} {:<6} {:<16} {}'.format(
    #         module_name,
    #         self.extra['host'],
    #         self.extra['port'],
    #         self.extra['hostname'] if self.extra['hostname'] else 'NONE',
    #         msg), kwargs

    def format(self, msg, *args, **kwargs):
        """
        Format msg for output if needed
        This is used instead of process() since process() applies to _all_ messages, including debug calls
        """
        if self.extra is None:
            return u'{}'.format(msg), kwargs

        if 'module' in self.extra.keys():
            if len(self.extra['module']) > 8:
                self.extra['module'] = self.extra['module'][:8] + '...'

        # If the logger is being called when hooking the 'options' module function
        if len(self.extra) == 1 and ('module' in self.extra.keys()):
            return u'{:<64} {}'.format(colored(self.extra['module'], 'cyan', attrs=['bold']), msg), kwargs

        # If the logger is being called from CMEServer
        if len(self.extra) == 2 and ('module' in self.extra.keys()) and ('host' in self.extra.keys()):
            return u'{:<24} {:<39} {}'.format(colored(self.extra['module'], 'cyan', attrs=['bold']), self.extra['host'], msg), kwargs

        # If the logger is being called from a protocol
        if 'module' in self.extra.keys():
            module_name = colored(self.extra['module'], 'cyan', attrs=['bold'])
        else:
            module_name = colored(self.extra['protocol'], 'blue', attrs=['bold'])

        return '{:<24} {:<15} {:<6} {:<16} {}'.format(
            module_name,
            self.extra['host'],
            self.extra['port'],
            self.extra['hostname'] if self.extra['hostname'] else 'NONE',
            msg), kwargs

    def display(self, msg, *args, **kwargs):
        """
        Display text to console, formatted for CME
        """
        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass

        # msg = u'{} {}'.format(colored("[*]", 'blue', attrs=['bold']), msg)
        msg, kwargs = self.format(u'{} {}'.format(colored("[*]", 'blue', attrs=['bold']), msg), kwargs)
        text = Text.from_ansi(msg)
        cme_console.print(text, *args, **kwargs)

    # def error(self, msg, color='red', *args, **kwargs):
    #     """
    #     Print error log
    #     """
    #     msg, kwargs = self.format(u'{} {}'.format(colored("[-]", color, attrs=['bold']), msg), kwargs)
    #     text = Text.from_ansi(msg)
    #     self.logger.error(text, *args, **kwargs)

    # def debug(self, msg, color='blue', *args, **kwargs):
    #     """
    #     Print debug log (viewable via --verbose)
    #     """
    #     return super()._log(logging.DEBUG, msg, args, **kwargs)

    def success(self, msg, *args, **kwargs):
        """
        Print some sort of success to the user
        """
        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass

        msg, kwargs = self.format(u'{} {}'.format(colored("[+]", 'green', attrs=['bold']), msg), kwargs)
        text = Text.from_ansi(msg)
        cme_console.print(text, *args, **kwargs)

    def highlight(self, msg, *args, **kwargs):
        """
        Prints a completely yellow highlighted message to the user
        """
        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass

        msg, kwargs = self.format(u'{}'.format(colored(msg, 'yellow', attrs=['bold'])), kwargs)
        text = Text.from_ansi(msg)
        cme_console.print(text, *args, **kwargs)

    # For Impacket's TDS library
    def logMessage(self, message):
        CMEAdapter.message += message.strip().replace('NULL', '') + '\n'

    def getMessage(self):
        out = CMEAdapter.message
        CMEAdapter.message = ''
        return out
    
    def setup_logfile(self, log_file=None):
        formatter = logging.Formatter("%(message)s")
        self.outputfile = init_log_file() if log_file == None else log_file
        file_creation = False
        if not os.path.isfile(self.outputfile):
            open(self.outputfile, 'x')
            file_creation = True
        file_handler = logging.FileHandler(filename=self.outputfile, mode="a")
        with file_handler._open() as f:
            if file_creation:
                f.write("[%s]> %s\n\n" % (datetime.now().strftime('%d-%m-%Y %H:%M:%S'), " ".join(sys.argv)))
            else:
                f.write("\n[%s]> %s\n\n" % (datetime.now().strftime('%d-%m-%Y %H:%M:%S'), " ".join(sys.argv)))
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)


# def setup_debug_logger():
#     debug_output_string = "{} %(message)s".format(colored('DEBUG', 'magenta', attrs=['bold']))
#     formatter = logging.Formatter(debug_output_string)
#     streamHandler = logging.StreamHandler(sys.stdout)
#     streamHandler.setFormatter(formatter)
#
#     root_logger = logging.getLogger()
#     root_logger.handlers = []
#     root_logger.addHandler(streamHandler)
#     root_logger.setLevel(logging.DEBUG)
#     return root_logger
#
#
# def setup_logger(level=logging.INFO, logger_name='CME'):
#     formatter = logging.Formatter("%(message)s")
#
#     streamHandler = logging.StreamHandler(sys.stdout)
#     streamHandler.setFormatter(formatter)
#
#     cme_logger = logging.getLogger(logger_name)
#     cme_logger.propagate = False
#     cme_logger.addHandler(streamHandler)
#     cme_logger.setLevel(level)
#
#     return cme_logger

def init_log_file():
    log_filename = os.path.join(os.path.expanduser('~/.cme'), 'logs', 'full-log_{}.log'.format(datetime.now().strftime('%Y-%m-%d')))
    return log_filename


cme_logger = CMEAdapter()
