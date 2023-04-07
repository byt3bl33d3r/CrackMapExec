#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
from logging.handlers import RotatingFileHandler
import os.path
import sys
import re
from cme.helpers.misc import called_from_cmd_args
from cme.console import cme_console
from termcolor import colored
from datetime import datetime
from rich.text import Text
from rich.logging import RichHandler


class CMEAdapter(logging.LoggerAdapter):
    def __init__(self, extra=None):
        logging.basicConfig(
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(
                console=cme_console,
                rich_tracebacks=True
            )]
        )
        self.logger = logging.getLogger("cme")
        self.extra = extra
        self.output_file = None

        logging.getLogger("pypykatz").disabled = True
        logging.getLogger("minidump").disabled = True
        logging.getLogger("lsassy").disabled = True

    def format(self, msg, *args, **kwargs):
        """
        Format msg for output if needed
        This is used instead of process() since process() applies to _all_ messages, including debug calls
        """
        if self.extra is None:
            return u'{}'.format(msg), kwargs

        if 'module_name' in self.extra.keys():
            if len(self.extra['module_name']) > 8:
                self.extra['module_name'] = self.extra['module_name'][:8] + '...'

        # If the logger is being called when hooking the 'options' module function
        if len(self.extra) == 1 and ('module_name' in self.extra.keys()):
            return u'{:<64} {}'.format(colored(self.extra['module_name'], 'cyan', attrs=['bold']), msg), kwargs

        # If the logger is being called from CMEServer
        if len(self.extra) == 2 and ('module_name' in self.extra.keys()) and ('host' in self.extra.keys()):
            return u'{:<24} {:<39} {}'.format(colored(self.extra['module_name'], 'cyan', attrs=['bold']), self.extra['host'], msg), kwargs

        # If the logger is being called from a protocol
        if 'module_name' in self.extra.keys():
            module_name = colored(self.extra['module_name'], 'cyan', attrs=['bold'])
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

        msg, kwargs = self.format(u'{} {}'.format(colored("[*]", 'blue', attrs=['bold']), msg), kwargs)
        text = Text.from_ansi(msg)
        cme_console.print(text, *args, **kwargs)
        self.log_console_to_file(text, *args, **kwargs)

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
        self.log_console_to_file(text, *args, **kwargs)

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
        self.log_console_to_file(text, *args, **kwargs)

    def fail(self, msg, *args, **kwargs):
        """
        Prints a failure (may or may not be an error) - e.g. login creds didn't work
        """
        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass
        msg, kwargs = self.format(u'{} {}'.format(colored("[-]", 'red', attrs=['bold']), msg), kwargs)
        text = Text.from_ansi(msg)
        cme_console.print(text, *args, **kwargs)
        self.log_console_to_file(text, *args, **kwargs)

    def log_console_to_file(self, text, *args, **kwargs):
        """
        If debug or info logging is not enabled, we still want display/success/fail logged to the file specified,
        so we create a custom LogRecord and pass it to all the additional handlers (which will be all the file handlers
        """
        if self.logger.getEffectiveLevel() >= logging.INFO:
            # will be 0 if it's just the console output, so only do this if we actually have file loggers
            if len(self.logger.handlers):
                for handler in self.logger.handlers:
                    try:
                        handler.handle(
                            logging.LogRecord(
                                "cme",
                                20,
                                "",
                                kwargs,
                                msg=text,
                                args=args,
                                exc_info=None,
                            )
                        )
                    except Exception as e:
                        self.logger.error(f"Issue while trying to custom print handler: {e}")
        else:
            self.logger.info(text)

    def add_file_log(self, log_file=None):
        file_formatter = TermEscapeCodeFormatter("%(asctime)s - %(levelname)s - %(message)s")
        output_file = self.init_log_file() if log_file is None else log_file
        file_creation = False

        if not os.path.isfile(output_file):
            open(output_file, 'x')
            file_creation = True

        file_handler = RotatingFileHandler(output_file, maxBytes=100000)

        with file_handler._open() as f:
            if file_creation:
                f.write("[%s]> %s\n\n" % (datetime.now().strftime('%d-%m-%Y %H:%M:%S'), " ".join(sys.argv)))
            else:
                f.write("\n[%s]> %s\n\n" % (datetime.now().strftime('%d-%m-%Y %H:%M:%S'), " ".join(sys.argv)))

        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        self.logger.debug(f"Added file handler: {file_handler}")

    @staticmethod
    def init_log_file():
        log_filename = os.path.join(
            os.path.expanduser(
                "~/.cme"
            ),
            "logs",
            f"full-log_{datetime.now().strftime('%Y-%m-%d')}.log"
        )
        return log_filename


class TermEscapeCodeFormatter(logging.Formatter):
    """A class to strip the escape codes from the """
    def __init__(self, fmt=None, datefmt=None, style='%', validate=True):
        super().__init__(fmt, datefmt, style, validate)

    def format(self, record):
        escape_re = re.compile(r'\x1b\[[0-9;]*m')
        record.msg = re.sub(escape_re, "", str(record.msg))
        return super().format(record)


# initialize the logger for all of CME - this is imported everywhere
cme_logger = CMEAdapter()
