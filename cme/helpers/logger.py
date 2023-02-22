#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import logging
import re
from termcolor import colored

def write_log(data, log_name):
    logs_dir = os.path.join(os.path.expanduser('~/.cme'), 'logs')
    with open(os.path.join(logs_dir, log_name), 'w') as log_output:
        log_output.write(data)

def highlight(text, color='yellow'):
    if color == 'yellow':
        return u'{}'.format(colored(text, 'yellow', attrs=['bold']))
    elif color == 'red':
        return u'{}'.format(colored(text, 'red', attrs=['bold']))

class AnsiRemoveFormatter(logging.Formatter):
    def format(self, record):
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        record.msg = ansi_escape.sub('', record.msg)
        return super(AnsiRemoveFormatter, self).format(record)