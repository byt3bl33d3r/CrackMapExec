import os
import random
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
