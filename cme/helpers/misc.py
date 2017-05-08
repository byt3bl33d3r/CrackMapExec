import random
import string
import re
import inspect

def gen_random_string(length=10):
	return ''.join(random.sample(string.ascii_letters, int(length)))

def validate_ntlm(data):
    allowed = re.compile("^[0-9a-f]{32}", re.IGNORECASE)
    if allowed.match(data):
        return True
    else:
        return False

def called_from_cmd_args():
    for stack in inspect.stack():
        if stack[3] == 'print_host_info':
            return True
        if stack[3] == 'plaintext_login' or stack[3] == 'hash_login':
            return True
        if stack[3] == 'call_cmd_args':
            return True
    return False
