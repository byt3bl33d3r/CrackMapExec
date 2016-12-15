import random
import string
import re

def gen_random_string(length=10):
	return ''.join(random.sample(string.ascii_letters, int(length)))

def validate_ntlm(data):
    allowed = re.compile("^[0-9a-f]{32}", re.IGNORECASE)
    if allowed.match(data):
        return True
    else:
        return False
