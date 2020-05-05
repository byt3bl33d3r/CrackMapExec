import random
import string
import re
import inspect
import os


def identify_target_file(target_file):
    with open(target_file, 'r') as target_file_handle:
        for i, line in enumerate(target_file_handle):
            if i == 1:
                if line.startswith('<NessusClientData'):
                    return 'nessus'
                elif line.endswith('nmaprun>\n'):
                    return 'nmap'

    return 'unknown'


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
        if stack[3] == 'plaintext_login' or stack[3] == 'hash_login' or stack[3] == 'kerberos_login':
            return True
        if stack[3] == 'call_cmd_args':
            return True
    return False


# Stolen from https://github.com/pydanny/whichcraft/
def which(cmd, mode=os.F_OK | os.X_OK, path=None):
    """Given a command, mode, and a PATH string, return the path which
    conforms to the given mode on the PATH, or None if there is no such
    file.
    `mode` defaults to os.F_OK | os.X_OK. `path` defaults to the result
    of os.environ.get("PATH"), or can be overridden with a custom search
    path.
    Note: This function was backported from the Python 3 source code.
    """
    # Check that a given file can be accessed with the correct mode.
    # Additionally check that `file` is not a directory, as on Windows
    # directories pass the os.access check.
    def _access_check(fn, mode):
        return (os.path.exists(fn) and os.access(fn, mode) and
                not os.path.isdir(fn))

    # If we're given a path with a directory part, look it up directly
    # rather than referring to PATH directories. This includes checking
    # relative to the current directory, e.g. ./script
    if os.path.dirname(cmd):
        if _access_check(cmd, mode):
            return cmd
        return None

    if path is None:
        path = os.environ.get("PATH", os.defpath)
    if not path:
        return None
    path = path.split(os.pathsep)

    files = [cmd]

    seen = set()
    for dir in path:
        normdir = os.path.normcase(dir)
        if normdir not in seen:
            seen.add(normdir)
            for thefile in files:
                name = os.path.join(dir, thefile)
                if _access_check(name, mode):
                    return name
    return None
