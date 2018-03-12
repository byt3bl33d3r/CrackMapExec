import cme
import os
import re
import zlib
import base64


def get_ps_script(path):
    return os.path.join(os.path.dirname(cme.__file__), 'data', path)


def ps_decode_and_inflate(command):
    """
    https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
    """
    decoded_data = base64.b64decode(command)
    return zlib.decompress(decoded_data, -15)


def ps_deflate_and_encode(command):
    """
    https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
    """
    zlibbed_str = zlib.compress(command)
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode(compressed_string)


def encode_ps_command(command):
    return base64.b64encode(command.encode('UTF-16LE'))


def strip_ps_code(code):
    """
    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a PowerShell source file.
    """

    # strip block comments
    strippedCode = re.sub(re.compile('<#.*?#>', re.DOTALL), '', code)
    # strip blank lines, lines starting with #, and verbose/debug statements
    strippedCode = "\n".join([
        line for line in strippedCode.split('\n') if ((line.strip() != '') and (not line.strip().startswith("#")) and (not line.strip().lower().startswith("write-verbose ")) and (not line.strip().lower().startswith("write-debug ")))
    ])

    return strippedCode


def obfs_ps_script(path_to_script):
    with open(get_ps_script(path_to_script), 'r') as script:
        return strip_ps_code(script.read())
