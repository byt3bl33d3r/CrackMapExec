from random import sample
from string import ascii_lowercase

def init_args(arg_namespace):
    """
    This is just so we can easily share argparse's namespace
    """

    global args
    args = arg_namespace

    global gfails
    gfails = 0

    global obfs_func_name
    obfs_func_name = ''.join(sample(ascii_lowercase, 10))