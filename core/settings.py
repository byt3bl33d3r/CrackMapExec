def init_args(arg_namespace):
    """
    This is just so we can easily share argparse's namespace
    """

    global args
    args = arg_namespace

    global gfails
    gfails = 0