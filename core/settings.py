def init_args(arg_namespace):
    """
    args will contain a namespace that we can modify whenever we want
    orig_args will contain the original namespace (duh!) and should never be modified
    """ 
    global orig_args
    orig_args = arg_namespace
    
    global args
    args = arg_namespace