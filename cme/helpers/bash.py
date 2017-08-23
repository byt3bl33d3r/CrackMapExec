import os
import cme

def get_script(path):
    with open(os.path.join(os.path.dirname(cme.__file__), 'data', path), 'r') as script:
        return script.read()
