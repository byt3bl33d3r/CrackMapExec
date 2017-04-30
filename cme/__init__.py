from gevent import monkey
monkey.patch_all()

import sys
import os
import cme

sys.path.insert(0, os.path.join(os.path.dirname(cme.__file__), 'thirdparty', 'pywerview'))
sys.path.insert(0, os.path.join(os.path.dirname(cme.__file__), 'thirdparty', 'impacket'))