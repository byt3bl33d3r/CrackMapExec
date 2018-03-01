from gevent import monkey
import sys
import os
import cme

monkey.patch_all()

thirdparty_modules = os.path.join(os.path.dirname(cme.__file__), 'thirdparty')

for module in os.listdir(thirdparty_modules):
    sys.path.insert(0, os.path.join(thirdparty_modules, module))
