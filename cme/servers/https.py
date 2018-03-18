from flask import Flask
from cme.helpers.misc import KThread


app = Flask(__name__)

thread = KThread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 443, 'threaded': True, 'ssl_context': 'adhoc'})
thread.daemon = True
thread.start()
