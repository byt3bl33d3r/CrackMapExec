import threading
import logging
import sys
import os
from impacket import smbserver

class CMESMBServer(threading.Thread):

    def __init__(self, logger, share_name, verbose=False):

        try:
            threading.Thread.__init__(self)

            self.server = smbserver.SimpleSMBServer()
            self.server.addShare(share_name.upper(), os.path.join('/tmp', 'cme_hosted'))
            if verbose: self.server.setLogFile('')
            self.server.setSMB2Support(False)
            self.server.setSMBChallenge('')

        except Exception as e:
            errno, message = e.args
            if errno == 98 and message == 'Address already in use':
                logger.error('Error starting SMB server: the port is already in use')
            else:
                logger.error('Error starting SMB server: {}'.format(message))

            sys.exit(1)

    def run(self):
        try:
            self.server.start()
        except:
            pass

    def shutdown(self):
        #try:
        #    while len(self.server.hosts) > 0:
        #        self.server.log.info('Waiting on {} host(s)'.format(highlight(len(self.server.hosts))))
        #        sleep(15)
        #except KeyboardInterrupt:
        #    pass

        self._Thread__stop()
        # make sure all the threads are killed
        for thread in threading.enumerate():
            if thread.isAlive():
                try:
                    thread._Thread__stop()
                except:
                    pass
