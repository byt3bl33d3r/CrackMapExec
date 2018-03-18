import logging
from gevent import sleep
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from cme.helpers.misc import gen_random_string


class ATEXEC(object):
    def __init__(self, target, username, password, domain, lmhash, nthash, connection=None):
        self.connection = connection
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = None
        self.doKerberos = False

        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % self.target
        self.rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(self.rpctransport, 'setRemoteHost'):
            self.rpctransport.setRemoteHost(self.target)
        if hasattr(self.rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            self.rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
        #rpctransport.set_kerberos(self.doKerberos, self.kdcHost)

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
