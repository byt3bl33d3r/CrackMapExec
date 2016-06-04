from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from cme.helpers import gen_random_string
from gevent import sleep

class TSCH_EXEC:
    def __init__(self, target, username, password, domain, hashes=None):
        self.__target = target
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__outputBuffer = ''
        self.__retOutput = False
        #self.__aesKey = aesKey
        #self.__doKerberos = doKerberos

        if hashes is not None:
        #This checks to see if we didn't provide the LM Hash
            if hashes.find(':') != -1:
                self.__lmhash, self.__nthash = hashes.split(':')
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ''

        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % self.__target
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(self.__rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            self.__rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            #rpctransport.set_kerberos(self.__doKerberos)

    def execute(self, command, output=False):
        self.__retOutput = output
        self.doStuff(command)
        return self.__outputBuffer

    def doStuff(self, command):
        
        def output_callback(data):
            self.__outputBuffer = data

        dce = self.__rpctransport.get_dce_rpc()

        dce.set_credentials(*self.__rpctransport.get_credentials())
        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        tmpName = gen_random_string(8)

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
"""
        if self.__retOutput:
            tmpFileName = tmpName + '.tmp'
            xml+= """      <Arguments>/C {} &gt; %windir%\\Temp\\{} 2&gt;&amp;1</Arguments>
    </Exec>
  </Actions>
</Task>
        """.format(command, tmpFileName)
        
        elif self.__retOutput is False:
            xml+= """      <Arguments>/C {}</Arguments>
    </Exec>
  </Actions>
</Task>
        """.format(command)

        #logging.info("Task XML: {}".format(xml))
        taskCreated = False
        #logging.info('Creating task \\%s' % tmpName)
        tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        taskCreated = True

        #logging.info('Running task \\%s' % tmpName)
        tsch.hSchRpcRun(dce, '\\%s' % tmpName)

        done = False
        while not done:
            #logging.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
            resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
            if resp['pLastRuntime']['wYear'] != 0:
                done = True
            else:
                sleep(2)

        #logging.info('Deleting task \\%s' % tmpName)
        tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
        taskCreated = False

        if taskCreated is True:
            tsch.hSchRpcDelete(dce, '\\%s' % tmpName)

        peer = ':'.join(map(str, self.__rpctransport.get_socket().getpeername()))
        #self.__logger.success('Executed command via ATEXEC')

        if self.__retOutput:
            smbConnection = self.__rpctransport.get_smb_connection()
            while True:
                try:
                    #logging.info('Attempting to read ADMIN$\\Temp\\%s' % tmpFileName)
                    smbConnection.getFile('ADMIN$', 'Temp\\%s' % tmpFileName, output_callback)
                    break
                except Exception as e:
                    if str(e).find('SHARING') > 0:
                        sleep(3)
                    elif str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                        sleep(3)
                    else:
                        raise
            #logging.debug('Deleting file ADMIN$\\Temp\\%s' % tmpFileName)
            smbConnection.deleteFile('ADMIN$', 'Temp\\%s' % tmpFileName)
        else:
            pass
            #logging.info('Output retrieval disabled')

        dce.disconnect()