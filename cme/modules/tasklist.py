from impacket.dcerpc.v5 import tsts as TSTS


class CMEModule:
    '''
    Display a list of currently running processes on the system.

    Module by snovvcrash (@snovvcrash), based on tstool.py by Alexander Korznikov (@nopernik)
    '''
    name = 'tasklist'
    description = 'Displays a list of currently running processes on the system'
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        VERBOSE     Turn verbose output ON.
        '''
        self.context = context
        self.sessions = {}

        self.verbose = None
        if module_options and 'VERBOSE' in module_options:
            self.verbose = True

    def get_session_list(self, connection):
        '''
        Retreive session list.
        '''
        with TSTS.TermSrvEnumeration(connection.conn, connection.host) as tse:
            handle = tse.hRpcOpenEnum()
            rsessions = tse.hRpcGetEnumResult(handle, Level=1)['ppSessionEnumResult']
            tse.hRpcCloseEnum(handle)

            for i in rsessions:
                sess = i['SessionInfo']['SessionEnum_Level1']
                state = TSTS.enum2value(TSTS.WINSTATIONSTATECLASS, sess['State']).split('_')[-1]
                self.sessions[sess['SessionId']] = {
                    'state': state,
                    'SessionName': sess['Name'],
                    'RemoteIp': '',
                    'ClientName': '',
                    'Username': '',
                    'Domain': '',
                    'Resolution': '',
                    'ClientTimeZone': ''
                }
    
    def enumerate_sessions_config(self, connection):
        '''
        Get session config one by one.
        '''
        if len(self.sessions):
            with TSTS.RCMPublic(connection.conn, connection.host) as rcmp:
                for SessionId in self.sessions:
                    resp = rcmp.hRpcGetClientData(SessionId)
                    if resp is not None:
                        self.sessions[SessionId]['RemoteIp'] = resp['ppBuff']['ClientAddress']
                        self.sessions[SessionId]['ClientName'] = resp['ppBuff']['ClientName']

                        if len(resp['ppBuff']['UserName']) and not len(self.sessions[SessionId]['Username']):
                            self.sessions[SessionId]['Username'] = resp['ppBuff']['UserName']

                        if len(resp['ppBuff']['Domain']) and not len(self.sessions[SessionId]['Domain']):
                            self.sessions[SessionId]['Domain'] = resp['ppBuff']['Domain']

                        self.sessions[SessionId]['Resolution'] = '{}x{}'.format(
                            resp['ppBuff']['HRes'],
                            resp['ppBuff']['VRes']
                        )

                        self.sessions[SessionId]['ClientTimeZone'] = resp['ppBuff']['ClientTimeZone']['StandardName']

    def on_login(self, context, connection):
        '''
        Display a list of currently running processes on the system.
        '''
        with TSTS.LegacyAPI(connection.conn, connection.host) as lapi:
            handle = lapi.hRpcWinStationOpenServer()

            r = lapi.hRpcWinStationGetAllProcesses(handle)
            if not len(r):
                return None

            maxImageNameLen = max([len(i['ImageName']) for i in r])
            maxSidLen = max([len(i['pSid']) for i in r])

            if self.verbose:
                self.get_session_list(connection)
                self.enumerate_sessions_config(connection)

                maxUserNameLen = max([len(self.sessions[i]['Username'] + self.sessions[i]['Domain']) + 1 for i in self.sessions]) + 1
                if maxUserNameLen < 11:
                    maxUserNameLen = 11

                template = (
                    '{imagename: <%d} '
                    '{pid: <6} '
                    '{sessid: <6} '
                    '{sessionName: <16} '
                    '{sessstate: <11} '
                    '{sessionuser: <%d} '
                    '{sid: <%d} '
                    '{workingset: <12}'
                ) % (maxImageNameLen, maxUserNameLen, maxSidLen)
                           
                context.log.highlight(template.format(
                        imagename='Image Name',
                        pid='PID',
                        sessionName='SessName',
                        sessid='SessID',
                        sessionuser='SessUser',
                        sessstate='State',
                        sid='SID',
                        workingset='Mem Usage'
                    )
                )
                
                context.log.highlight(template.replace(' <', '=<').format(
                        imagename='',
                        pid='',
                        sessionName='',
                        sessid='',
                        sessionuser='',
                        sessstate='',
                        sid='',
                        workingset=''
                    )
                )

                for procInfo in r:
                    sessId = procInfo['SessionId']
                    fullUserName = ''

                    if len(self.sessions[sessId]['Domain']):
                        fullUserName += self.sessions[sessId]['Domain'] + '\\'

                    if len(self.sessions[sessId]['Username']):
                        fullUserName += self.sessions[sessId]['Username']

                    row = template.replace('{workingset: <12}', '{workingset: >10,} K').format(
                        imagename=procInfo['ImageName'],
                        pid=procInfo['UniqueProcessId'],
                        sessionName=self.sessions[sessId]['SessionName'],
                        sessid=procInfo['SessionId'],
                        sessstate=self.sessions[sessId]['state'].replace('Disconnected', 'Disc'),
                        sid=procInfo['pSid'],
                        sessionuser=fullUserName,
                        workingset=procInfo['WorkingSetSize'] // 1000
                    )

                    context.log.highlight(row)
            else:
                template = '{: <%d} {: <8} {: <11} {: <%d} {: >12}' % (maxImageNameLen, maxSidLen)
                context.log.highlight(template.format('Image Name', 'PID', 'Session#', 'SID', 'Mem Usage'))
                context.log.highlight(template.replace(': ', ':=').format('', '', '', '', ''))

                for procInfo in r:
                    row = template.format(
                        procInfo['ImageName'],
                        procInfo['UniqueProcessId'],
                        procInfo['SessionId'],
                        procInfo['pSid'],
                        '{:,} K'.format(procInfo['WorkingSetSize'] // 1000),
                    )

                    context.log.highlight(row)
