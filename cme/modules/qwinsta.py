from impacket.dcerpc.v5 import tsts as TSTS


class CMEModule:
    '''
    Display information about Remote Desktop Services sessions.

    Module by snovvcrash (@snovvcrash), based on tstool.py by Alexander Korznikov (@nopernik)
    '''
    name = 'qwinsta'
    description = 'Displays information about Remote Desktop Services sessions'
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
                    'Domain':'',
                    'Resolution': '',
                    'ClientTimeZone': ''
                }

    def enumerate_sessions_info(self, connection):
        '''
        Get session info one by one.
        '''
        if len(self.sessions):
            with TSTS.TermSrvSession(connection.conn, connection.host) as tss:
                for SessionId in self.sessions.keys():
                    sessdata = tss.hRpcGetSessionInformationEx(SessionId)
                    sessflags = TSTS.enum2value(TSTS.SESSIONFLAGS, sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['SessionFlags'])

                    self.sessions[SessionId]['flags'] = sessflags
                    domain = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['DomainName']

                    if not len(self.sessions[SessionId]['Domain']) and len(domain):
                        self.sessions[SessionId]['Domain'] = domain

                    username = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['UserName']

                    if not len(self.sessions[SessionId]['Username']) and len(username):
                        self.sessions[SessionId]['Username'] = username

                    self.sessions[SessionId]['ConnectTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['ConnectTime']
                    self.sessions[SessionId]['DisconnectTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['DisconnectTime']
                    self.sessions[SessionId]['LogonTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['LogonTime']
                    self.sessions[SessionId]['LastInputTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['LastInputTime']
    
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
        Display information about Remote Desktop Services sessions.
        '''
        desktop_states = {
            'WTS_SESSIONSTATE_UNKNOWN': '',
            'WTS_SESSIONSTATE_LOCK': 'Locked',
            'WTS_SESSIONSTATE_UNLOCK': 'Unlocked'
        }

        self.get_session_list(connection)
        if not len(self.sessions):
            return 'No sessions found'

        self.enumerate_sessions_info(connection)
        if self.verbose:
            self.enumerate_sessions_config(connection)
        
        maxSessionNameLen = max([len(self.sessions[i]['SessionName']) + 1 for i in self.sessions])
        maxSessionNameLen = maxSessionNameLen if len('SESSIONNAME') < maxSessionNameLen else len('SESSIONNAME') + 1
        maxUsernameLen = max([len(self.sessions[i]['Username'] + self.sessions[i]['Domain']) + 1 for i in self.sessions]) + 1
        maxUsernameLen = maxUsernameLen if len('Username') < maxUsernameLen else len('Username') + 1
        maxIdLen = max([len(str(i)) for i in self.sessions])
        maxIdLen = maxIdLen if len('ID') < maxIdLen else len('ID') + 1
        maxStateLen = max([len(self.sessions[i]['state']) + 1 for i in self.sessions])
        maxStateLen = maxStateLen if len('STATE') < maxStateLen else len('STATE') + 1
        maxRemoteIp = max([len(self.sessions[i]['RemoteIp']) + 1 for i in self.sessions])
        maxRemoteIp = maxRemoteIp if len('RemoteAddress') < maxRemoteIp else len('RemoteAddress') + 1
        maxClientName = max([len(self.sessions[i]['ClientName']) + 1 for i in self.sessions])
        maxClientName = maxClientName if len('ClientName') < maxClientName else len('ClientName') + 1

        template = (
            '{SESSIONNAME: <%d} '
            '{USERNAME: <%d} '
            '{ID: <%d} '
            '{STATE: <%d} '
            '{DSTATE: <9} '
            '{CONNTIME: <20} '
            '{DISCTIME: <20} '
        ) % (maxSessionNameLen, maxUsernameLen, maxIdLen, maxStateLen)

        template_verbose = (
            '{CLIENTNAME: <%d} '
            '{REMOTEIP: <%d} '
            '{RESOLUTION: <11} '
            '{TIMEZONE: <15}'
        ) % (maxClientName, maxRemoteIp)

        result = []
        header = template.format(
            SESSIONNAME='SESSIONNAME',
            USERNAME='USERNAME',
            ID='ID',
            STATE='STATE',
            DSTATE='Desktop',
            CONNTIME='ConnectTime',
            DISCTIME='DisconnectTime',
        )
        
        header2 = template.replace(' <', '=<').format(
            SESSIONNAME='',
            USERNAME='',
            ID='',
            STATE='',
            DSTATE='',
            CONNTIME='',
            DISCTIME='',
        )

        header_verbose = ''
        header2_verbose = ''
        if self.verbose:
            header_verbose = template_verbose.format(
                CLIENTNAME='ClientName',
                REMOTEIP='RemoteAddress',
                RESOLUTION='Resolution',
                TIMEZONE='ClientTimeZone'
            )

            header2_verbose = template_verbose.replace(' <', '=<').format(
                CLIENTNAME='',
                REMOTEIP='',
                RESOLUTION='',
                TIMEZONE=''
            )

        result.append(header + header_verbose)
        result.append(header2 + header2_verbose)
        
        for i in self.sessions:
            connectTime = self.sessions[i]['ConnectTime']
            connectTime = connectTime.strftime(r'%Y/%m/%d %H:%M:%S') if connectTime.year > 1601 else 'None'

            disconnectTime = self.sessions[i]['DisconnectTime']
            disconnectTime = disconnectTime.strftime(r'%Y/%m/%d %H:%M:%S') if disconnectTime.year > 1601 else 'None'
            userName = self.sessions[i]['Domain'] + '\\' + self.sessions[i]['Username'] if len(self.sessions[i]['Username']) else ''

            row = template.format(
                SESSIONNAME=self.sessions[i]['SessionName'],
                USERNAME=userName,
                ID=i,
                STATE=self.sessions[i]['state'],
                DSTATE=desktop_states[self.sessions[i]['flags']],
                CONNTIME=connectTime,
                DISCTIME=disconnectTime,
            )

            row_verbose = ''
            if self.verbose:
                row_verbose = template_verbose.format(
                    CLIENTNAME=self.sessions[i]['ClientName'],
                    REMOTEIP=self.sessions[i]['RemoteIp'],
                    RESOLUTION=self.sessions[i]['Resolution'],
                    TIMEZONE=self.sessions[i]['ClientTimeZone']
                )

            result.append(row + row_verbose)

        for row in result:
            self.context.log.highlight(row)
