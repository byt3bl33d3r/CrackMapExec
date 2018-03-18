import logging
from gevent import sleep
from cme.c2 import C2
from cme.helpers.powershell import ps_deflate_and_encode, ps_decode_and_inflate
from cme.helpers.misc import gen_random_string


class File(C2):
    def __init__(self, proto, payload, exec_methods, force_ps32, ret_output):
        C2.__init__(self, proto, payload, exec_methods, force_ps32, ret_output)

        self.share = "C$"
        self.path = "Windows\\Temp"
        self.output_file_name = gen_random_string(8)
        self.payload_file_name = gen_random_string(8)

        self.command_with_output = ''
        self.command_without_output = ''

    def run(self, command):
        compressed_payload = ps_deflate_and_encode(self.create_ps_payload(self.payload))

        self.write(compressed_payload)
        self.execute_command(self.command_with_output if self.ret_output else self.command_without_output)
        output = self.get_output()
        self.cleanup()

        return output

    def write(self, payload):
        ## Finish this
        self.proto.conn.createFile()

    def get_output(self):
        output = ''

        if not self.ret_output:
            return

        def output_callback(data):
            # Wat
            output += data

        while True:
            try:
                self.proto.conn.getFile(self.share, self.output_file_name, output_callback)
            except Exception as e:
                logging.debug("Error retrieving output file {}: {}".format(self.output_file_name, e))
                sleep(4)

        return ps_decode_and_inflate(output)

    def cleanup(self):
        try:
            self.proto.conn.deleteFile(self.share, self.output_file_name)
        except Exception as e:
            logging.debug("Error retrieving output file {}: {}".format(self.output_file_name, e))

        try:
            self.proto.conn.deleteFile(self.share, self.payload_file_name)
        except Exception as e:
            logging.debug("Error retrieving output file {}: {}".format(self.output_file_name, e))
