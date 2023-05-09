#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import http.server
import threading
import ssl
import os
import sys
from http.server import BaseHTTPRequestHandler
from time import sleep
from cme.helpers.logger import highlight
from cme.logger import CMEAdapter


class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        server_logger = CMEAdapter(
            extra={
                "module_name": self.server.module.name.upper(),
                "host": self.client_address[0],
            }
        )
        server_logger.display("- - %s" % (format % args))

    def do_GET(self):
        if hasattr(self.server.module, "on_request"):
            server_logger = CMEAdapter(
                extra={
                    "module_name": self.server.module.name.upper(),
                    "host": self.client_address[0],
                }
            )
            self.server.context.log = server_logger
            self.server.module.on_request(self.server.context, self)

    def do_POST(self):
        if hasattr(self.server.module, "on_response"):
            server_logger = CMEAdapter(
                extra={
                    "module_name": self.server.module.name.upper(),
                    "host": self.client_address[0],
                }
            )
            self.server.context.log = server_logger
            self.server.module.on_response(self.server.context, self)

    def stop_tracking_host(self):
        """
        This gets called when a module has finshed executing, removes the host from the connection tracker list
        """
        try:
            self.server.hosts.remove(self.client_address[0])
            if hasattr(self.server.module, "on_shutdown"):
                self.server.module.on_shutdown(self.server.context, self.server.connection)
        except ValueError:
            pass


class CMEServer(threading.Thread):
    def __init__(self, module, context, logger, srv_host, port, server_type="https"):
        try:
            threading.Thread.__init__(self)

            self.server = http.server.HTTPServer((srv_host, int(port)), RequestHandler)
            self.server.hosts = []
            self.server.module = module
            self.server.context = context
            self.server.log = CMEAdapter(extra={"module_name": self.server.module.name.upper()})
            self.cert_path = os.path.join(os.path.expanduser("~/.cme"), "cme.pem")
            self.server.track_host = self.track_host

            logger.debug("CME server type: " + server_type)
            if server_type == "https":
                self.server.socket = ssl.wrap_socket(self.server.socket, certfile=self.cert_path, server_side=True)

        except Exception as e:
            errno, message = e.args
            if errno == 98 and message == "Address already in use":
                logger.error("Error starting HTTP(S) server: the port is already in use, try specifying a diffrent port using --server-port")
            else:
                logger.error(f"Error starting HTTP(S) server: {message}")

            sys.exit(1)

    def base_server(self):
        return self.server

    def track_host(self, host_ip):
        self.server.hosts.append(host_ip)

    def run(self):
        try:
            self.server.serve_forever()
        except:
            pass

    def shutdown(self):
        try:
            while len(self.server.hosts) > 0:
                self.server.log.info(f"Waiting on {highlight(len(self.server.hosts))} host(s)")
                sleep(15)
        except KeyboardInterrupt:
            pass

        # shut down the server/socket
        self.server.shutdown()
        self.server.socket.close()
        self.server.server_close()

        # make sure all the threads are killed
        for thread in threading.enumerate():
            if thread.is_alive():
                try:
                    thread._stop()
                except:
                    pass
