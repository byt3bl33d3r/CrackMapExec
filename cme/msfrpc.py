#! /usr/bin/env python3

# MSF-RPC - A  Python library to facilitate MSG-RPC communication with Metasploit

# Copyright (c) 2014-2016 Ryan Linn  - RLinn@trustwave.com, Marcello Salvati - byt3bl33d3r@gmail.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

import msgpack
import requests


class MsfError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)


class MsfAuthError(MsfError):
    def __init__(self, msg):
        self.msg = msg


class Msfrpc:

    def __init__(self, opts=[]):
        self.host = opts.get('host') or "127.0.0.1"
        self.port = opts.get('port') or "55552"
        self.uri = opts.get('uri') or "/api/"
        self.ssl = opts.get('ssl') or False
        self.token = None
        self.headers = {"Content-type": "binary/message-pack"}

    def encode(self, data):
        return msgpack.packb(data)

    def decode(self, data):
        return msgpack.unpackb(data)

    def call(self, method, opts=[]):
        if method != 'auth.login':
            if self.token is None:
                raise MsfAuthError("MsfRPC: Not Authenticated")

        if method != "auth.login":
            opts.insert(0, self.token)

        if self.ssl is True:
            url = "https://%s:%s%s" % (self.host, self.port, self.uri)
        else:
            url = "http://%s:%s%s" % (self.host, self.port, self.uri)

        opts.insert(0, method)
        payload = self.encode(opts)

        r = requests.post(url, data=payload, headers=self.headers)

        opts[:] = []  # Clear opts list

        return self.decode(r.content)

    def login(self, user, password):
        auth = self.call("auth.login", [user, password])
        try:
            if auth['result'] == 'success':
                self.token = auth['token']
                return True
        except:
            raise MsfAuthError("MsfRPC: Authentication failed")
