#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# All credits to https://github.com/d4t4s3c/Win7Blue
# @d4t4s3c
# Module by @mpgn_x64

from ctypes import *
import socket
import struct


class CMEModule:
    name = "ms17-010"
    description = "MS17-010, /!\ not tested oustide home lab"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """ """

    def on_login(self, context, connection):
        if check(connection.host):
            context.log.highlight("VULNERABLE")
            context.log.highlight("Next step: https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/")


class SMB_HEADER(Structure):
    """SMB Header decoder."""

    _pack_ = 1

    _fields_ = [
        ("server_component", c_uint32),
        ("smb_command", c_uint8),
        ("error_class", c_uint8),
        ("reserved1", c_uint8),
        ("error_code", c_uint16),
        ("flags", c_uint8),
        ("flags2", c_uint16),
        ("process_id_high", c_uint16),
        ("signature", c_uint64),
        ("reserved2", c_uint16),
        ("tree_id", c_uint16),
        ("process_id", c_uint16),
        ("user_id", c_uint16),
        ("multiplex_id", c_uint16),
    ]

    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)


def generate_smb_proto_payload(*protos):
    """Generate SMB Protocol. Pakcet protos in order."""
    hexdata = []
    for proto in protos:
        hexdata.extend(proto)
    return "".join(hexdata)


def calculate_doublepulsar_xor_key(s):
    """Calaculate Doublepulsar Xor Key"""
    x = 2 * s ^ (((s & 0xFF00 | (s << 16)) << 8) | (((s >> 16) | s & 0xFF0000) >> 8))
    x = x & 0xFFFFFFFF
    return x


def negotiate_proto_request():
    """Generate a negotiate_proto_request packet."""
    netbios = ["\x00", "\x00\x00\x54"]

    smb_header = [
        "\xFF\x53\x4D\x42",
        "\x72",
        "\x00\x00\x00\x00",
        "\x18",
        "\x01\x28",
        "\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00",
        "\x00\x00",
        "\x2F\x4B",
        "\x00\x00",
        "\xC5\x5E",
    ]

    negotiate_proto_request = [
        "\x00",
        "\x31\x00",
        "\x02",
        "\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00",
        "\x02",
        "\x4C\x4D\x31\x2E\x32\x58\x30\x30\x32\x00",
        "\x02",
        "\x4E\x54\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00",
        "\x02",
        "\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00",
    ]

    return generate_smb_proto_payload(netbios, smb_header, negotiate_proto_request)


def session_setup_andx_request():
    """Generate session setuo andx request."""
    netbios = ["\x00", "\x00\x00\x63"]

    smb_header = [
        "\xFF\x53\x4D\x42",
        "\x73",
        "\x00\x00\x00\x00",
        "\x18",
        "\x01\x20",
        "\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00",
        "\x00\x00",
        "\x2F\x4B",
        "\x00\x00",
        "\xC5\x5E",
    ]

    session_setup_andx_request = [
        "\x0D",
        "\xFF",
        "\x00",
        "\x00\x00",
        "\xDF\xFF",
        "\x02\x00",
        "\x01\x00",
        "\x00\x00\x00\x00",
        "\x00\x00",
        "\x00\x00",
        "\x00\x00\x00\x00",
        "\x40\x00\x00\x00",
        "\x26\x00",
        "\x00",
        "\x2e\x00",
        "\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00",
        "\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00",
    ]

    return generate_smb_proto_payload(netbios, smb_header, session_setup_andx_request)


def tree_connect_andx_request(ip, userid):
    """Generate tree connect andx request."""

    netbios = ["\x00", "\x00\x00\x47"]

    smb_header = [
        "\xFF\x53\x4D\x42",
        "\x75",
        "\x00\x00\x00\x00",
        "\x18",
        "\x01\x20",
        "\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00",
        "\x00\x00",
        "\x2F\x4B",
        userid,
        "\xC5\x5E",
    ]

    ipc = "\\\\{}\IPC$\x00".format(ip)

    tree_connect_andx_request = [
        "\x04",
        "\xFF",
        "\x00",
        "\x00\x00",
        "\x00\x00",
        "\x01\x00",
        "\x1A\x00",
        "\x00",
        ipc.encode(),
        "\x3f\x3f\x3f\x3f\x3f\x00",
    ]

    length = len("".join(smb_header)) + len("".join(tree_connect_andx_request))

    netbios[1] = struct.pack(">L", length)[-3:]

    return generate_smb_proto_payload(netbios, smb_header, tree_connect_andx_request)


def peeknamedpipe_request(treeid, processid, userid, multiplex_id):
    """Generate tran2 request"""

    netbios = ["\x00", "\x00\x00\x4a"]

    smb_header = [
        "\xFF\x53\x4D\x42",
        "\x25",
        "\x00\x00\x00\x00",
        "\x18",
        "\x01\x28",
        "\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00",
        treeid,
        processid,
        userid,
        multiplex_id,
    ]

    tran_request = [
        "\x10",
        "\x00\x00",
        "\x00\x00",
        "\xff\xff",
        "\xff\xff",
        "\x00",
        "\x00",
        "\x00\x00",
        "\x00\x00\x00\x00",
        "\x00\x00",
        "\x00\x00",
        "\x4a\x00",
        "\x00\x00",
        "\x4a\x00",
        "\x02",
        "\x00",
        "\x23\x00",
        "\x00\x00",
        "\x07\x00",
        "\x5c\x50\x49\x50\x45\x5c\x00",
    ]

    return generate_smb_proto_payload(netbios, smb_header, tran_request)


def trans2_request(treeid, processid, userid, multiplex_id):
    """Generate trans2 request."""

    netbios = ["\x00", "\x00\x00\x4f"]

    smb_header = [
        "\xFF\x53\x4D\x42",
        "\x32",
        "\x00\x00\x00\x00",
        "\x18",
        "\x07\xc0",
        "\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00",
        treeid,
        processid,
        userid,
        multiplex_id,
    ]

    trans2_request = [
        "\x0f",
        "\x0c\x00",
        "\x00\x00",
        "\x01\x00",
        "\x00\x00",
        "\x00",
        "\x00",
        "\x00\x00",
        "\xa6\xd9\xa4\x00",
        "\x00\x00",
        "\x0c\x00",
        "\x42\x00",
        "\x00\x00",
        "\x4e\x00",
        "\x01",
        "\x00",
        "\x0e\x00",
        "\x00\x00",
        "\x0c\x00" + "\x00" * 12,
    ]

    return generate_smb_proto_payload(netbios, smb_header, trans2_request)


def check(ip, port=445):
    """Check if MS17_010 SMB Vulnerability exists."""
    try:
        buffersize = 1024
        timeout = 5.0

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect((ip, port))

        raw_proto = negotiate_proto_request()
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        raw_proto = session_setup_andx_request()
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)
        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]
        smb = SMB_HEADER(smb_header)

        user_id = struct.pack("<H", smb.user_id)

        session_setup_andx_response = tcp_response[36:]
        native_os = session_setup_andx_response[9:].split("\x00")[0]

        raw_proto = tree_connect_andx_request(ip, user_id)
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]
        smb = SMB_HEADER(smb_header)

        tree_id = struct.pack("<H", smb.tree_id)
        process_id = struct.pack("<H", smb.process_id)
        user_id = struct.pack("<H", smb.user_id)
        multiplex_id = struct.pack("<H", smb.multiplex_id)

        raw_proto = peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id)
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]
        smb = SMB_HEADER(smb_header)

        nt_status = struct.pack("BBH", smb.error_class, smb.reserved1, smb.error_code)

        if nt_status == "\x05\x02\x00\xc0":
            return True
        elif nt_status in ("\x08\x00\x00\xc0", "\x22\x00\x00\xc0"):
            return False
        else:
            return False

    except Exception as err:
        return False
    finally:
        client.close()
