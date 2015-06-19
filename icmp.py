#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015 netease

Author  :   windpro
E-mail  :   zzn1889@corp.netease.com
Date    :   15/6/19
Desc    :   
"""
import socket
import struct
import ctypes

BUFFER_SIZE = 8192

class IPPacket(object):
    def __init__(self, buf=None):
        # des:socket.inet_ntoa(self.dst)
        self.ttl, self.proto, self.chksum, self._src, self._dst = [0 for _ in range(5)]
        if buf:
            self.loads(buf)

    src = property(lambda self: socket.inet_ntoa(self._src),
                   lambda self, value: setattr(self, "_src", socket.inet_aton(value)))

    dst = property(lambda self: socket.inet_ntoa(self._dst),
                   lambda self, value: setattr(self, "_dst", socket.inet_aton(value)))

    @staticmethod
    def checksum(data):
        if len(data) % 2:
            odd_byte = ord(data[-1])
            data = data[:-1]
        else:
            odd_byte = 0
        words = struct.unpack("!%sH" %(len(data)/2), data)
        total = 0
        for word in words:
            total += word
        else:
            total += odd_byte
        total = (total>>16) + (total & 0xffff)
        total += total>>16
        return ctypes.c_ushort(~total).value

    def loads(self, buf):
        self.ttl, self.proto, self.chksum = struct.unpack("!BBH", buf[8:12])
        self._src, self._dst = buf[12:16], buf[16:20]

class ICMPPacket(IPPacket):
    def __init__(self, buf=None):
        self.type, self.code, self.chksum, self.id, self.seqno = [0 for _ in range(5)]
        self._data = ""
        super(ICMPPacket, self).__init__(buf)

    def loads(self, buf):
        super(ICMPPacket, self).loads(buf)
        self.type, self.code, self.chksum, self.id, self.seqno = struct.unpack("!BBHHH", buf[20:28])
        self._data = buf[28:]

    @classmethod
    def create(cls, _type, code, _id, seqno, data):
        pk = cls()
        pk.type, pk.code, pk.id, pk.seqno, pk._data = _type, code, _id, seqno, data
        return pk

    def dumps(self):
        packfmt = "!BBHHH%ss" % (len(self._data))
        args = [self.type, self.code, 0, self.id, self.seqno, self._data]
        args[2] = IPPacket.checksum(struct.pack(packfmt, *args))
        return struct.pack(packfmt, *args)
