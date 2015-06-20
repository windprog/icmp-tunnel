#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015 Windpro

Author  :   windpro
E-mail  :   windprog@gmail.com
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
        self.ttl, self.proto, self.chksum, self._src, self._dst = [None for _ in range(5)]
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
        self.type, self.code, self.chksum, self.id, self.seqno = [None for _ in range(5)]
        self.data = ""
        super(ICMPPacket, self).__init__(buf)

    def loads(self, buf):
        IPPacket.loads(self, buf)
        self.type, self.code, self.chksum, self.id, self.seqno = struct.unpack("!BBHHH", buf[20:28])
        # 从网卡中获取的数据
        self.data = buf[28:]

    @classmethod
    def create(cls, _type, code, _id, seqno, data):
        pk = cls()
        pk.type, pk.code, pk.id, pk.seqno, pk.data = _type, code, _id, seqno, data
        return pk

    def dumps(self):
        packfmt = "!BBHHH%ss" % (len(self.data))
        args = [self.type, self.code, 0, self.id, self.seqno, self.data]
        args[2] = IPPacket.checksum(struct.pack(packfmt, *args))
        return struct.pack(packfmt, *args)

class TunnelPacket(ICMPPacket):
    def __init__(self, buf=None):
        # 载入二进制数据或者创建空对象
        self.session_id = None  # 2字节，客户端的seasion id
        self.random_info = None  # 8字节，目前是time.time() 用于随机化checksum 帮助双倍发送流量
        super(TunnelPacket, self).__init__(buf)

    @property
    def user_data(self):
        return self.data[10:]

    def loads(self, buf):
        # 载入二进制数据
        ICMPPacket.loads(self, buf)
        self.command_id, self.tunnel_id = struct.unpack("!Hd", self.data[:10])

    @classmethod
    def create(cls, _type, code, _id, seqno, session_id, random_info, data):
        # 创建对象
        pk = cls()
        pk.type, pk.code, pk.id, pk.seqno, pk.session_id, pk.random_info, pk.data = \
            _type, code, _id, seqno, data
        return pk

    def dumps(self):
        packfmt = "!BBHHHHd%ss" % (len(self.data))
        args = [self.type, self.code, 0, self.id, self.seqno, self.session_id, self.random_info, self.data]
        args[2] = IPPacket.checksum(struct.pack(packfmt, *args))
        return struct.pack(packfmt, *args)