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
from icmp import checksum as no_ctypes_checksum

DEFAULT_MIN_ICMP_SIZE = 32
BUFFER_SIZE = 8192


class IPPacket(object):
    DEBUG = False
    END_TO = 20

    def __init__(self, buf=None):
        # des:socket.inet_ntoa(self.dst)
        self.raw_data = buf
        self.ttl, self.proto, self.chksum, self._src, self._dst = [None for _ in range(5)]
        if buf:
            self.loads(buf)
        if buf and self.DEBUG:
            print "parse IP ttl=", self.ttl, "proto=", self.proto, \
                "_src=", self.src, "dst=", self.dst

    src = property(lambda self: socket.inet_ntoa(self._src),
                   lambda self, value: setattr(self, "_src", socket.inet_aton(value)))

    dst = property(lambda self: socket.inet_ntoa(self._dst),
                   lambda self, value: setattr(self, "_dst", socket.inet_aton(value)))

    @classmethod
    def checksum(cls, data):
        if len(data) % 2:
            odd_byte = ord(data[-1])
            data = data[:-1]
        else:
            odd_byte = 0
        words = struct.unpack("!%sH" % (len(data) / 2), data)
        total = 0
        for word in words:
            total += word
        else:
            total += odd_byte
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return ctypes.c_ushort(~total).value
    
    @classmethod
    def no_ctypes_checksum(cls, data):
        return no_ctypes_checksum(data)

    def loads(self, buf):
        self.ttl, self.proto, self.chksum = struct.unpack("!BBH", buf[8:12])
        self._src, self._dst = buf[12:16], buf[16:20]


try:
    import ctypes
except:
    IPPacket.checksum = IPPacket.no_ctypes_checksum


class ICMPPacket(IPPacket):
    END_TO = 28

    def __init__(self, buf=None):
        self.type, self.code, self.chksum, self.id, self.seqno = [None for _ in range(5)]
        self._data = ""
        super(ICMPPacket, self).__init__(buf)
        if buf and self.DEBUG:
            print "parse ICMP type=", self.type, "code=", self.code, "checksum=", self.chksum, "id=", self.id, "seqno=", self.seqno

    def loads(self, buf):
        IPPacket.loads(self, buf)
        self.type, self.code, self.chksum, self.id, self.seqno = struct.unpack("!BBHHH", buf[20:28])

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


class TunnelPacket(ICMPPacket):
    ICMP_FMT = '!BBHHH'
    def __init__(self, buf=None):
        # 载入二进制数据或者创建空对象
        self.session_id = 0  # 保留字段,用于判断来源
        self.data_list = []
        super(TunnelPacket, self).__init__(buf)
        if buf and self.DEBUG:
            print "parse Tunnel session_id=", self.session_id, "data_count", len(self.data_list)

    def loads(self, buf):
        # 载入二进制数据
        ICMPPacket.loads(self, buf)
        self.data_list = []

        start_index = ICMPPacket.END_TO
        end_index = ICMPPacket.END_TO + 4
        self.session_id, data_len = struct.unpack("!HH", self.raw_data[start_index:end_index])
        while True:
            if end_index + data_len > len(self.raw_data):
                # 超出最大数量
                break
            data = self.raw_data[end_index:end_index + data_len]
            if not data or len(data) != data_len:
                # 数据不准确
                break
            self.data_list.append(data)
            data_len_str = self.raw_data[end_index + data_len:end_index + data_len + 2]
            if not data_len_str:
                # 没有下一个
                break
            end_index = end_index + data_len + 2
            data_len = struct.unpack("!H", data_len_str)[0]

    @classmethod
    def create(cls, _type, code, _id, seqno, session_id=0, data_list=[]):
        # 创建对象
        pk = cls()
        pk.type, pk.code, pk.id, pk.seqno, pk.session_id, pk.data_list = _type, code, _id, seqno, session_id, data_list
        return pk

    def dumps(self):
        # type, code, chksum, id, seqno, session_id, *data_list
        packfmt = "!BBHHHH" + "".join(["H%ss" % len(data) for data in self.data_list])
        data_args = []
        for data in self.data_list:
            assert len(data) < 65535
            data_args.extend((len(data), data))
        icmp_args = [self.type, self.code, 0, self.id, self.seqno]
        args = icmp_args + [self.session_id] + data_args
        # 最小包
        hop_result = struct.pack(packfmt, *args)
        if len(hop_result) < DEFAULT_MIN_ICMP_SIZE:
            hop_result += '-' * (DEFAULT_MIN_ICMP_SIZE - len(hop_result))
        # 重新计算checksum
        icmp_args[2] = IPPacket.checksum(hop_result)
        # 连结包头和主题数据
        return struct.pack(self.ICMP_FMT, *icmp_args) + hop_result[8:]


if __name__ == '__main__':
    assert len(TunnelPacket.create(0, 0, 0, 0, 0, ["a", "bd"]).dumps()) == 17

    # "a" * 20 + TunnelPacket.create(0,0,0,0,0,["a", "bd"]).dumps()
    test_buf = '616161616161616161616161616161616161616100009c3800000000000000016100026264'.decode('hex')
    p = TunnelPacket(test_buf)
    assert p.data_list == ['a', 'bd']

    # "a" * 20 + TunnelPacket.create(0,0,0,0,0,["a", "bd"]).dumps() + 'asdgadsgasdgasdghadsgh'
    test_error_buf = '616161616161616161616161616161616161616100009c3800000000000000016100026264' \
                     '6173646761647367616473676164736768'.decode('hex')
    p = TunnelPacket(test_error_buf)
    assert p.data_list == ['a', 'bd']

    # ("a" * 20 + TunnelPacket.create(0,0,0,0,0,["a", "bd"]).dumps())[:-1]
    test_left_buf = '616161616161616161616161616161616161616100009c38000000000000000161000262'.decode('hex')
    p = TunnelPacket(test_left_buf)
    assert p.data_list == ['a']
