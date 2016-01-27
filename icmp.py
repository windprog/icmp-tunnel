#!/usr/bin/env python

import socket
import binascii
import struct


BUFFER_SIZE = 8192


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff

class IPPacket():
    def _checksum(self, data):
        import ctypes
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

    def _checksum_no_ctypes(self, data):
        return checksum(data)

    def parse(self, buf, debug = True):
        self.ttl, self.proto, self.chksum = struct.unpack("!BBH", buf[8:12])
        self.src, self.dst = buf[12:16], buf[16:20]
        if debug:
            print "parse IP ttl=", self.ttl, "proto=", self.proto, "src=", socket.inet_ntoa(self.src), \
                "dst=", socket.inet_ntoa(self.dst)

class ICMPPacket(IPPacket):
    def parse(self, buf, debug = True):
        IPPacket.parse(self, buf, debug)

        self._type, self.code, self.chksum, self.id, self.seqno = struct.unpack("!BBHHH", buf[20:28])
        if debug:
            print "parse ICMP type=", self._type, "code=", self.code, "id=", self.id, "seqno=", self.seqno
        return buf[28:]

    def createEx(self, type_, code, id_, seqno, data,Ischksum=True):
        packfmt = "!BBHHH%ss" % (len(data))
        args = [type_, code, 0, id_, seqno, data]
        if Ischksum==True:
            args[2] = IPPacket._checksum(self, struct.pack(packfmt, *args))
        return struct.pack(packfmt, *args)

    def create(self, type_, code, id_, seqno, data):
        packfmt = "!BBHHH%ss" % (len(data))
        args = [type_, code, 0, id_, seqno, data]
        args[2] = IPPacket._checksum(self, struct.pack(packfmt, *args))
        return struct.pack(packfmt, *args)

    def createByServer(self, Identity, seqnoAndPassword, data):
        packfmt = "!BBHHH%ss" % (len(data))
        args = [0, 0, 0, Identity, seqnoAndPassword, data]

        args[2] = IPPacket._checksum(self, struct.pack(packfmt, *args))

        self._type, self.code, self.chksum, self.id, self.seqno = args[0:5]

        return struct.pack(packfmt, *args)

    def createByClient(self, Identity, seqnoAndPassword, data):
        packfmt = "!BBHHH%ss" % (len(data))
        args = [8, 0, 0, Identity, seqnoAndPassword, data]

        #args[2] = IPPacket._checksum(self, struct.pack(packfmt, *args))

        self._type, self.code, self.chksum, self.id, self.seqno = args[0:5]

        result = struct.pack(packfmt, *args)
        return result

try:
    import ctypes
except:
    IPPacket._checksum = IPPacket._checksum_no_ctypes


def ping():
    fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    fd.connect(("xiaoxia.org", 22))
    
    print "Waiting for icmp data"
    index = 1
    while True:
        icmp = ICMPPacket()
        buf = icmp.create(8, 86, 0x2012, index, "helloworld"*200)
        index += 1
        print "send\n", binascii.hexlify(buf)
        fd.send(buf)
        buf = fd.recv(BUFFER_SIZE)
        icmp.parse(buf)

def testping(ipaddress):
    icmp = socket.getprotobyname("icmp")
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    
    icmp = ICMPPacket()
    buf = icmp.create(8, 86, 0x2012, 1, "hello")
    print "send\n", binascii.hexlify(buf)
    dest_addr  =  socket.gethostbyname(ipaddress)
    my_socket.sendto(buf,(dest_addr,1))
    recPacket, addr = my_socket.recvfrom(BUFFER_SIZE)
    recv = icmp.parse(recPacket,True)

if __name__=="__main__":
    testping("192.168.216.132")
