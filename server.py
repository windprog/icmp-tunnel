#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015 netease

Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   15/6/18
Desc    :   
"""
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import json
import pytun
import random
import select
import socket
import struct
import sys
import time
from icmp import ICMPPacket
import sys

CLIENT_ICMP_TYPE = 8
SERVER_ICMP_TYPE = 0
PASSWORD = 'password'


def tun_setup(is_server):
    tun = None
    if is_server == True:
        tun = pytun.TunTapDevice("stun")
        tun.addr = "10.8.0.1"
        tun.dstaddr = "10.8.0.2"
    else:
        tun = pytun.TunTapDevice("ctun")
        tun.addr = "10.8.0.2"
        tun.dstaddr = "10.8.0.1"
    tun.netmask = "255.255.255.0"
    tun.mtu = 1300
    tun.up()
    return tun


class AESCipher:
    def __init__(self, key):
        self.BS = 16
        h = SHA256.new()
        h.update(self.pad(key))
        h.update(h.hexdigest())
        h.update(h.hexdigest())
        h.update(h.hexdigest())
        self.key = h.hexdigest()[:16]

    def pad(self, raw):
        # two bytes length,+padded data
        lenbytes = struct.pack('<H', len(raw))
        padding = 'x' * (self.BS - (len(raw) + 2) % self.BS)
        return lenbytes + raw + padding

    def unpad(self, data):
        datalen = struct.unpack('<H', data[:2])[0]
        return data[2:2 + datalen]

    def encrypt(self, raw):
        ret = None
        try:
            raw = self.pad(raw)
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            ret = iv + cipher.encrypt(raw)
        except:
            print "Encrypt error %s" % sys.exc_info()[0]
            ret = None
        return ret

    def decrypt(self, enc):
        ret = None
        try:
            iv = enc[:AES.block_size]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            ret = self.unpad(cipher.decrypt(enc[AES.block_size:]))
        except:
            print "Decrypt error %s" % sys.exc_info()[0]
            ret = None
        return ret

class TunnelPacket(ICMPPacket):
    def __init__(self, buf=None):
        self.tunnel_id = None
        super(TunnelPacket, self).__init__(buf)

    def loads(self, buf):
        super(ICMPPacket, self).loads(buf)
        # self.tunnel_id为原来data字段的头两个字节
        self.type, self.code, self.chksum, self.id, self.seqno, self.tunnel_id = struct.unpack("!BBHHHL", buf[20:32])
        self.data = buf[32:]

    @classmethod
    def create(cls, _type, code, _id, seqno, tunnel_id, data):
        pk = cls()
        pk.type, pk.code, pk.id, pk.seqno, pk.tunnel_id, pk.data = _type, code, _id, seqno, tunnel_id, data
        return pk

    def dumps(self):
        packfmt = "!BBHHHL%ss" % (len(self.data))
        args = [self.type, self.code, 0, self.id, self.seqno, self.tunnel_id, self.data]
        args[2] = ICMPPacket.checksum(struct.pack(packfmt, *args))
        return struct.pack(packfmt, *args)

class PacketControl(object):
    def __init__(self, tunnel):
        self.tunnel = tunnel
        assert isinstance(self.tunnel, Tunnel)
        self.builder_class = ICMPPacket
        self.now_send_id = long(0)
        self.recv_ids = []
        self.cipher = AESCipher(PASSWORD)

    def get_send_id(self):
        self.now_send_id += 1
        if self.now_send_id >= sys.maxint:
            self.now_send_id = long(1)
        return self.now_send_id

    def send(self, buf):
        buf = self.cipher.encrypt(buf)
        if buf is None:
            return
        ipk = TunnelPacket.create(
            self.tunnel.icmp_type, 0, self.tunnel.now_icmp_identity, 0x4147, self.get_send_id(), buf).dumps()
        for _ in range(2):
            self.tunnel.icmpfd.sendto(ipk, (self.tunnel.DesIp, 22))

    def recv(self):
        buf = self.tunnel.icmpfd.recv(2048)
        packet = TunnelPacket(buf)
        packet.data = self.cipher.decrypt(packet.data)
        if packet.seqno != 0x4147:  # True packet
            return None
        print packet.tunnel_id
        if not packet.data:
            return None
        if packet.tunnel_id not in self.recv_ids:
            if len(self.recv_ids) > 100000:
                self.recv_ids.pop(0)
            self.recv_ids.append(packet.tunnel_id)
            return packet
        else:
            return None


class Tunnel(object):
    def __init__(self, is_server, des_ip=None):
        self.is_server = is_server
        self.DesIp = des_ip

        self.epoll = select.epoll()

        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        self.epoll.register(self.icmpfd.fileno(), select.EPOLLIN)
        self.tunfd = self.get_tun()
        self.epoll.register(self.tunfd.fileno(), select.EPOLLIN)

        self.now_icmp_identity = 0xffff

        self.control = PacketControl(self)
        if is_server:
            self.icmp_type = SERVER_ICMP_TYPE
        else:
            self.icmp_type = CLIENT_ICMP_TYPE
        if is_server:
            print 'server ip:10.8.0.1 dev:stun finish'
            try:
                # 初始化iptabls  你可以自行编写脚本，方便自动化
                from iptables import init
                init()
            except:
                pass
        else:
            print 'server ip:10.8.0.2 dev:ctun finish'

    def get_tun(self):
        return tun_setup(self.is_server)

    def close(self):
        self.tunfd.close()

    def run(self):
        while True:
            events = self.epoll.poll(30)
            if len(events) == 0:
                continue
            for fileno, event in events:
                if fileno == self.tunfd.fileno():
                    buf = self.tunfd.read(2048)
                    self.control.send(buf)
                elif fileno == self.icmpfd.fileno():
                    packet = self.control.recv()
                    if not packet:
                        continue
                    data = packet.data
                    self.now_icmp_identity = packet.id
                    if self.is_server:
                        des_ip = socket.inet_ntoa(packet.src)
                        self.DesIp = des_ip
                    self.tunfd.write(data)


if __name__ == '__main__':
    kwargs = dict(
        is_server=True,
    )
    if len(sys.argv) > 1:
        # client
        kwargs['is_server'] = False
        kwargs['des_ip'] = sys.argv[1]
    t = Tunnel(**kwargs)
    try:
        t.run()
    except KeyboardInterrupt:
        t.close()
        sys.exit(0)
