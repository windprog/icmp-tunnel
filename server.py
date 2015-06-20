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

from collections import OrderedDict

class LastUpdatedOrderedDict(OrderedDict):
    def __init__(self, capacity):
        OrderedDict.__init__(self)  # 注意这里有self
        self._capacity = capacity

    def __setitem__(self, key, value):
        if key in self:
            del self[key]
        else:
            if len(self) >= self._capacity:
                self.popitem(False)
        super(LastUpdatedOrderedDict, self).__setitem__(key, value)


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


MIN_ID = 0
MAX_ID = 0xffff

class Tunnel(object):
    def __init__(self, is_server, des_ip=None):
        self.is_server = is_server
        self.DesIp = des_ip

        self.epoll = select.epoll()

        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        self.epoll.register(self.icmpfd.fileno(), select.EPOLLIN)
        self.tunfd = self.get_tun()
        self.epoll.register(self.tunfd.fileno(), select.EPOLLIN)

        self.cipher = AESCipher(PASSWORD)

        self.NowIdentity = 0xffff

        self.recv_ids = LastUpdatedOrderedDict(10000)
        self.now_id = MIN_ID
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

    def get_id(self):
        if self.now_id < MAX_ID:
            self.now_id += 1
            return self.now_id
        else:
            self.now_id = MIN_ID
            return self.now_id

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
                    buf = self.cipher.encrypt(buf) + struct.pack('!d', time.time())
                    if buf is None:
                        continue
                    ipk = ICMPPacket.create(self.icmp_type, 0, self.NowIdentity, 0x4147, buf).dumps()
                    # debug
                    new_pk = ICMPPacket.create(self.icmp_type, 0, self.NowIdentity, 0x4147, buf)
                    new_pk.dumps()
                    next_pk = ICMPPacket.create(self.icmp_type, 0, self.NowIdentity, 0x4147, (buf[:-8] + struct.pack('!d', time.time())))
                    next_pk.dumps()
                    print 'sending checksum:%s next same packet checksum:%s' % (new_pk.chksum, next_pk.chksum)
                    
                    try:
                        self.icmpfd.sendto(ipk, (self.DesIp, 22))
                    except:
                        self.icmpfd.close()
                        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
                        try:
                            self.icmpfd.sendto(ipk, (self.DesIp, 22))
                        except:
                            pass
                elif fileno == self.icmpfd.fileno():
                    buf = self.icmpfd.recv(2048)
                    packet = ICMPPacket(buf)
                    data = packet.data
                    if packet.seqno == 0x4147:
                        chksum = packet.chksum
                        if chksum in self.recv_ids:
                            if time.time() - self.recv_ids[chksum] < 3:
                                # 再次在3秒内接到一样id的数据包丢弃
                                continue
                        if self.is_server:
                            des_ip = socket.inet_ntoa(packet.src)
                            self.DesIp = des_ip
                        if len(data) <= 8:
                            continue
                        data = self.cipher.decrypt(data[:-8])
                        if not data:
                            continue
                        # 可解密，证明是正常数据，保证通路正常
                        self.NowIdentity = packet.id
                        self.recv_ids[chksum] = time.time()
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
