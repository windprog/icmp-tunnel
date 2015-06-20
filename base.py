#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015 Windpro

Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   15/6/20
Desc    :   
"""
from collections import OrderedDict
import struct
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import select
import sys

from interface import BaseIoControl, TunInfo, BaseTun


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

class IoControl(BaseIoControl):
    def __init__(self):
        self._epoll = select.epoll()
        self.command = {}

    def register(self, fileno, io_callback):
        self._epoll.register(fileno, select.EPOLLIN)
        self.command[fileno] == io_callback

    def serve_forever(self):
        while True:
            events = self._epoll.poll(30)
            if len(events) == 0:
                continue
            for fileno, event in events:
                if fileno in self.command:
                    try:
                        self.command[fileno]()
                    except:
                        import traceback
                        print traceback.print_exc(file=sys.stdout)


class Tun(BaseTun):
    def __init__(self, addr, dstaddr, netmask="255.255.255.0", mtu=1300, **kwargs):
        self.tun_info = TunInfo(addr, dstaddr)
        self.netmask, self.mtu = netmask, mtu
        self.tunfd = None

    def start(self):
        try:
            import pytun
        except:
            pass
        assert isinstance(self.tun_info, TunInfo)
        tun = pytun.TunTapDevice("stun")
        self.tunfd = tun
        tun.addr = self.tun_info.addr
        tun.dstaddr = self.tun_info.dstaddr
        tun.netmask = self.netmask
        tun.mtu = self.mtu
        tun.up()
        return tun

    def close(self):
        self.tunfd.close()

    def write(self, data):
        self.tunfd.write(data)

    def fileno(self):
        return self.tunfd.fileno()

    def read(self, length=2048):
        return self.tunfd.read(length)