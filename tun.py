#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/1/21
Desc    :   
"""
import sys
import os
import fcntl
import struct

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001 | 0x1000 #TUN + NO_PI
MTU = 1400


class Tun(object):
    ONE_INSTANCE = '__instance__'
    ALL_TUN = {}

    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, cls.ONE_INSTANCE):
            ins = object.__new__(cls)
            setattr(cls, cls.ONE_INSTANCE, ins)
        else:
            ins = getattr(cls, cls.ONE_INSTANCE)
        if 'openwrt' in os.popen('uname -a').read().lower():
            # openwrt TUNSETIFF参数为-2147199798
            kwargs.setdefault('tunsetiff', -2147199798)
        ins.config(**kwargs)
        return ins

    def config(self, tunsetiff=TUNSETIFF, iff_tun=IFF_TUN, mtu=MTU):
        self.tunsetiff, self.iff_tun, self.mtu = tunsetiff, iff_tun, mtu

    def create_tun(self, tun_ip, tun_peer):
        """ Every client needs a tun interface """
        if sys.platform == 'darwin':
            for i in xrange(10):
                try:
                    tname = 'tun%s' % i
                    tun_fd = os.open('/dev/%s' % tname, os.O_RDWR)
                    break
                except:
                    continue
            init_command = "ifconfig %s %s/32 %s mtu %s up" % (tname, tun_ip, tun_peer, self.mtu)
        else:
            try:
                tun_fd = os.open("/dev/net/tun", os.O_RDWR)
            except:
                tun_fd = os.open("/dev/tun", os.O_RDWR)
            if tun_fd < 0:
                raise Exception('Failed to create tun device')
            ifs = fcntl.ioctl(tun_fd, self.tunsetiff, struct.pack("16sH", "tun%d", self.iff_tun))
            tname = ifs[:16].strip("\x00")
            init_command = "ifconfig %s %s dstaddr %s mtu %s up" % (tname, tun_ip, tun_peer, self.mtu)

        # Set up local ip and peer ip
        print "Configuring interface %s with ip %s" % (tname, tun_ip)
        os.system(init_command)

        return tun_fd, tname
