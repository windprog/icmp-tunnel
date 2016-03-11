#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/1/28
Desc    :
"""

import os, sys
import getopt
import socket
import select
import time
import traceback
from interface import BaseSender
from icmp_sender import ServerICMPSender, ClientICMPSender
from tun_sender import TunInstance

TUN_IP = "10.1.2.1"
TUN_PEER = '10.1.2.2'


class SelectTunnel(object):
    def __init__(self, pkg_sender, tun_sender):
        self.pkg_sender = pkg_sender
        self.tun_sender = tun_sender
        assert isinstance(pkg_sender, BaseSender)
        assert isinstance(tun_sender, BaseSender)

    def close(self):
        os.close(self.tun_sender.tfd())

    def forever(self):
        self.server_ip = '0.0.0.0'
        while True:
            self.process()

    def process(self):
        rset = select.select([self.pkg_sender.tfd(), self.tun_sender.tfd()], [], [])[0]
        for r in rset:
            if r == self.tun_sender.tfd():
                # tun 模块收到数据
                for data in self.tun_sender.recv():
                    # 这里没有实现读到不能读,需要重构一下
                    self.pkg_sender.send(data)
            elif r == self.pkg_sender.tfd():
                # 网络收到数据
                for data in self.pkg_sender.recv():
                    os.write(self.tun_sender.tfd(), data)


class ServerTunnel(SelectTunnel):
    pass


class ClientTunnel(SelectTunnel):
    IP_DOMAIN = 'xxxx.f3322.org'

    def __init__(self, pkg_sender, tun_sender):
        super(ClientTunnel, self).__init__(pkg_sender, tun_sender)
        self.heartbeat = 0
        self.heartbeat_data = 'req:'
        self.check_heartbeat()

    def check_heartbeat(self):
        try:
            self.pkg_sender.server_ip = socket.getaddrinfo(self.IP_DOMAIN, None)[0][4][0]
            if time.time() - self.heartbeat > 3:
                self.pkg_sender.send(self.heartbeat_data)
        except:
            print 'send heartbeat error! domain:%s' % repr(self.IP_DOMAIN)

    def process(self):
        super(ClientTunnel, self).process()
        self.check_heartbeat()


if __name__ == "__main__":
    opts = getopt.getopt(sys.argv[1:], "c:l:p:d:")
    is_server = True
    DEBUG = False
    for opt, optarg in opts[0]:
        if opt == "-c":
            is_server = False
            ClientTunnel.IP_DOMAIN = optarg
        elif opt == "-l":
            TUN_IP = optarg
        elif opt == '-p':
            TUN_PEER = optarg
        elif opt == '-d':
            DEBUG = True

    tun_sender = TunInstance(TUN_IP, TUN_PEER)
    if is_server:
        pkg_sender = ServerICMPSender()
        tunnel_builder = SelectTunnel
    else:
        pkg_sender = ClientICMPSender()
        tunnel_builder = ClientTunnel
    pkg_sender.debug = DEBUG

    tunnel = tunnel_builder(pkg_sender, tun_sender)
    print "Allocated interface %s" % (tun_sender.tname)
    try:
        tunnel.forever()
    except KeyboardInterrupt:
        tunnel.close()
        sys.exit(0)
