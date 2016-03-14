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
import time
import traceback
from interface import BaseSender
from icmp_sender import ServerICMPSender, ClientICMPSender
from tun_sender import TunInstance
from tun_poll import TunPoll, BasePoll

TUN_IP = "10.1.2.1"
TUN_PEER = '10.1.2.2'


class SelectTunnel(object):
    def __init__(self, pkg_sender, tun_sender):
        self.pkg_sender = pkg_sender
        self.tun_sender = tun_sender
        self.poll = TunPoll()
        self.poll.register_tun(self.tun_sender.fd())
        self.poll.register_socket(self.pkg_sender.fd())
        assert isinstance(self.poll, BasePoll)
        assert isinstance(pkg_sender, BaseSender)
        assert isinstance(tun_sender, BaseSender)

        # vars
        self.last_recv = 0

    def close(self):
        os.close(self.tun_sender.fd())

    def forever(self):
        self.server_ip = '0.0.0.0'
        while True:
            self.process()

    def process(self):
        # rset = select.select([self.pkg_sender.tfd(), self.tun_sender.tfd()], [], [], 0.01)[0]
        # for r in rset:
        for fileno, event in self.poll.wait(timeout=0.01):
            if fileno == self.tun_sender.fd():
                # tun 模块收到数据
                for data in self.tun_sender.recv():
                    # 这里没有实现读到不能读,需要重构一下
                    self.pkg_sender.send(data)
            elif fileno == self.pkg_sender.fd():
                # 网络收到数据
                now = time.time()
                for data in self.pkg_sender.recv():
                    self.last_recv = now
                    os.write(self.tun_sender.fd(), data)


class ServerTunnel(SelectTunnel):
    pass


class ClientTunnel(SelectTunnel):
    IP_DOMAIN = 'xxxx.f3322.org'

    def __init__(self, pkg_sender, tun_sender):
        super(ClientTunnel, self).__init__(pkg_sender, tun_sender)

        self.heartbeat_data = 'req:'
        self.check_heartbeat()

    def check_heartbeat(self):
        try:
            self.pkg_sender.server_ip = socket.getaddrinfo(self.IP_DOMAIN, None)[0][4][0]
            if time.time() - self.last_recv > 3:
                self.pkg_sender.send(self.heartbeat_data)
                self.last_recv = time.time()
        except:
            print 'send heartbeat error! domain:%s' % repr(self.IP_DOMAIN)

    def process(self):
        super(ClientTunnel, self).process()
        self.check_heartbeat()


if __name__ == "__main__":
    opts = getopt.getopt(sys.argv[1:], "c:l:p:d:t:")
    is_server = True
    DEBUG = False
    _type = 'icmp'
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
        elif opt == '-t':
            _type = optarg

    if _type == 'udp':
        from udp_sender import ClientUDPSender as ClientSender
        from udp_sender import ServerUDPSender as ServerSender
    else:
        from icmp_sender import ClientICMPSender as ClientSender
        from icmp_sender import ServerICMPSender as ServerSender

    if is_server:
        SenderBuilder = ServerSender
        tunnel_builder = SelectTunnel
    else:
        SenderBuilder = ClientSender
        tunnel_builder = ClientTunnel

    pkg_sender = SenderBuilder()
    tun_sender = TunInstance(TUN_IP, TUN_PEER)
    pkg_sender.debug = DEBUG

    tunnel = tunnel_builder(pkg_sender, tun_sender)
    print "Allocated interface %s" % (tun_sender.tname)
    try:
        tunnel.forever()
    except KeyboardInterrupt:
        tunnel.close()
        sys.exit(0)
