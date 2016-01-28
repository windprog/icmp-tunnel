#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/1/28
Desc    :   
"""
import icmp
import socket
import os
from tun import Tun

DEFAULT_MIN_PACKET_SIZE = 16
BUFFER_SIZE = 8192


class BaseTunnel(object):
    def __init__(self, tun_ip, tun_peer):
        self.tfd, self.tname = Tun().create_tun(tun_ip, tun_peer)
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmpfd.setblocking(0)
        self.packet = icmp.ICMPPacket()
        self.now_identity = 0xffff
        self.server_ip = ''
        self.heartbeat_data = 'req:' + 'q' * (DEFAULT_MIN_PACKET_SIZE - 4 if DEFAULT_MIN_PACKET_SIZE > 4 else '')

    def send(self, data):
        return self.icmpfd.sendto(data, (self.server_ip, 1))

    def recv(self):
        return self.icmpfd.recv(BUFFER_SIZE)

    def get_server_data(self, data):
        return self.packet.create(0, 0, self.now_identity, 0x4147, data)

    def get_client_data(self, data):
        return self.packet.create(8, 0, self.now_identity, 0x4147, data)

    def read_from_tun(self):
        return os.read(self.tfd, BUFFER_SIZE)