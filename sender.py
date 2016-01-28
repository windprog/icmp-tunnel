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
from packet import TunnelPacket

DEFAULT_MIN_ICMP_SIZE = 24
BUFFER_SIZE = 8192


class BaseTunnel(object):
    def __init__(self, tun_ip, tun_peer):
        self.tfd, self.tname = Tun().create_tun(tun_ip, tun_peer)
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmpfd.setblocking(0)
        self.now_identity = 0xffff
        self.server_ip = ''
        self.heartbeat_data = 'req:'
        self.pending_list = []

    def send(self, data):
        return self.icmpfd.sendto(data, (self.server_ip, 1))

    def recv(self):
        return self.icmpfd.recv(BUFFER_SIZE)

    def _get_icmp_data(self, _type, data):
        pending_list = self.pending_list
        self.pending_list = []
        data_list = pending_list + [data]
        result = TunnelPacket.create(_type, 0, self.now_identity, 0x4147, data_list=data_list).dumps()
        if len(result) < DEFAULT_MIN_ICMP_SIZE:
            result += 'q' * (DEFAULT_MIN_ICMP_SIZE - len(result))
        return result
        # return self.packet.create(0, 0, self.now_identity, 0x4147, data)

    def get_server_data(self, data):
        self._get_icmp_data(0, data)

    def get_client_data(self, data):
        return self._get_icmp_data(8, data)
        # return self.packet.create(8, 0, self.now_identity, 0x4147, data)

    def read_from_tun(self):
        return os.read(self.tfd, BUFFER_SIZE)
