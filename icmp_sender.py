#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/1/28
Desc    :   
"""
import socket
import traceback
from packet import TunnelPacket
from interface import BaseSender, BUFFER_SIZE
from cmd_control import CommandControl


class ICMPSender(BaseSender):
    def __init__(self, server_ip=''):
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmpfd.setblocking(0)
        self.now_identity = 0xffff
        self.server_ip = server_ip
        self.pending_list = []
        self.icmp_type = 8
        self.cmd_control = CommandControl(self)
        self.debug = False

    def send(self, data):
        pending_list = self.pending_list
        self.pending_list = []
        data_list = pending_list + [data]
        result = TunnelPacket.create(self.icmp_type, 0, self.now_identity, 0x4147, data_list=data_list).dumps()
        return self.icmpfd.sendto(result, (self.server_ip, 1))

    def recv(self):
        buf = self.icmpfd.recv(BUFFER_SIZE)
        packet = TunnelPacket(buf)
        self.now_identity = packet.id
        self.server_ip = packet.src
        data_list = packet.data_list
        for one_data in data_list:
            self.cmd_control.check(one_data)
        return data_list

    def tfd(self):
        return self.icmpfd


class ServerICMPSender(ICMPSender):
    def __init__(self):
        super(ServerICMPSender, self).__init__()
        self.icmp_type = 0


class ClientICMPSender(ICMPSender):
    def __init__(self, server_ip=''):
        # check_heartbeat 会设置server_ip
        super(ClientICMPSender, self).__init__(server_ip=server_ip)
        self.icmp_type = 8


if __name__ == '__main__':
    import sys, select

    if sys.argv[1:]:
        sender = ServerICMPSender()
    else:
        # 预设server ip
        sender = ClientICMPSender(sys.argv[1])

    while True:
        rset = select.select([sender.tfd()], [], [])[0]
        for r in rset:
            if r == sender.tfd():
                result = sender.recv()
                print result, [len(item) for item in result]
                sender.send('remote accept:' + result[0])
        print u'-' * 50
        data = raw_input('input data：')
        sender.send(data)
