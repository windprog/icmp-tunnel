#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/14
Desc    :
"""
import socket
import traceback
from packet import TunnelPacket
from interface import BaseSender, BUFFER_SIZE
from cmd_control import CommandControl


class UDPSender(BaseSender):
    def __init__(self, server_ip=''):
        self.server_ip = server_ip
        self.port = 0x4147
        self.pending_list = []
        self.cmd_control = CommandControl(self)
        self.debug = False

    def send(self, data):
        try:
            ret = self.udpfd.sendto(data, (self.server_ip, self.port))
            if self.debug:
                print 'send ip:%s type:udp port:%s count:%s data:%s' % (self.server_ip, self.port, len(data), repr(data))
            return ret
        except socket.error, e:
            print 'socket error', e.errno

    def f(self):
        return self.udpfd

    def fd(self):
        return self.udpfd.fileno()


class ServerUDPSender(UDPSender):
    def __init__(self, server_ip=''):
        super(ServerUDPSender, self).__init__()
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.bind(("", 0x4147))

    def recv(self):
        buf, addr = self.udpfd.recvfrom(BUFFER_SIZE)
        self.server_ip = addr[0]
        self.port = addr[1]
        is_command = self.cmd_control.check(buf)
        if self.debug:
            print 'recv ip:%s type:udp port:%s count:%s data:%s' % (self.server_ip, self.port, len(buf), repr(buf))
        if is_command:
            return []
        return [buf]


class ClientUDPSender(UDPSender):
    def __init__(self, server_ip=''):
        super(ClientUDPSender, self).__init__()
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.bind(("", 0))

    def recv(self):
        buf, _ = self.udpfd.recvfrom(BUFFER_SIZE)
        is_command = self.cmd_control.check(buf)
        if self.debug:
            print 'recv ip:%s type:udp port:%s count:%s data:%s' % (self.server_ip, self.port, len(buf), repr(buf))
        if is_command:
            return []
        return [buf]


if __name__ == '__main__':
    import sys, select, time

    if not sys.argv[1:]:
        sender = ServerUDPSender()
    else:
        # 预设server ip
        sender = ClientUDPSender(sys.argv[1])
    sender.debug = True
    next_sleep_time = 0.01

    while True:
        rset = select.select([sender.f()], [], [], next_sleep_time)[0]
        for r in rset:
            if r == sender.f():
                result = sender.recv()
                print result, [len(item) for item in result]
                sender.send('remote accept:' + result[0])

        data = raw_input('input data：')
        if data.isdigit():
            next_sleep_time = int(data)
            continue
        else:
            next_sleep_time = 0.01
        print u'-' * 50
        sender.send(data)
