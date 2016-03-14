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
import os
from random import randint
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
        self.icmp_type = None
        self.cmd_control = CommandControl(self)
        self.debug = False

    def send(self, data):
        pending_list = self.pending_list
        self.pending_list = []
        data_list = pending_list + [data]
        icmp_code = 0
        result = TunnelPacket.create(
            self.icmp_type, icmp_code, self.now_identity, 0x4147, data_list=data_list, garbage='').dumps()
        if self.debug:
            print 'send ip:%s type:%s code:%s identity:%s seqno:%s total_count:%s data:%s' % (
                self.server_ip, self.icmp_type, icmp_code, self.now_identity, 0x4147, len(result) - 8, repr(data_list))
        try:
            ret = self.icmpfd.sendto(result, (self.server_ip, 1))
        except socket.error, e:
            print 'socket error', e.errno

    def recv(self):
        buf = self.icmpfd.recv(BUFFER_SIZE)
        packet = TunnelPacket(buf)
        if self.debug:
            print 'recv from_ip:%s type:%s code:%s identity:%s seqno:%s total_count:%s data:%s' % (
                packet.src, packet.type, packet.code, packet.id, packet.seqno, len(buf), repr(packet.data_list))
        target_remote_icmp_type = ServerICMPSender.ICMP_TYPE if self.icmp_type == ClientICMPSender.ICMP_TYPE else \
            ClientICMPSender.ICMP_TYPE
        if packet.seqno != 0x4147 or packet.type != target_remote_icmp_type:
            # 非正常数据
            return []
        self.now_identity = packet.id
        self.server_ip = packet.src
        data_list = packet.data_list
        is_command = False
        for one_data in data_list:
            is_command = self.cmd_control.check(one_data)
        if is_command:
            return []
        return data_list

    def f(self):
        return self.icmpfd

    def fd(self):
        return self.icmpfd.fileno()


class ServerICMPSender(ICMPSender):
    ICMP_TYPE = 18

    def __init__(self, server_ip=''):
        super(ServerICMPSender, self).__init__()
        self.icmp_type = self.ICMP_TYPE


class ClientICMPSender(ICMPSender):
    ICMP_TYPE = 17

    def __init__(self, server_ip=''):
        # check_heartbeat 会设置server_ip
        super(ClientICMPSender, self).__init__(server_ip=server_ip)
        self.icmp_type = self.ICMP_TYPE


if __name__ == '__main__':
    import sys, select, time

    if not sys.argv[1:]:
        sender = ServerICMPSender()
    else:
        # 预设server ip
        sender = ClientICMPSender(sys.argv[1])
    sender.debug = True
    next_sleep_time = 0.01

    stop = False


    def print_result():
        try:
            while not stop:
                rset = select.select([sender.f()], [], [], next_sleep_time)[0]
                for r in rset:
                    if r == sender.f():
                        result = sender.recv()
                        # print repr(result), [len(item) for item in result]
        except KeyboardInterrupt:
            pass
        except:
            print traceback.format_exc()
        finally:
            # Cleanup something.
            pass


    import threading

    thread = threading.Thread(target=print_result)
    thread.start()

    try:
        while True:
            data = raw_input('input data：')
            if not data:
                stop = True
                break
            if data.isdigit():
                next_sleep_time = int(data)
                continue
            else:
                next_sleep_time = 0.01
            print u'-' * 50
            sender.send(data)
    except KeyboardInterrupt:
        pass
    except:
        print traceback.format_exc()
    finally:
        # Cleanup something.
        pass
