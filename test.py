#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015 netease

Author  :   windpro
E-mail  :   zzn1889@corp.netease.com
Date    :   15/6/19
Desc    :   
"""
from unittest import TestCase
from server import PacketControl, TunnelPacket, IPPacket, cipher
from server import CLIENT_ICMP_TYPE, SERVER_ICMP_TYPE
import socket

SERVER_IP = '8.8.8.8'
CLIENT_IP = '7.7.7.7'

class MockServerTunnel(object):
    def __init__(self):
        self.is_server = False

        now_icmp_identity = 0xffff
        DesIp = 'localhost'

        self.recv_pk = TunnelPacket.create(
            _type=8,
            code=0,
            _id=now_icmp_identity,
            seqno=0x4147,
            tunnel_id=0,  # 当前的tunnel id
            data='some result',
            command_id=0,  # 更新tunnel id
        )
        ip_recv_data = 'x'*12 + socket.inet_aton(SERVER_IP) + socket.inet_aton(CLIENT_IP)
        IPPacket.loads(self.recv_pk, ip_recv_data)
        self.recv_data = ip_recv_data + self.recv_pk.dumps()
        assert len(self.recv_data) == 20 + 8 + 1 + 4 + len(cipher.encrypt('some result'))

        class obj(object):
            def __init__(self):
                pass

        self.icmpfd = obj()
        setattr(self.icmpfd, 'recv', lambda e: self.recv_data)


class ServerTestCase(TestCase):
    def setUp(self):
        self.ctl = PacketControl(MockServerTunnel())

    def test_success_recv(self):
        self.assertTrue(self.ctl.recv() == 'some result')