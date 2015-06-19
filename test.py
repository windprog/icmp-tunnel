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
    def __init__(self, testcase):
        self.testcase = testcase
        self.is_server = True
        self.icmp_type = 0

        self.now_icmp_identity = 0xffff
        self.DesIp = 'localhost'

        class obj(object):
            def __init__(self):
                pass

        self.icmpfd = obj()
        setattr(self.icmpfd, 'recv', lambda e: self.get_recv_data())

        def sendto(_str, ad):
            ip, port = ad
            pre = 'x'*12 + socket.inet_aton(CLIENT_IP if ip == SERVER_IP else SERVER_IP) + socket.inet_aton(ip)
            pk = TunnelPacket(pre + _str)
            assert pk.data == 'some result' or 'server' in pk.data
        setattr(self.icmpfd, 'sendto', lambda _str, ad: sendto(_str, ad))

    def get_recv_data(self):
        self.recv_pk = TunnelPacket.create(
            _type=8,
            code=0,
            _id=self.now_icmp_identity,
            seqno=0x4147,
            tunnel_id=self.testcase.tunnel_id,  # 当前的tunnel id
            data='some result',
            command_id=0,  # 更新tunnel id
        )
        ip_recv_data = 'x'*12 + socket.inet_aton(SERVER_IP) + socket.inet_aton(CLIENT_IP)
        IPPacket.loads(self.recv_pk, ip_recv_data)
        recv_data = ip_recv_data + self.recv_pk.dumps()
        assert len(recv_data) == 20 + 8 + 1 + 4 + len(cipher.encrypt('some result'))
        return recv_data


class ServerTestCase(TestCase):
    def setUp(self):
        self.server_ctl = PacketControl(MockServerTunnel(self))
        # self.client_ctl = PacketControl(MockClientTunnel())

    def test_success_recv(self):
        self.tunnel_id = 1
        self.assertTrue(self.server_ctl.recv() == 'some result')
        self.assertTrue(self.server_ctl.recv() is None)
        self.tunnel_id = 2
        self.assertTrue(self.server_ctl.recv() == 'some result')

        self.server_ctl.send('some result')

