#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015 Windpro

Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   15/6/18
Desc    :   
"""
from interface import BaseServer, BaseIoCallback, BasePacketControl, TunInfo, BaseConnection, BaseTun, BaseDhcpControl
from base import IoControl, Tun, LastUpdatedOrderedDict, AESCipher
import json
import uuid
import socket
import struct
import time
from packet import TunnelPacket
import sys


PASSWORD = 'password'
cipher = AESCipher(PASSWORD)


class DhcpControl(BaseDhcpControl):
    def __init__(self, server, start_ip='10.8.0.3', limit=100):
        """
            server占用0.1 和 0.2
        """
        self.server = server
        self.all = {}
        self._next_ip_int = socket.ntohl(struct.unpack("I",socket.inet_aton(str(start_ip)))[0]) - 2

    def next_ip_int(self):
        self._next_ip_int += 2
        return self._next_ip_int

    def new(self, session_id):
        if session_id in self.all:
            self.server.del_session(session_id)
            del self.all[session_id]
        next_ip_int = self.next_ip_int()
        me_ip = socket.inet_ntoa(struct.pack('I',socket.htonl(next_ip_int)))
        des_ip = socket.inet_ntoa(struct.pack('I',socket.htonl(next_ip_int + 1)))
        return me_ip, des_ip



class ICMPPacketIoCallback(BaseIoCallback):
    """
        从icmp中接收到数据
    """
    def __init__(self, server):
        self.server = server
        assert isinstance(self.server, BaseServer)

    def __call__(self):
        data = self.server.icmp.recv(2048)
        pk = TunnelPacket(data)
        cns = BaseConnection.connections
        l_info = (pk.session_id, pk._src)
        if l_info in cns:
            # 验证登陆
            cns[l_info].recv(pk)
        else:
            data = pk.user_data
            ip = pk.src
            if self.server.is_server:
                if data.startswith('{'):
                    info = json.loads(data)
                    if info.get('username') == 'test':
                        new_session_id = self.server.next_session_id()
                        addr, dstaddr = self.server.dhcp.new(new_session_id)
                        self.server.icmp.sendto(json.dumps({
                            "session_id": new_session_id,
                            'command_id': info.get('command_id'),
                            'ip': ip,
                            'addr': addr,
                            'dstaddr': dstaddr,
                        }))
            else:
                # 后续开发icmp打洞
                pass

class TunIoCallback(BaseIoCallback):
    """
        从tun中接收到数据
    """
    def __init__(self, source, packet_control):
        self.source = source
        assert isinstance(source, BaseTun)
        self.pc = packet_control
        assert isinstance(self.pc, BasePacketControl)

    def __call__(self):
        data = self.source.read(2048)
        self.pc.from_tun(data)

class ICMPPacketControl(BasePacketControl):
    """
        数据包管理
    """
    def __init__(self, server, type, now_id=0xffff, seqno=0x4147):
        self.server = server
        assert isinstance(self.server, BaseServer)
        self.type, self.now_id, self.seqno = type, now_id, seqno
        self.un_use_command = LastUpdatedOrderedDict(10000)

    def get_command(self, command_id):
        """
            获取未处理的命令
        """
        return self.un_use_command.pop(command_id, None)

    def from_tun(self, data):
        """
            处理来自tun的数据
        """
        session_id = None
        cn = BaseConnection.connections.get(session_id)
        ipk = TunnelPacket.create(
            _type=self.type,
            code=0,
            _id=self.now_id,
            seqno=self.seqno,
            data=data,
            session_id=session_id,
            random_info=time.time(),
        )
        data = ipk.dumps()
        cn.send(data)

    def from_internet(self, packet):
        """
            处理icmp数据包，不一定全部正确
        """
        self.now_id = packet.id
        cn = BaseConnection.connections.get(packet.session_id)
        if cn:
            self.server.tun.write(packet.user_data)

class BaseTunnel(BaseServer):
    """
        tunnel 程序入口
    """
    def __init__(self, is_server):
        self.is_server = is_server
        # new version
        if is_server:
            self.icmp_type = 0
        else:
            self.icmp_type = 8
        self.pk_control = ICMPPacketControl(self.icmp_type, self)

        self.io_control = IoControl()

        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        self.io_control.register(self.icmpfd.fileno(), ICMPPacketIoCallback(self))

    def close(self):
        self.tun.close()

    def run(self):
        self.io_control.serve_forever()

class ICMPConnection(BaseConnection):
    """
        注意：目前每一个connection一个tun
    """
    def __init__(self, server, ip):
        self.ip = ip
        self.server = server
        assert isinstance(self.server, ServerTunnel)
        if server.is_server:
            self.tun = Tun('10.8.0.1', '10.8.0.2')
            assert isinstance(self.tun, BaseTun)
            self.server.io_control.register(self.tun.fileno(), TunIoCallback(self.tun.tunfd, self.server.pk_control))
        else:
            login_info = self.login(self.server.username, self.server.password)
            self.server.client_ip = login_info['ip']
            self.tun = Tun(**login_info)
            assert isinstance(self.tun, BaseTun)
            self.server.io_control.register(self.tun.fileno(), TunIoCallback(self.tun.tunfd, self.server.pk_control))
        self.last_recv_time = None
        self.pc = server.packet_control
        assert isinstance(self.pc, BasePacketControl)

    def login(self, username, password):
        command_id = self.send_command({
            'command': 'login',
            'user': username,
            'password': password
        })
        for _ in range(60*10):
            time.sleep(0.1)
            info = self.server.pk_control.get_command(command_id)
            if info:
                return info
        raise Exception('登陆超时')

    def send_command(self, info):
        info['command_id'] = str(uuid.uuid4()).replace("-", "")
        self.server.icmpfd.sendto(json.dumps(info))
        return info['command_id']

    def send(self, data):
        self.server.icmpfd.sendto(data, (self.ip, 22))

    def close(self):
        self.server.io_control.unregister(self.tun.fileno())
        self.tun.close()

    def recv(self, packet):
        self.pc.from_internet(packet)


class ServerTunnel(BaseTunnel):
    def __init__(self):
        super(ServerTunnel, self).__init__(is_server=True)
        self._next_session_id = 0
        self.dhcp = DhcpControl(self)

    def next_session_id(self):
        self._next_session_id += 1
        if self._next_session_id >= 65500:
            raise Exception('无法接受更多用户')
        return self._next_session_id

    def del_session(self, session_id):
        for kv, cn in BaseConnection.connections.iteritems():
            sid, ip = kv
            if sid == session_id:
                cn.close()
                break


class ClientTunnel(BaseTunnel):
    def __init__(self, des_ip):
        super(ClientTunnel, self).__init__(is_server=False)
        self.des_ip = des_ip
        self.connection = ICMPConnection(self, self.des_ip)

        self.username = 'test'
        self.password = 'test'


if __name__ == '__main__':
    kwargs = dict(
        is_server=True,
    )

    if len(sys.argv) > 1:
        # client
        print 'server ip:10.8.0.2 dev:ctun finish'
        is_server = False
        t = ClientTunnel(sys.argv[1])
    else:
        # server
        print 'server ip:10.8.0.1 dev:stun finish'
        try:
            # 初始化iptabls  你可以自行编写脚本，方便自动化
            from iptables import init
            init()
        except:
            pass
        is_server = True
        t = ServerTunnel()

    try:
        t.run()
    except KeyboardInterrupt:
        t.close()
        sys.exit(0)
