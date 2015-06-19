#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015 netease

Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   15/6/18
Desc    :   
"""
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import json
import random
import select
import socket
import struct
import sys
import time
from icmp import ICMPPacket, IPPacket
import sys
import copy
try:
    import pytun
except:
    pass

CLIENT_ICMP_TYPE = 8
SERVER_ICMP_TYPE = 0
PASSWORD = 'password'


def tun_setup(is_server):
    tun = None
    if is_server == True:
        tun = pytun.TunTapDevice("stun")
        tun.addr = "10.8.0.1"
        tun.dstaddr = "10.8.0.2"
    else:
        tun = pytun.TunTapDevice("ctun")
        tun.addr = "10.8.0.2"
        tun.dstaddr = "10.8.0.1"
    tun.netmask = "255.255.255.0"
    tun.mtu = 1300
    tun.up()
    return tun


class AESCipher:
    def __init__(self, key):
        self.BS = 16
        h = SHA256.new()
        h.update(self.pad(key))
        h.update(h.hexdigest())
        h.update(h.hexdigest())
        h.update(h.hexdigest())
        self.key = h.hexdigest()[:16]

    def pad(self, raw):
        # two bytes length,+padded data
        lenbytes = struct.pack('<H', len(raw))
        padding = 'x' * (self.BS - (len(raw) + 2) % self.BS)
        return lenbytes + raw + padding

    def unpad(self, data):
        datalen = struct.unpack('<H', data[:2])[0]
        return data[2:2 + datalen]

    def encrypt(self, raw):
        ret = None
        try:
            raw = self.pad(raw)
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            ret = iv + cipher.encrypt(raw)
        except:
            print "Encrypt error %s" % sys.exc_info()[0]
            ret = None
        return ret

    def decrypt(self, enc):
        ret = None
        try:
            iv = enc[:AES.block_size]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            ret = self.unpad(cipher.decrypt(enc[AES.block_size:]))
        except:
            print "Decrypt error %s" % sys.exc_info()[0]
            ret = None
        return ret


cipher = AESCipher(PASSWORD)


class TunnelPacket(ICMPPacket):
    def __init__(self, buf=None):
        # 载入二进制数据或者创建空对象
        self.tunnel_id = None
        self.command_id = None
        super(TunnelPacket, self).__init__(buf)

    def loads(self, buf):
        # 载入二进制数据
        IPPacket.loads(self, buf)
        # self.tunnel_id为原来data字段的头两个字节
        self.type, self.code, self.chksum, self.id, self.seqno, self.command_id, self.tunnel_id = struct.unpack("!BBHHHBL", buf[20:33])
        # 从网卡中获取的数据
        self._data = buf[33:]

    # 当command_id==0时 始终让_data为加密数据
    data = property(lambda self: self.get_data(), lambda self, data: self.set_data(data))

    def get_data(self):
        if self.command_id == 0:
            return cipher.decrypt(self._data)
        else:
            return self._data

    def set_data(self, data):
        if self.command_id == 0:
            self._data = cipher.encrypt(data)
        else:
            self._data = data

    @classmethod
    def create(cls, _type, code, _id, seqno, tunnel_id, data, command_id=0):
        # 创建对象
        pk = cls()
        pk.type, pk.code, pk.id, pk.seqno, pk.tunnel_id, pk.command_id = \
            _type, code, _id, seqno, tunnel_id, command_id
        # 当command_id==0时 自动加密
        pk.data = data
        return pk

    def dumps(self):
        packfmt = "!BBHHHBL%ss" % (len(self._data))
        args = [self.type, self.code, 0, self.id, self.seqno, self.command_id, self.tunnel_id, self._data]
        args[2] = IPPacket.checksum(struct.pack(packfmt, *args))
        return struct.pack(packfmt, *args)


class PacketControl(object):
    MAX_RECV_TABLE = 100000

    def __init__(self, tunnel):
        self.tunnel = tunnel
        self.local_tunnel_id = long(0)
        self.remote_tunnel_id = long(0)  # 3秒更新一次
        self.recv_ids = []

        self.last_update_tunnel = None

        self.max_packet_count_peer_sec = (1024*1024*1000 / 8) / 1000  # "每个数据包1000字节 跑满千兆网卡" 每秒 数据包数

        self.COMMAND = {
            0: self.parse_data,  # 已加密的正常数据
            1: self.parse_update_tunnel_id,
        }

    def get_send_id(self):
        # 获取自增id, 第一次发出为1
        self.local_tunnel_id += 1
        if self.local_tunnel_id >= sys.maxint:
            self.local_tunnel_id = long(1)
        return self.local_tunnel_id

    def send_update_tunnel_id(self):
        cm = 'server' if self.tunnel.is_server else 'client'
        ipk = TunnelPacket.create(
            _type=self.tunnel.icmp_type,
            code=0,
            _id=self.tunnel.now_icmp_identity,
            seqno=0x4147,
            tunnel_id=0,  # 这个随意一个数字都可以，在这里只是占位
            data=",".join([str(self.local_tunnel_id), cm]),
            command_id=1,  # 更新tunnel id
        )
        self.send_pk(ipk)

    def send_pk(self, ipk):
        data = ipk.dumps()
        # debug
        p_data = copy.copy(ipk.data)
        try:
            self.tunnel.icmpfd.sendto(data, (self.tunnel.DesIp, 22))
        except:
            self.tunnel.icmpfd.close()
            self.tunnel.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            try:
                self.tunnel.icmpfd.sendto(data, (self.tunnel.DesIp, 22))
            except:
                print 'send command_id:%s len:%s content:%s fail' % (ipk.command_id, len(p_data), p_data[:20].replace('\n', ''))
                return
        print 'send command_id:%s len:%s content:%s success' % (p_data, len(p_data), p_data[:20].replace('\n', ''))

    def send(self, buf):
        print 'accept data from tun len:%s' % len(buf)
        if not self.last_update_tunnel or (time.time() - self.last_update_tunnel) >= 3.0:
            # 第一次运行或者距离上一次发送大于等于3秒，发送本地tunnel id
            print 'what the fuck to send update'
            self.send_update_tunnel_id()
            self.last_update_tunnel = time.time()

        if buf is None:
            return
        ipk = TunnelPacket.create(
            _type=self.tunnel.icmp_type,
            code=0,
            _id=self.tunnel.now_icmp_identity,
            seqno=0x4147,
            tunnel_id=self.get_send_id(), # 当前的tunnel id
            data=buf,
            command_id=0,  # 更新tunnel id
        )
        self.send_pk(ipk)

    def parse_data(self, packet):
        assert isinstance(packet, TunnelPacket)
        data = packet.data
        if not data:
            print '无法解密或者无数据'
            return None
        if abs(packet.tunnel_id - self.remote_tunnel_id) > self.max_packet_count_peer_sec:
            # 错误的数据包
            print '错误的数据包'
            return None
        if packet.tunnel_id not in self.recv_ids:
            if len(self.recv_ids) > self.MAX_RECV_TABLE:
                self.recv_ids.pop(0)
            self.recv_ids.append(packet.tunnel_id)
            # debug
            p_data = copy.copy(packet.data)
            print 'write to command_id:%s len:%s content:%s' % (packet.command_id, len(p_data), p_data[:10].replace('\n', ''))
            return data
        else:
            return None

    def parse_update_tunnel_id(self, packet):
        assert isinstance(packet, TunnelPacket)
        try:
            print 'parse_update_tunnel_id:', packet.data
            self.remote_tunnel_id = long(packet.data.split(',')[0])
        except:
            pass

    def recv(self):
        buf = self.tunnel.icmpfd.recv(2048)
        # debug
        old_buf = copy.deepcopy(buf)
        print 'accept data from internet len:%s' % len(buf)
        packet = TunnelPacket(buf)
        if packet.seqno != 0x4147:  # True packet
            return None

        # 维持icmp 通道
        self.tunnel.now_icmp_identity = packet.id
        if self.tunnel.is_server:
            des_ip = packet.src
            self.tunnel.DesIp = des_ip

        # debug
        data = copy.copy(packet.data)
        print 'recv command_id:%s len:%s content:%s' % (packet.command_id, len(data), data[:10].replace('\n', ''))
        callback = self.COMMAND.get(packet.command_id)
        if callback:
            return callback(packet)
        else:
            assert old_buf == buf
            return cipher.decrypt(buf[28:])


class Tunnel(object):
    def __init__(self, is_server, des_ip=None):
        self.is_server = is_server
        self.DesIp = des_ip

        self.epoll = select.epoll()

        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        self.epoll.register(self.icmpfd.fileno(), select.EPOLLIN)
        self.tunfd = self.get_tun()
        self.epoll.register(self.tunfd.fileno(), select.EPOLLIN)

        self.now_icmp_identity = 0xffff

        self.control = PacketControl(self)
        if is_server:
            self.icmp_type = SERVER_ICMP_TYPE
        else:
            self.icmp_type = CLIENT_ICMP_TYPE
        if is_server:
            print 'server ip:10.8.0.1 dev:stun finish'
            try:
                # 初始化iptabls  你可以自行编写脚本，方便自动化
                from iptables import init
                init()
            except:
                pass
        else:
            print 'server ip:10.8.0.2 dev:ctun finish'

    def get_tun(self):
        return tun_setup(self.is_server)

    def close(self):
        self.tunfd.close()

    def run(self):
        while True:
            events = self.epoll.poll(30)
            if len(events) == 0:
                continue
            for fileno, event in events:
                try:
                    # 保证持续运行
                    if fileno == self.tunfd.fileno():
                        print 'new'
                        buf = self.tunfd.read(2048)
                        self.control.send(buf)
                    elif fileno == self.icmpfd.fileno():
                        data = self.control.recv()
                        if data:
                            # 写入网卡
                            print 'write tun'
                            self.tunfd.write(data)
                except Exception, e:
                    print e


if __name__ == '__main__':
    kwargs = dict(
        is_server=True,
    )
    if len(sys.argv) > 1:
        # client
        kwargs['is_server'] = False
        kwargs['des_ip'] = sys.argv[1]
    t = Tunnel(**kwargs)
    try:
        t.run()
    except KeyboardInterrupt:
        t.close()
        sys.exit(0)
