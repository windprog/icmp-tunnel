#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015 Windpro

Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   15/6/21
Desc    :   
"""
import os, sys
import hashlib
import getopt
import fcntl
import time
import struct
import socket, select
import traceback
import signal
import ctypes
import binascii
import cPickle as pickle
import re
from icmp import IPPacket
from server import LastUpdatedOrderedDict, AESCipher, ICMPPacket
from socket import error as socket_error
import random

PASSWORD = "icmpudp"
SHARED_PASSWORD = hashlib.sha1(PASSWORD).digest()
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001 | 0x1000  # TUN + NO_PI

BUFFER_SIZE = 8192
MODE = 0
DEBUG = 0
PORT = 0
IFACE_IP = "10.0.0.1"
IFACE_PEER = "10.0.0.2"
MTU = 1400
TIMEOUT = 60 * 10  # seconds
RT_INTERVAL = 30  # seconds
ipstr2int = lambda x: struct.unpack('!I', socket.inet_aton(x))[0]


class BaseNode(object):
    def __init__(self):
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        self.cipher = AESCipher(PASSWORD)
        self.recv_ids = LastUpdatedOrderedDict(10000)

    def send_udp(self, data, ip, udp_port):
        self.udpfd.sendto(data, (ip, udp_port))

    def send_icmp(self, data, ip, icmp_id):
        pk = ICMPPacket.create(_type=self.icmp_code, code=0, _id=icmp_id, seqno=0x4148, data=data)
        self.icmpfd.sendto(pk.dumps(), (ip, 22))


class Server(BaseNode):
    def __init__(self, server_port=1111):
        super(Server, self).__init__()
        self.sessions = {}  # session_id: {'ip', 'type'(udp or icmp), 'udp_port', 'icmp_id', 'tunfd', 'tun_peer', 'tun_ip', 'active_time'}
        self.udpfd.bind(("", server_port))
        print 'Server listen at port', PORT
        self.icmp_code = 0

    def get_client_by_tun(self, r):
        for c in self.sessions.itervalues():
            if c['tun_fd'] == r:
                return c

    def create_tun(self):
        """For every client, we create a P2P interface for it."""
        try:
            tun_fd = os.open("/dev/net/tun", os.O_RDWR)
        except:
            tun_fd = os.open("/dev/tun", os.O_RDWR)
        if tun_fd < 0:
            raise Exception('Failed to create tun device')
        ifs = fcntl.ioctl(tun_fd, TUNSETIFF, struct.pack("16sH", "tun%d", IFF_TUN))
        tname = ifs[:16].strip("\x00")
        return {'tun_fd': tun_fd, 'tun_name': tname}

    def config_tun(self, c):
        """Set up IP address and P2P address"""
        print "Configuring interface %s with ip %s" % (c['tun_name'], c['tun_ip'])
        os.system("ifconfig %s %s dstaddr %s mtu %s up" % (c['tun_name'], c['tun_ip'], c['tun_peer'], MTU))
        try:
            from iptables import init

            init()
        except:
            pass

    def send(self, data, session_id):
        ss = self.sessions.get(session_id)
        _type = ss.get('type')
        ip = ss.get('ip')
        udp_port = ss.get('udp_port')
        icmp_id = ss.get('icmp_id')
        if _type == 'udp' and ip and udp_port:
            self.send_udp(data, ip, udp_port)
        elif _type == 'icmp' and ip and icmp_id:
            self.send_icmp(data, ip, icmp_id)
        else:
            print 'sending error no', session_id, ip, _type, 'udp', udp_port, 'icmp', icmp_id

    def send_login_success(self, _session_id):
        d = {
            'ret': 0,
            'session_id': str(_session_id)
        }
        self.send('AUTH' + pickle.dumps(d), _session_id)

    def do_login(self, data):
        if data.startswith('AUTH'):
            _input = pickle.loads(data[4:])
            # Check password
            if _input['password'] != SHARED_PASSWORD:
                return None
            # Find existing session
            for session_id, c in self.sessions.iteritems():
                if c['tun_peer'] == _input['tun_ip'] and c['tun_ip'] == _input['tun_peer']:
                    print '[%s] Keep alive tun %s, %s -> %s for %s %s:%s' % (
                        time.ctime(), c['tun_name'], c['tun_ip'], c['tun_peer'],
                        c.get('type', ''), c.get('ip', ''),
                        c.get('udp_port', '') if c.get('type') == 'udp' else c.get('icmp_id', ''))
                    return c
            # Create new client session
            c = {
                'tun_peer': _input['tun_ip'],
                'tun_ip': _input['tun_peer'],
                'active_time': time.time(),
            }
            c.update(self.create_tun())
            self.config_tun(c)
            session_id = random.randint(0, 4294967295)  # struct 中 L 最大为：4294967295
            while session_id in self.sessions:
                session_id = random.randint(0, 4294967295)
            self.sessions[session_id] = c
            c['session_id'] = session_id
            print '[%s] Created new tun %s, %s -> %s' % (
                time.ctime(), c['tun_name'], c['tun_ip'], c['tun_peer'])
            return c

    def parse_recv(self, _type):
        if _type == 'udp':
            data, addr = self.udpfd.recvfrom(BUFFER_SIZE)
            ip, port_or_id = addr

            def send_login_error():
                self.send_udp('AUTH', ip, port_or_id)
        else:
            buf = self.icmpfd.recv(2048)
            packet = ICMPPacket(buf)
            if packet.seqno != 0x4148:
                return
            data = packet.data
            ip = socket.inet_ntoa(packet.src)
            port_or_id = packet.id

            def send_login_error():
                self.send_icmp('AUTH', ip, port_or_id)
        if data.startswith('AUTH'):
            session = self.do_login(data)
            if session:
                session['ip'] = ip
                if _type == 'udp':
                    session['udp_port'] = port_or_id
                else:
                    session['icmp_id'] = port_or_id
                session['type'] = _type
                self.send_login_success(session['session_id'])
            else:
                print 'login error %s %s:%s' % (_type, ip, port_or_id)
                send_login_error()
        else:
            if data and len(data) < 7:
                return
            session_id, chksum = struct.unpack('!LH', data[-6:])
            c = self.sessions.get(session_id)  # 等待修改，可改成ip + session_id的方式防止劫持
            if not c:
                print 'accept not login packet from %s %s:%s' % (_type, ip, port_or_id)
                return
            if c['type'] != _type or c['ip'] != ip or \
                    ((_type == 'udp' and c['udp_port'] != port_or_id) or (
                            _type == 'icmp' and c['icmp_id'] != port_or_id)):
                print 'updating %s: %s %s:%s to %s %s:%s' % (
                    session_id, c['type'], c['ip'], c['udp_port'], _type, ip, port_or_id)
                c['type'] = _type
                c['ip'] = ip
                if _type == 'udp':
                    c['udp_port'] = port_or_id
                else:
                    c['icmp_id'] = port_or_id
            c['active_time'] = time.time()
            if chksum in self.recv_ids:
                if time.time() - self.recv_ids[chksum] < 1:
                    # 再次在1秒内接到一样id的数据包丢弃,后续需要通过动态计算延时来更改
                    return
            self.recv_ids[chksum] = time.time()
            data = self.cipher.decrypt(data[:-6])
            try:
                os.write(c['tun_fd'], data)
            except:
                print 'error packet from %s %s:%s' % (_type, ip, port_or_id)

    def run(self):
        """ Server packets loop """
        while True:
            fds = [x['tun_fd'] for x in self.sessions.itervalues()]
            fds.append(self.udpfd)
            fds.append(self.icmpfd)
            rset = select.select(fds, [], [], 1)[0]
            for r in rset:
                if r == self.udpfd:
                    self.parse_recv('udp')
                elif r == self.icmpfd:
                    self.parse_recv('icmp')
                else:
                    c = self.get_client_by_tun(r)
                    data = os.read(r, BUFFER_SIZE)
                    data = self.cipher.encrypt(data)
                    ex_str = struct.pack('!LH', c['session_id'], IPPacket.checksum(
                        data + struct.pack('!d', time.time())
                    ))
                    try:
                        data += ex_str
                        for _ in xrange(2):
                            self.send(data, c['session_id'])
                    except:
                        pass


class Client(BaseNode):
    def __init__(self, server_ip, server_port, tun_ip, tun_peer, action='udp'):
        super(Client, self).__init__()
        self.icmp_code = 8
        self.session_id = None
        self.password = PASSWORD
        self.logged = False
        self.server_ip = server_ip
        self.server_port = server_port
        self.tun_ip = tun_ip
        self.tun_peer = tun_peer
        self.session = {
            'tun_ip': tun_ip,
            'tun_peer': tun_peer,
            'type': action,
            'icmp_id': 0xffff,
        }
        self.session.update(self.create_tun())
        self.config_tun(self.session)
        self.tunfd = self.session['tun_fd']
        self.udpfd.bind(("", 0))
        # runtime
        self.logged = False
        self.log_time = 0
        self.active_time = time.time()
        self.login_success_time = time.time()
        self.do_login()
        print '[%s] Created client %s, %s -> %s for udp %s:%s' % (
            time.ctime(), self.session['tun_name'], self.session['tun_ip'], self.session['tun_peer'],
            server_ip, server_port)
        try:
            if sys.platform == 'darwin':
                from iptables import osx_client_init

                osx_client_init()
        except:
            pass

    def create_tun(self):
        """ Every client needs a tun interface """
        if sys.platform == 'darwin':
            for i in xrange(10):
                try:
                    tname = 'tun%s' % i
                    tun_fd = os.open('/dev/%s' % tname, os.O_RDWR)
                    return {'tun_fd': tun_fd, 'tun_name': tname}
                except:
                    pass
        else:
            try:
                tun_fd = os.open("/dev/net/tun", os.O_RDWR)
            except:
                tun_fd = os.open("/dev/tun", os.O_RDWR)
            ifs = fcntl.ioctl(tun_fd, TUNSETIFF, struct.pack("16sH", "t%d", IFF_TUN))
            tname = ifs[:16].strip("\x00")
            return {'tun_fd': tun_fd, 'tun_name': tname}
        raise Exception('无法创建网卡')

    def config_tun(self, c):
        """
            Set up local ip and peer ip
            支持mac
        """
        print "Configuring interface %s with ip %s" % (c['tun_name'], c['tun_ip'])
        if sys.platform == 'darwin':
            os.system("ifconfig %s %s/32 %s mtu %s up" % (c['tun_name'], c['tun_ip'], c['tun_peer'], MTU))
        else:
            os.system("ifconfig %s %s dstaddr %s mtu %s up" % (c['tun_name'], c['tun_ip'], c['tun_peer'], MTU))

    def parse_login_result(self, data):
        """ Check login results """
        self.logged = False
        try:
            d = pickle.loads(data[4:])
            if d['ret'] == 0:
                self.logged = True
                self.session_id = int(d['session_id'])
                self.login_success_time = time.time()
                print "session_id:%s Logged in server succefully!" % self.session_id
                return
        except:
            pass
        print "Logged failed"

    def send(self, data):
        ss = self.session
        _type = ss.get('type')
        ip = self.server_ip
        udp_port = self.server_port
        icmp_id = ss.get('icmp_id')
        if _type == 'udp' and ip and udp_port:
            self.send_udp(data, ip, udp_port)
        elif _type == 'icmp' and ip and icmp_id:
            self.send_icmp(data, ip, icmp_id)
        else:
            print 'sending error no', ip, _type, 'udp', udp_port, 'icmp', icmp_id

    def do_login(self):
        d = {
            'password': SHARED_PASSWORD,
            'tun_ip': IFACE_IP,
            'tun_peer': IFACE_PEER,
        }
        self.send('AUTH' + pickle.dumps(d))
        self.log_time = time.time()
        print "[%s] Do login %s %s:%s" % (time.ctime(), self.session.get('type', ''), self.server_ip,
                                          self.server_port if self.session.get('type', '') else self.session['icmp_id'])

    def parse_recv(self, _type):
        if _type == 'udp':
            data, addr = self.udpfd.recvfrom(BUFFER_SIZE)
        else:
            buf = self.icmpfd.recv(2048)
            packet = ICMPPacket(buf)
            if packet.seqno != 0x4148:
                return
            data = packet.data

        if data.startswith("AUTH"):
            self.parse_login_result(data)
        else:
            if data and len(data) < 7:
                return
            session_id, chksum = struct.unpack('!LH', data[-6:])
            if chksum in self.recv_ids:
                if time.time() - self.recv_ids[chksum] < 1:
                    # 再次在1秒内接到一样id的数据包丢弃,后续需要通过动态计算延时来更改
                    return
            self.recv_ids[chksum] = time.time()
            os.write(self.tunfd, self.cipher.decrypt(data[:-6]))
            self.active_time = time.time()

    def run(self):
        """ Client network loop """

        while True:
            try:
                now = time.time()
                if now - self.active_time > 60:  # If no packets within 60 secs, Force relogin, NAT problem, Just keepalive
                    self.active_time = now
                    self.logged = False
                    if now - self.login_success_time > 180:
                        self.session['type'] = 'icmp'
                if not self.logged and now - self.log_time > 2.:
                    self.do_login()
                rset = select.select([self.udpfd, self.icmpfd, self.tunfd], [], [], 1)[0]
                for r in rset:
                    if r == self.tunfd:
                        data = os.read(self.tunfd, BUFFER_SIZE)
                        data = self.cipher.encrypt(data)
                        if not self.session_id:
                            print '还未登陆，无法发送网卡数据'
                            continue
                        ex_str = struct.pack('!LH', self.session_id, IPPacket.checksum(
                            data + struct.pack('!d', time.time())
                        ))
                        # dst = struct.unpack('!I', data[20:24])[0]
                        # addr = self.get_router_by_dst(dst)
                        # print 'new packet from:%s' % socket.inet_ntoa(data[20:24])

                        try:
                            data += ex_str
                            for _ in xrange(2):
                                self.send(data)
                        except:
                            pass
                    elif r == self.udpfd:
                        self.parse_recv('udp')
                    elif r == self.icmpfd:
                        self.parse_recv('icmp')
            except socket_error, e:
                print e.errno, e
                if e.errno == 50 or e.errno == 51:
                    time.sleep(1)


def usage(status=0):
    print "Usage: %s [-s port|-c serverip] [-hd] [-l localip] [-a udp or icmp]" % (sys.argv[0])
    sys.exit(status)


def on_exit(no, info):
    raise Exception("TERM signal caught!")


if __name__ == "__main__":
    opts = getopt.getopt(sys.argv[1:], "s:c:l:p:a:hd")
    action = 'udp'
    for opt, optarg in opts[0]:
        if opt == "-h":
            usage()
        elif opt == "-d":
            DEBUG += 1
        elif opt == "-s":
            MODE = 1
            PORT = int(optarg)
        elif opt == "-c":
            MODE = 2
            IP, PORT = optarg.split(",")
            IP = socket.gethostbyname(IP)
            PORT = int(PORT)
        elif opt == "-l":
            IFACE_IP = optarg
        elif opt == "-p":
            IFACE_PEER = optarg
        elif opt == '-a':
            action = 'icmp'

    if MODE == 0 or PORT == 0:
        usage(1)

    signal.signal(signal.SIGTERM, on_exit)
    if MODE == 1:
        tun = Server(PORT)
    else:
        tun = Client(server_ip=IP, server_port=PORT, tun_ip=IFACE_IP, tun_peer=IFACE_PEER, action=action)
    try:
        tun.run()
    except KeyboardInterrupt:
        pass
    except:
        print traceback.format_exc()
    finally:
        # Cleanup something.
        pass
