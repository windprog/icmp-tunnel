#!/usr/bin/python
#coding: utf8
'''
    UDP Tunnel VPN
    Xiaoxia (xiaoxia@xiaoxia.org)
    First version: 2012-2-21
    Updated: 2014-6-3 P2P network packet exchange
    Updated: 2015-6-2 for mac
'''

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

SHARED_PASSWORD = hashlib.sha1("feiwu").digest()
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001 | 0x1000 #TUN + NO_PI

BUFFER_SIZE = 8192
MODE = 0
DEBUG = 0
PORT = 0
IFACE_IP = "10.0.0.1"
IFACE_PEER = "10.0.0.2"
MTU = 1400
TIMEOUT = 60*10 # seconds
RT_INTERVAL = 30 # seconds
ipstr2int = lambda x: struct.unpack('!I', socket.inet_aton(x))[0]

class Server():
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
        return tun_fd, tname

    def config_tun(self, tun_ip, tun_peer, tun_name):
        """Set up IP address and P2P address"""
        print "Configuring interface %s with ip %s" % (tun_name, tun_ip)
        os.system("ifconfig %s %s dstaddr %s mtu %s up" % (tun_name, tun_ip, tun_peer, MTU))


    def run(self):
        """ Server packets loop """
        global PORT
        self.tun_fd, self.tname = self.create_tun()
        self.config_tun(IFACE_IP, IFACE_PEER, self.tname)
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.bind(("", PORT))
        self.sessions = []
        self.rt_sync_time = 0
        self.addr = None

        print 'Server listen at port', PORT
        while True:
            fds = [self.tun_fd]
            fds.append(self.udpfd)
            rset = select.select(fds, [], [], 1)[0]
            for r in rset:
                if r == self.udpfd:
                    data, addr = self.udpfd.recvfrom(BUFFER_SIZE)
                    self.addr = addr
                    os.write(self.tun_fd, data)
                else:
                    data = os.read(r, BUFFER_SIZE)
                    try:
                        self.udpfd.sendto(data, self.addr)
                    except: pass

class Client():
    def create_tun(self):
        """ Every client needs a tun interface """
        if sys.platform == 'darwin':
            for i in xrange(10):
                try:
                    tname = 'tun%s' % i
                    tun_fd = os.open('/dev/%s' % tname, os.O_RDWR)
                    break
                except:
                    continue
        else:
            try:
                tun_fd = os.open("/dev/net/tun", os.O_RDWR)
            except:
                tun_fd = os.open("/dev/tun", os.O_RDWR)
            ifs = fcntl.ioctl(tun_fd, TUNSETIFF, struct.pack("16sH", "t%d", IFF_TUN))
            tname = ifs[:16].strip("\x00")

        return tun_fd, tname

    def config_tun(self, tun_ip, tun_peer, tun_name):
        """ Set up local ip and peer ip """
        print "Configuring interface %s with ip %s" % (tun_name, tun_ip)
        os.system("ifconfig %s %s/32 %s mtu %s up" % (tun_name, tun_ip, tun_peer, MTU))

    def run(self):
        """ Client network loop """
        global PORT
        self.tun_fd, self.tname = self.create_tun()
        self.config_tun(IFACE_IP, IFACE_PEER, self.tname)
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.bind(("", 0))
        self.logged = False
        self.log_time = 0
        self.active_time = 0
        self.addr = (IP, PORT)
        self.rt_table = [(0, 0, (IP, PORT))]
        print '[%s] Created client %s, %s -> %s for %s' % (time.ctime(), self.tname, IFACE_IP, IFACE_PEER, self.addr)

        while True:
            rset = select.select([self.udpfd, self.tun_fd], [], [], 1)[0]
            for r in rset:
                if r == self.tun_fd:
                    data = os.read(self.tun_fd, BUFFER_SIZE)
                    self.udpfd.sendto(data, self.addr)
                elif r == self.udpfd:
                    data, src = self.udpfd.recvfrom(BUFFER_SIZE)
                    os.write(self.tun_fd, data)

def usage(status = 0):
    print "Usage: %s [-s port|-c serverip] [-hd] [-l localip]" % (sys.argv[0])
    sys.exit(status)

def on_exit(no, info):
    raise Exception("TERM signal caught!")

if __name__=="__main__":
    opts = getopt.getopt(sys.argv[1:],"s:c:l:p:hd")
    for opt,optarg in opts[0]:
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

    if MODE == 0 or PORT == 0:
        usage(1)

    signal.signal(signal.SIGTERM, on_exit)
    if MODE == 1:
        tun = Server()
    else:
        tun = Client()
    try:
        tun.run()
    except KeyboardInterrupt:
        pass
    except:
        print traceback.format_exc()
    finally:
        # Cleanup something.
        pass


