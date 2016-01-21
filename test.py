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
from tun import Tun

BUFFER_SIZE = 8192
MODE = 0
PORT = 0
IFACE_IP = "10.0.0.1"
IFACE_PEER = "10.0.0.2"

class Server():
    """
    python test.py  -s 1111 -l 192.168.128.1
    """
    def run(self):
        """ Server packets loop """
        global PORT
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.bind(("", PORT))
        self.sessions = []
        self.rt_sync_time = 0
        now_addr = ('0.0.0.0', 1)
        tun_fd, _ = Tun().create_tun(IFACE_IP, IFACE_PEER)

        print 'Server listen at port', PORT
        while True:
            rset = select.select([self.udpfd, tun_fd], [], [], 1)[0]
            for r in rset:
                if r == self.udpfd:
                    data, now_addr = self.udpfd.recvfrom(BUFFER_SIZE)
                    os.write(tun_fd, data)
                else:
                    data = os.read(r, BUFFER_SIZE)
                    try:
                        self.udpfd.sendto(data, now_addr)
                    except: pass

class Client():
    """
    python test.py -c 192.168.35.145,1111 -l 192.168.128.2 -p 192.168.128.1
    """
    def run(self):
        """ Client network loop """
        global PORT
        tun_fd, tname = Tun().create_tun(IFACE_IP, IFACE_PEER)
        self.tunfd = tun_fd
        self.udpfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udpfd.bind(("", 0))
        self.addr = (IP, PORT)
        print '[%s] Created client %s, %s -> %s for %s' % (time.ctime(), tname, "10.0.0.2", "10.0.0.1", self.addr)

        while True:
            rset = select.select([self.udpfd, self.tunfd], [], [], 1)[0]
            for r in rset:
                if r == self.tunfd:
                    data = os.read(self.tunfd, BUFFER_SIZE)
                    self.udpfd.sendto(data, self.addr)
                elif r == self.udpfd:
                    data, src = self.udpfd.recvfrom(BUFFER_SIZE)
                    os.write(self.tunfd, data)

def usage(status = 0):
    print "Usage: %s [-s port|-c serverip] [-hd] [-l localip]" % (sys.argv[0])
    sys.exit(status)

def on_exit(no, info):
    raise Exception("TERM signal caught!")

if __name__=="__main__":
    opts = getopt.getopt(sys.argv[1:],"s:c:l:p:h")
    for opt,optarg in opts[0]:
        if opt == "-h":
            usage()
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


