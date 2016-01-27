#!/usr/bin/env python

import os, sys
import getopt
import icmp
import socket
import select
import time

from tun import Tun

TUN_IP = "10.1.2.2"
TUN_PEER = '10.1.2.1'
MTU = 65000


class Tunnel():
    IP_DOMAIN = 'xxxx.f3322.org'

    def __init__(self, tun_ip, tun_peer):
        self.heartbeat = 0
        self.tfd, self.tname = Tun().create_tun(tun_ip, tun_peer)
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmpfd.setblocking(0)
        self.packet = icmp.ICMPPacket()
        self.now_identity = 0xffff
        self.server_ip = ''
        self.check_heartbeat()

    def close(self):
        os.close(self.tfd)

    def check_heartbeat(self):
        try:
            self.server_ip = socket.getaddrinfo(self.IP_DOMAIN, None)[0][4][0]
            if time.time() - self.heartbeat > 3:
                self.icmpfd.sendto(self.packet.create(8, 0, self.now_identity, 0x4147, 'heartbeat'), (self.server_ip, 1))
                self.heartbeat = time.time()
            print 'send heartbeat to server:%s' % self.server_ip
        except:
            print 'send heartbeat error!'

    def run(self):
        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [], 3)[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, MTU)
                    buf = self.packet.create(8, 0, self.now_identity, 0x4147, data)
                    try:
                        print 'send ip', self.server_ip, 'length', len(data)
                        self.icmpfd.sendto(buf, (self.server_ip, 1))
                    except:
                        print 'error data len:', len(buf), buf[-10:]

                elif r == self.icmpfd:
                    buf = self.icmpfd.recv(icmp.BUFFER_SIZE)
                    data = self.packet.parse(buf, True)
                    if self.packet.seqno == 0x4147:  # true password
                        self.heartbeat = time.time()
                        os.write(self.tfd, data)
            self.check_heartbeat()


if __name__ == "__main__":
    opts = getopt.getopt(sys.argv[1:], "c:l:p:")
    for opt, optarg in opts[0]:
        if opt == "-c":
            Tunnel.IP_DOMAIN = optarg
        if opt == "-l":
            TUN_IP = optarg
        elif opt == '-p':
            TUN_PEER = optarg

    tun = Tunnel(TUN_IP, TUN_PEER)
    print "Allocated interface %s" % (tun.tname)
    try:
        tun.run()
    except KeyboardInterrupt:
        tun.close()
        sys.exit(0)
