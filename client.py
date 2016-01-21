#!/usr/bin/env python

import os, sys
import getopt
import fcntl
import icmp
import struct
import socket
import select
from tun import Tun

TUN_IP = "10.1.2.2"
TUN_PEER = '10.1.2.1'
MTU = 65000


class Tunnel():
    IP_DOMAIN = 'xxxx.f3322.org'

    def create(self, tun_ip, tun_peer):
        self.tfd, self.tname = Tun().create_tun(tun_ip, tun_peer)

    def close(self):
        os.close(self.tfd)

    def connect(self):
        self.server_ip = socket.getaddrinfo(self.IP_DOMAIN, None)[0][4][0]

    def run(self):
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmpfd.setblocking(0)
        self.connect()
        packet = icmp.ICMPPacket()

        now_identity = 0xffff

        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [], 3)[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, MTU)
                    # Client
                    # NowIdentity += 1
                    # NowIdentity %= 65535
                    # buf = packet.createByClient(NowIdentity,0x4147, data)
                    buf = packet.create(8, 0, now_identity, 0x4147, data)
                    try:
                        print 'send ip', self.server_ip, 'length', len(data)
                        self.icmpfd.sendto(buf, (self.server_ip, 1))
                    except:
                        print 'error data len:', len(buf), buf[-10:]

                elif r == self.icmpfd:
                    buf = self.icmpfd.recv(icmp.BUFFER_SIZE)
                    data = packet.parse(buf, True)
                    if packet.seqno == 0x4147:  # true password
                        # Client
                        print 'writing ,', len(data)
                        os.write(self.tfd, data)
            self.connect()


if __name__ == "__main__":
    opts = getopt.getopt(sys.argv[1:], "s:c:l:hd")
    for opt, optarg in opts[0]:
        if opt == "-c":
            Tunnel.IP_DOMAIN = optarg
        if opt == "-l":
            TUN_IP = optarg
        elif opt == '-p':
            TUN_PEER = optarg

    tun = Tunnel()
    tun.create(TUN_IP, TUN_PEER)
    print "Allocated interface %s" % (tun.tname)
    try:
        tun.run()
    except KeyboardInterrupt:
        tun.close()
        sys.exit(0)
