#!/usr/bin/env python

import os, sys
import getopt
import icmp
import socket
import select
import time

from tun import Tun

TUN_IP = "10.1.2.1"
TUN_PEER = '10.1.2.2'
MTU = 65000


class Tunnel():
    def __init__(self, tun_ip, tun_peer):
        self.tfd, self.tname = Tun().create_tun(tun_ip, tun_peer)
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmpfd.setblocking(0)
        self.packet = icmp.ICMPPacket()
        self.now_identity = 0xffff
        self.server_ip = ''

    def close(self):
        os.close(self.tfd)

    def run(self):
        self.server_ip = '0.0.0.0'
        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [])[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, MTU)
                    buf = self.packet.create(0, 0, self.now_identity, 0x4147, data)
                    try:
                        print 'send ip', self.server_ip, 'length', len(data)
                        self.icmpfd.sendto(buf, (self.server_ip, 1))
                    except:
                        print 'error data len:', len(buf), buf[-10:]
                elif r == self.icmpfd:
                    buf = self.icmpfd.recv(icmp.BUFFER_SIZE)
                    data = self.packet.parse(buf, True)
                    if self.packet.seqno == 0x4147:  # True packet
                        self.now_identity = self.packet.id
                        src = buf[12:16]
                        now_server_ip = socket.inet_ntoa(src)
                        if now_server_ip != self.server_ip:
                            self.server_ip = now_server_ip
                        if data == 'heartbeat':
                            print 'time:%s recv heartbeat' % time.time()
                            continue
                        os.write(self.tfd, data)


if __name__ == "__main__":
    opts = getopt.getopt(sys.argv[1:], "l:p:")
    for opt, optarg in opts[0]:
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
