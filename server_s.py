#!/usr/bin/env python

import os, sys
import getopt
import fcntl
import icmp_s
import struct
import socket
import select

TUNSETIFF = -2147199798
IFF_TUN   = 0x0001
IFACE_IP = "10.1.2.1/24"
MTU = 65000


class Tunnel():
    def create(self):
        self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "t%d", IFF_TUN))
        self.tname = ifs[:16].strip("\x00")

    def close(self):
        os.close(self.tfd)

    def config(self, ip):
        os.system("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu 1396" % (self.tname))
        os.system("ip addr add %s dev %s" % (ip, self.tname))

    def run(self):
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmpfd.setblocking(0)
        packet = icmp_s.ICMPPacket()
        now_identity = 0xffff
        self.server_ip = '0.0.0.0'
        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [])[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, MTU)
                    #server
                    #buf = packet.createByServer(now_identity,0x4147, data)
                    buf = packet.create(0, 0, now_identity, 0x4147, data)
                    try:
                        # self.icmpfd.send(buf)
                        print 'send ip', self.server_ip, 'length', len(data)
                        self.icmpfd.sendto(buf, (self.server_ip, 1))
                    except:
                        print 'error data len:', len(buf), buf[-10:]
                elif r == self.icmpfd:
                    buf = self.icmpfd.recv(icmp_s.BUFFER_SIZE)
                    data = packet.parse(buf, True)
                    if packet.seqno == 0x4147:  #True packet
                        now_identity = packet.id
                        src = buf[12:16]
                        now_server_ip = socket.inet_ntoa(src)
                        if now_server_ip != self.server_ip:
                            self.server_ip = now_server_ip
                        os.write(self.tfd, data)


if __name__ == "__main__":
    opts = getopt.getopt(sys.argv[1:], "s:c:l:hd")
    for opt, optarg in opts[0]:
        if opt == "-l":
            IFACE_IP = optarg

    tun = Tunnel()
    tun.create()
    print "Allocated interface %s" % (tun.tname)
    tun.config(IFACE_IP)
    try:
        tun.run()
    except KeyboardInterrupt:
        tun.close()
        sys.exit(0)    