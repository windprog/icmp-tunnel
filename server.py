#!/usr/bin/env python

import os, sys
import getopt
import socket
import select
import time
from sender import BaseTunnel

TUN_IP = "10.1.2.1"
TUN_PEER = '10.1.2.2'


class Tunnel(BaseTunnel):
    def __init__(self, tun_ip, tun_peer):
        super(Tunnel, self).__init__(tun_ip, tun_peer)

    def close(self):
        os.close(self.tfd)

    def recv_heartbeat(self, req_data):
        print 'recv heartbeat from %s time:%s' % (self.server_ip, time.time())
        buf = self.get_server_data(self.heartbeat_data)
        self.icmpfd.sendto(self.get_server_data(buf), (self.server_ip, 1))

    def run(self):
        self.server_ip = '0.0.0.0'
        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [])[0]
            for r in rset:
                if r == self.tfd:
                    data = self.read_from_tun()
                    buf = self.get_server_data(data)
                    try:
                        self.send(buf)
                    except Exception, e:
                        print 'error data len:', len(buf), type(e)
                elif r == self.icmpfd:
                    buf = self.recv()
                    data = self.packet.parse(buf, True)
                    if self.packet.seqno == 0x4147:  # True packet
                        self.now_identity = self.packet.id
                        src = buf[12:16]
                        self.server_ip = socket.inet_ntoa(src)
                        if data.startswith('req:'):
                            # control request
                            self.recv_heartbeat(data)
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
