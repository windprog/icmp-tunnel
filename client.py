#!/usr/bin/env python

import os, sys
import getopt
import socket
import select
import time
from sender import BaseTunnel

TUN_IP = "10.1.2.2"
TUN_PEER = '10.1.2.1'


class Tunnel(BaseTunnel):
    IP_DOMAIN = 'xxxx.f3322.org'

    def __init__(self, tun_ip, tun_peer):
        super(Tunnel, self).__init__(tun_ip, tun_peer)
        self.heartbeat = 0
        self.check_heartbeat()

    def close(self):
        os.close(self.tfd)

    def check_heartbeat(self):
        try:
            self.server_ip = socket.getaddrinfo(self.IP_DOMAIN, None)[0][4][0]
            if time.time() - self.heartbeat > 3:
                buf = self.get_client_data(self.heartbeat_data)
                self.send(buf)
                self.heartbeat = time.time()
                print 'send heartbeat to server:%s len:%s' % (self.server_ip, len(buf))
        except:
            print 'send heartbeat error! domain:%s' % repr(self.IP_DOMAIN)

    def run(self):
        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [], 3)[0]
            for r in rset:
                if r == self.tfd:
                    data = self.read_from_tun()
                    buf = self.get_client_data(data)
                    try:
                        self.send(buf)
                    except Exception, e:
                        print 'error data len:', len(buf), type(e)

                elif r == self.icmpfd:
                    buf = self.recv()
                    data = self.packet.parse(buf, True)
                    if self.packet.seqno == 0x4147:  # true password
                        self.heartbeat = time.time()
                        if data.startswith('res:'):
                            # control response
                            continue
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
