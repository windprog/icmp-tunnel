#!/usr/bin/env python

import os, sys
import getopt
import socket
import select
import time
from sender import BaseTunnel
from packet import TunnelPacket

TUN_IP = "10.1.2.1"
TUN_PEER = '10.1.2.2'


class Tunnel(BaseTunnel):
    def __init__(self, tun_ip, tun_peer):
        super(Tunnel, self).__init__(tun_ip, tun_peer)

    def close(self):
        os.close(self.tfd)

    def recv_heartbeat(self, req_data):
        print 'recv heartbeat from %s time:%s' % (self.server_ip, time.time())
        res_data = "res:" + req_data[4:]
        self.icmpfd.sendto(self.get_server_data(res_data), (self.server_ip, 1))

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
                        self.pending_list.append(buf)
                        print 'error data len:', len(buf), type(e)
                elif r == self.icmpfd:
                    buf = self.recv()
                    packet = TunnelPacket(buf)
                    if packet.seqno == 0x4147:  # True packet
                        self.now_identity = packet.id
                        self.server_ip = packet.src
                        data_list = packet.data_list
                        if data_list and data_list[0].startswith('req:'):
                            # control request
                            self.recv_heartbeat(data_list[0])
                            data_list = data_list[1:]
                        for one_data in data_list:
                            os.write(self.tfd, one_data)


if __name__ == "__main__":
    opts = getopt.getopt(sys.argv[1:], "l:p:d:")
    for opt, optarg in opts[0]:
        if opt == "-l":
            TUN_IP = optarg
        elif opt == '-p':
            TUN_PEER = optarg
        elif opt == '-d':
            TunnelPacket.DEBUG = True

    tun = Tunnel(TUN_IP, TUN_PEER)
    print "Allocated interface %s" % (tun.tname)
    try:
        tun.run()
    except KeyboardInterrupt:
        tun.close()
        sys.exit(0)
