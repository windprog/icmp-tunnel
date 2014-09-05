#!/usr/bin/env python

import os, sys
import hashlib
import getopt
import fcntl
import icmp
import time
import struct
import socket, select

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001

IFACE_IP = "10.0.0.1"
MTU = 1500

debug = False

class Tunnel():
    def create(self):
        self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        ifs = fcntl.ioctl(self.tfd, TUNSETIFF, struct.pack("16sH", "t%d", IFF_TUN))
        self.tname = ifs[:16].strip("\x00")
    
    def close(self):
        os.close(self.tfd)
        
    def config(self, ip):
        os.system("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu 1000" % (self.tname))
        os.system("ip addr add %s dev %s" % (ip, self.tname))
    
    def run(self):
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        
        packet = icmp.ICMPPacket()
            
        NowIdentity = 0xffff
        
        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [])[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, MTU)
                    # Client
                    #NowIdentity += 1
                    #NowIdentity %= 65535
                    buf = packet.createByClient(NowIdentity,0x4147, data)
                    if debug:
                        print "send ICMP type=", packet._type,"code=",packet.code,"chksum=",packet.chksum,"id=", packet.id, "seqno=", packet.seqno,"data size:",len(buf)-8
                    self.icmpfd.sendto(buf, (ServerIP, 22)) 
                    
                elif r == self.icmpfd:
                    buf = self.icmpfd.recv(icmp.BUFFER_SIZE)
                    data = packet.parse(buf, False)
                    if packet.seqno == 0x4147:#true password
                        if debug:
                            print "recv ICMP type=", packet._type,"code=",packet.code,"chksum=",packet.chksum,"id=", packet.id, "seqno=", packet.seqno,"data size:",len(data)-8
                        # Client
                        os.write(self.tfd, data) 
                        

if __name__=="__main__":
    opts = getopt.getopt(sys.argv[1:],"s:c:l:hd")
    for opt,optarg in opts[0]:
        if opt == "-c":
            ServerIP = optarg
        elif opt == "-l":
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
        
    