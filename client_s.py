#!/usr/bin/env python

import os, sys
import hashlib
import getopt
import fcntl
import icmp_s
import time
import struct
import socket, select
import globalvar
import ctypes

api = ctypes.CDLL('./s.so')



class Tunnel():
    def create(self):
        self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        ifs = fcntl.ioctl(self.tfd, globalvar.TUNSETIFF, struct.pack("16sH", "t%d", globalvar.IFF_TUN))
        self.tname = ifs[:16].strip("\x00")
    
    def close(self):
        os.close(self.tfd)
        
    def config(self, ip):
        os.system("ip link set %s up" % (self.tname))
        os.system("ip link set %s mtu 1396" % (self.tname))
        os.system("ip addr add %s dev %s" % (ip, self.tname))
    
    def run(self):
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        
        packet = icmp_s.ICMPPacket()
            
        NowIdentity = 0xffff
        
        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [])[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, globalvar.MTU)
                    # Client
                    #NowIdentity += 1
                    #NowIdentity %= 65535
                    #buf = packet.createByClient(NowIdentity,0x4147, data)
                    buf = packet.createEx(17,0,NowIdentity,0x4147, data,True)             
                    #self.icmpfd.sendto(buf, (globalvar.ServerIP, 22)) 
                    res = api.sendicmp(globalvar.ServerIP,buf,len(buf))
                    if res<=0:
                        buf = "\0"*1000
                        api.geterror((-1)*res,buf)
                        print buf
                    
                elif r == self.icmpfd:
                    buf = self.icmpfd.recv(icmp_s.BUFFER_SIZE)
                    data = packet.parse(buf, False)
                    if packet.seqno == 0x4147:#true password
                        # Client
                        os.write(self.tfd, data) 
                        

if __name__=="__main__":
    opts = getopt.getopt(sys.argv[1:],"s:c:l:hd")
    for opt,optarg in opts[0]:
        if opt == "-c":
            globalvar.ServerIP = optarg
        elif opt == "-l":
            globalvar.IFACE_IP = optarg
    
    
    tun = Tunnel()
    tun.create()
    print "Allocated interface %s" % (tun.tname)
    tun.config(globalvar.IFACE_IP)
    try:
        tun.run()
    except KeyboardInterrupt:
        tun.close()
        sys.exit(0)
        
    
