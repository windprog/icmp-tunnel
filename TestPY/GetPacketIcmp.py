#!/usr/bin/env python

import os, sys
import hashlib
import getopt
import fcntl
import icmp
import time
import struct
import socket, select

debug = True

class Tunnel():
    def run(self):
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        
        packet = icmp.ICMPPacket()
            
        NowIdentity = 0xffff
        
        while True:
            rset = select.select([self.icmpfd], [], [])[0]
            for r in rset:
                if r == self.icmpfd:
                    buf = self.icmpfd.recv(icmp.BUFFER_SIZE)
                    data = packet.parse(buf, False)
                    if debug:
                        print "recv ICMP type=", packet._type,"code=",packet.code,"chksum=",packet.chksum,"id=", packet.id, "seqno=", packet.seqno,"data size:",len(data)
                        # Client
                        #os.write(self.tfd, data) 
                        

if __name__=="__main__":
    tun = Tunnel()
    tun.run()
        
    
