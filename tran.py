#!/usr/bin/env python

import os, sys
import hashlib
import getopt
import fcntl
import icmp
import time
import struct
import socket, select

global des
global sou


class Tunnel():
    
    def run(self):
        self.icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        packet = icmp.ICMPPacket()
        while True:
            rset = select.select([self.icmpfd], [], [])[0]
            for r in rset:
                if r == self.icmpfd:
                    buf = self.icmpfd.recv(icmp.BUFFER_SIZE)
                    data = packet.parse(buf, False) 
                    src = buf[12:16]
                    print socket.inet_ntoa(src)
                    if socket.inet_ntoa(src)==des:
                        buf = packet.create(packet._type,packet.code,packet.id,packet.seqno,data,True)
                        self.icmpfd.sendto(buf, (sou, 22))
                    else:
                        buf = packet.create(packet._type,packet.code,packet.id,packet.seqno,data,False)
                        self.icmpfd.sendto(buf, (des, 22))
                        

if __name__=="__main__":
    opts = getopt.getopt(sys.argv[1:],"d:s:l:p:")
    global des
    global sou
    for opt,optarg in opts[0]:    
        if opt == "-d":
            des = optarg
        elif opt == "-s":
            sou = optarg
    
    print "Tran is started"
    try:
        Tunnel().run()
    except KeyboardInterrupt:
        sys.exit(0)
