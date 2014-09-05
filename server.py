#!/usr/bin/env python

import os, sys
import hashlib
import getopt
import fcntl
import icmp
import time
import struct
import socket, select
import PThread
import globalvar
from Queue import Queue
import thread
import threading

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
        packet = icmp.ICMPPacket()
        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [])[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, globalvar.MTU)
                    if len(data)>24:
                        globalvar.cond.acquire()
                        try:
                            PThread.outputPacket[globalvar.DefaultServerIP].put(data)
                        except:
                            print 'Server is notfound.'
                        globalvar.cond.notify()
                        globalvar.cond.release()
                elif r == self.icmpfd:
                    buf = self.icmpfd.recv(icmp.BUFFER_SIZE)
                    data = packet.parse(buf, False) 
                    if packet.seqno == globalvar.Password:#true password
                        if len(data)>20:                       
                            #process accept
                            #read packet
                            start = 0
                            end = 0
                            while start!=len(data):                
                                countByte = data[start:start+2]
                                count, = struct.unpack("!H",countByte)
                                start+=2
                                end=count+start
                                #write t0
                                if end>len(data):
                                    break                
                                os.write(globalvar.tun.tfd, data[start:end])
                                start=end
                                if end==len(data):
                                    break
                    elif packet.seqno == globalvar.Password+1:
                        if data=='update':
                            globalvar.NowIdentity = packet.id
                            src = buf[12:16]
                            globalvar.DefaultServerIP = socket.inet_ntoa(src)  
                            if not PThread.outputPacket.has_key(globalvar.DefaultServerIP):
                                PThread.outputPacket.clear()
                                PThread.outputPacket[globalvar.DefaultServerIP] = Queue()
                    elif packet.seqno == 0x4147:#old version
                        os.write(self.tfd, data)
                        

if __name__=="__main__":
    opts = getopt.getopt(sys.argv[1:],"s:c:l:p:")
    for opt,optarg in opts[0]:    
        if opt == "-l":
            globalvar.IFACE_IP = optarg
        elif opt == "-p":
            globalvar.Password = int(optarg)
            if globalvar.Password>65530:
                print 'Input password is too big!'
                sys.exit(0)
    
    PThread.init()
    globalvar.tun = Tunnel()
    globalvar.tun.create()
    print "Allocated interface %s" % (globalvar.tun.tname)
    globalvar.tun.config(globalvar.IFACE_IP)
    #init lock
    globalvar.cond = threading.Condition()
    PThread.StartThread()
    try:
        globalvar.tun.run()
    except KeyboardInterrupt:
        PThread.close()
        globalvar.tun.close()
        sys.exit(0)
        
def testRun():
    globalvar.IFACE_IP = '10.1.104.1/24'
    globalvar.Password = 104
    
    PThread.init()
    globalvar.tun = Tunnel()
    globalvar.tun.create()
    print "Allocated interface %s" % (globalvar.tun.tname)
    globalvar.tun.config(globalvar.IFACE_IP)
    #init lock
    globalvar.cond = threading.Condition()
    PThread.StartThread()
    try:
        globalvar.tun.run()
    except KeyboardInterrupt:
        PThread.close()
        globalvar.tun.close()
        sys.exit(0)