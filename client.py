#!/usr/bin/env python

import os, sys
import hashlib
import getopt
import fcntl
import icmp
import icmp_s
import time
import struct
import socket, select
import globalvar
import random
from decimal import Decimal
import Proute
import datetime
import thread
import threading
import PThread

def clientProcess():
    while globalvar.Opened:
        keepAlive()
        #count Speed
        if globalvar.LastBLTime!=None:
            timespan = datetime.datetime.now() - globalvar.LastBLTime
            if (timespan.seconds*1000*1000+timespan.microseconds)>=1000*1000:
                globalvar.NowSpeed = Decimal(globalvar.BandwidthLimit[globalvar.DefaultServerIP]*1000*1000)/Decimal((timespan.seconds*1000*1000+timespan.microseconds)*1024) 
                if globalvar.debug==True:
                    print str(globalvar.NowSpeed) + "kb/s"
                globalvar.LastBLTime = datetime.datetime.now()
                globalvar.BandwidthLimit[globalvar.DefaultServerIP] = 0
        time.sleep(10)

def keepAlive():
    #process alive packet
    PThread.sendPacket(globalvar.DefaultServerIP,globalvar.testData)
    for sIP in globalvar.ElseServersIP:
        PThread.sendPacket(sIP,globalvar.testData)

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
                        if globalvar.debug:
                            print 'des is %s'%socket.inet_ntoa(data[20:24])
                        ServerIP = Proute.GetServer(data[20:24])
                        if not ServerIP:
                            #record IP
                            ServerIP = globalvar.DefaultServerIP
                            if globalvar.NowSpeed>=globalvar.BLSpeedNum and globalvar.ElseServersIP.count>=1:
                                serverNum = random.randint(0,len(globalvar.ElseServersIP)-1)+1
                                ServerIP = globalvar.ElseServersIP[serverNum-1]
                                Proute.InsertIP(data[20:24],serverNum)                                    
                            else:
                                Proute.InsertIP(data[20:24],0)
                        if globalvar.oldVersionServersIP.has_key(ServerIP):
                            buf = icmp.ICMPPacket().create(globalvar.IcmpType,globalvar.IcmpCode,globalvar.NowIdentity,globalvar.oldVersionServersIP[ServerIP],data,False)
                            PThread.sendPacketNowait(ServerIP,buf)
                        else:
                            globalvar.cond.acquire()
                            PThread.outputPacket[ServerIP].put(data)
                            globalvar.cond.notify()
                            globalvar.cond.release()                            
                elif r == self.icmpfd:
                    buf = self.icmpfd.recv(icmp.BUFFER_SIZE)
                    data = packet.parse(buf, False) 
                    if packet.seqno == 0x4147:#old version
                        os.write(self.tfd, data) 
                    elif packet.seqno == globalvar.Password:#true password
                        # Client
                        if globalvar.LastBLTime==None:
                            #init
                            globalvar.LastBLTime = datetime.datetime.now()
                        else:
                            if len(data)>20:
                                #process accept
                                #read packet
                                start = 0
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
                                if socket.inet_ntoa(buf[12:16])==globalvar.DefaultServerIP:
                                    globalvar.BandwidthLimit[globalvar.DefaultServerIP]+=len(buf)
                        

if __name__=="__main__":
    opts = getopt.getopt(sys.argv[1:],"d:e:l:p:")
    for opt,optarg in opts[0]:
        if opt =='-d':
            globalvar.DefaultServerIP = optarg
        elif opt == '-e':
            globalvar.ElseServersIP = optarg.split(",")
        elif opt == "-l":
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
    globalvar.testData = icmp.ICMPPacket().create(globalvar.IcmpType,globalvar.IcmpCode,globalvar.NowIdentity,globalvar.Password+1,'update',True)
    globalvar.BandwidthLimit[globalvar.DefaultServerIP] = 0
    for serverIP in globalvar.ElseServersIP:
        globalvar.BandwidthLimit[serverIP] = 0
    globalvar.tun.config(globalvar.IFACE_IP)
    #init lock
    globalvar.cond = threading.Condition()
    PThread.StartThread()
    thread.start_new_thread(clientProcess,())
    try:
        globalvar.tun.run()
    except KeyboardInterrupt:
        PThread.close()
        globalvar.tun.close()
        sys.exit(0)
        
def testRun():
    globalvar.DefaultServerIP = '118.244.147.104'
    globalvar.IFACE_IP = '10.1.104.2/24'
    globalvar.Password = 104
    PThread.init()
    globalvar.tun = Tunnel()
    globalvar.tun.create()
    print "Allocated interface %s" % (globalvar.tun.tname)
    globalvar.testData = icmp.ICMPPacket().create(globalvar.IcmpType,globalvar.IcmpCode,globalvar.NowIdentity,globalvar.Password+1,'update',True)
    globalvar.BandwidthLimit[globalvar.DefaultServerIP] = 0
    for serverIP in globalvar.ElseServersIP:
        globalvar.BandwidthLimit[serverIP] = 0
    globalvar.tun.config(globalvar.IFACE_IP)
    #init lock
    globalvar.cond = threading.Condition()
    PThread.StartThread()
    thread.start_new_thread(clientProcess,())
    try:
        globalvar.tun.run()
    except KeyboardInterrupt:
        PThread.close()
        globalvar.tun.close()
        sys.exit(0)