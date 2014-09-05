#!/usr/bin/env python

import os, sys
import hashlib
import getopt
import fcntl
import icmp
import time
import struct
import socket, select
import globalvar
import ReadCPU

class Tunnel():
    def create(self):
        self.tfd = os.open("/dev/net/tun", os.O_RDWR)
        ifs = fcntl.ioctl(self.tfd, globalvar.TUNSETIFF, struct.pack("16sH", "t%d", globalvar.IFF_TUN))
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
        while True:
            rset = select.select([self.icmpfd, self.tfd], [], [])[0]
            for r in rset:
                if r == self.tfd:
                    data = os.read(self.tfd, globalvar.MTU)
                    if ReadCPU.CPU0>globalvar.CPULimit:
                        globalvar.NeedSendZip=False
                    else:
                        globalvar.NeedSendZip=True
                    if globalvar.NeedSendZip:#Need Zip
                        #encoding zip
                        try:
                            data = icmp.enZipData(data)
                        except:
                            time.sleep(0.01)
                            try:
                                data = icmp.enZipData(data)
                            except:
                                pass
                        buf = packet.createByServer(globalvar.NowIdentity,0x4148, data)
                    else:
                        buf = packet.createByServer(globalvar.NowIdentity,0x4147, data)
                    if globalvar.debug:
                        print "send ICMP type=", packet._type,"code=",packet.code,"chksum=",packet.chksum,"id=", packet.id, "seqno=", packet.seqno,"data size:",len(buf)-8
                    #send packet
                    try:
                        self.icmpfd.sendto(buf, (globalvar.ClientIP, 22))
                    except:
                        time.sleep(0.01)
                        try:
                            self.icmpfd.sendto(buf, (globalvar.ClientIP, 22))
                        except:
                            time.sleep(0.5)
                            try:
                                self.icmpfd.sendto(buf, (globalvar.ClientIP, 22))
                            except:
                                pass
                        
                        
                elif r == self.icmpfd:
                    buf = self.icmpfd.recv(icmp.BUFFER_SIZE)
                    data = packet.parse(buf, False)
                    if globalvar.debug:
                        print "recv ICMP type=", packet._type,"code=",packet.code,"chksum=",packet.chksum,"id=", packet.id, "seqno=", packet.seqno,"data size:",len(data)
                    if packet.seqno == 0x4147:#True packet And No ZIp
                        # Simply write the packet to local or forward them to other clients ???
                        globalvar.NowIdentity = packet.id
                        src = buf[12:16]
                        globalvar.ClientIP = socket.inet_ntoa(src)                    
                        os.write(self.tfd, data)
                    elif packet.seqno == 0x4148:#True packet And ZIp
                        globalvar.NowIdentity = packet.id
                        src = buf[12:16]
                        globalvar.ClientIP = socket.inet_ntoa(src)
                        #decoding zip
                        try:
                            data = icmp.deZipData(data)                        
                            os.write(self.tfd, data)                                                    
                        except:
                            pass

if __name__=="__main__":
    opts = getopt.getopt(sys.argv[1:],"s:c:l:hd")
    for opt,optarg in opts[0]:    
        if opt == "-l":
            globalvar.IFACE_IP = optarg
    
    tun = Tunnel()
    tun.create()
    print "Allocated interface %s" % (tun.tname)
    tun.config(globalvar.IFACE_IP)
    try:
        tun.run()
        #start CalCPU
        ReadCPU.Run()
    except KeyboardInterrupt:
        tun.close()
        sys.exit(0)