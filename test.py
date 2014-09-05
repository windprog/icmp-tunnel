#!/usr/bin/env python
import socket
import icmp
import select

count = 0

icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
packet = icmp.ICMPPacket()
while True:
    rset = select.select([icmpfd], [], [])[0]
    for r in rset:
        if r == icmpfd:
            buf = icmpfd.recv(icmp.BUFFER_SIZE)
            data = packet.parse(buf, False)
            count+=1
            src = buf[12:16]
            ClientIP = socket.inet_ntoa(src)    
            print "totalCount=%s,ClientIP: %s,recv ICMP type=%s,code=%s,chksum=%s,id=%s,seqno=%s,data size=%s,  data6=%s"%\
                        (count,ClientIP,packet._type,packet.code,packet.chksum,packet.id,packet.seqno,len(data),data[0:6])           