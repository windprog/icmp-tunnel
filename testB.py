#!/usr/bin/env python

import icmp
import socket
import time
from datetime import datetime

sm = 0.002
data = 't'*56
ip = '192.210.195.29'
pk = icmp.ICMPPacket()
id = 30295
seqno=105
count = 5000
buf = pk.create(0,0,id,seqno,data)

def test():
    for i in range(count):
        icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        icmpfd.sendto(buf, (ip, 22))
        time.sleep(sm)
        
def getut():
    t1 = datetime.now();test();t2 = datetime.now()
    return t2-t1
def getspeed():
    timesp = getut()
    return (len(data)+8)*count/timesp.seconds/1024

if __name__=="__main__":
    print getspeed()