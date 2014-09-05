import sys
import struct
import time
import socket
import icmp

t1 = time.time()

packet = icmp.ICMPPacket()

buf = packet.createByClient(65535,0x4147, 'test'*200)

icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))

for t in range(0,500000):
    icmpfd.sendto(buf, ('113.105.12.150', 1))
    time.sleep(0.001)

t2 = time.time()

print t2-t1
