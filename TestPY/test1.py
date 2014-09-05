#!/usr/bin/env python

import threading
import Queue
import sys
import struct
import time
import socket
import icmp

global PacketQueue
PacketQueue = Queue.Queue()
global IsInit
IsInit = False
global ThreadCount
ThreadCount = 1
    
class DoThread(threading.Thread): #The timer class is derived from the class threading.Thread  
    def __init__(self, threadNum):  
        threading.Thread.__init__(self)  
        self.thread_num = threadNum  
        self.thread_stop = False  
   
    def run(self): #Overwrite run() method, put what you want the thread do here  
        print 'Thread NO.',self.thread_num,' was start\n'
        icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        while not self.thread_stop:
            if PacketQueue.empty == True:
                time.sleep(0.001)
            else:
                time.sleep(0.001)
                buf = PacketQueue.get()
                icmpfd.sendto(buf, ('113.105.12.150', 65535))
                              
    def stop(self): 
        self.thread_stop = True 
        print 'Thread NO.(%d) was stop\n' %(self.thread_num)
        
def Send_scapy(_IP_,data_,NowIdentity):
    pkt = data_
    PacketQueue.put(pkt)
    global IsInit
    if not IsInit: 
        for num in range(ThreadCount):
            threadArr[num].start()
        IsInit = True
        print 'initialized'
        
threadArr = {}
for num in range(ThreadCount):
    threadArr[num]= DoThread(num)

if __name__ == '__main__':  
    t1 = time.time()
    packet = icmp.ICMPPacket()
    icmpfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    data = packet.createByServer(65535,0x4147, 'test'*200)
    for i in range(50000):
        icmpfd.sendto(data, ('113.105.12.150', 65535))
        time.sleep(0.001)

    
    while not PacketQueue.empty:
        pass
    t2 = time.time()
    
    print t2-t1
    
    for t in range(len(threadArr)):
        threadArr[t].stop()