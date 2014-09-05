import threading
import Queue
import time
from scapy.all import *#apt-get install python-scapy

global PacketQueue
PacketQueue = Queue.Queue()
global IsInit
IsInit = False
global ThreadCount
ThreadCount = 10
    
class DoThread(threading.Thread): #The timer class is derived from the class threading.Thread  
    def __init__(self, threadNum):  
        threading.Thread.__init__(self)  
        self.thread_num = threadNum  
        self.thread_stop = False  
   
    def run(self): #Overwrite run() method, put what you want the thread do here  
        print 'Thread NO.',self.thread_num,' was start\n'
        while not self.thread_stop:
            if PacketQueue.empty == True:
                time.sleep(0.001)
            else:
                pkt = PacketQueue.get()
                send(pkt) 
            
    def stop(self): 
        self.thread_stop = True 
        print 'Thread NO.(%d) was stop\n' %(self.thread_num)
        
def Send_scapy(_IP_,data_,NowIdentity):
    pkt = IP(dst=_IP_)/ICMP(type=0,code=0,id=NowIdentity,seq=0x4147)/data_
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
    for i in range(500):
        Send_scapy('127.0.0.1','test',1)
    
    while not PacketQueue.empty:
        pass
    t2 = time.time()
    
    print t2-t1
    
    time.sleep(5)
    for t in range(len(threadArr)):
        threadArr[t].stop()