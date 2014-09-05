import sys
import struct
from scapy.all import *#apt-get install python-scapy

def Send_scapy(_IP_,data_,NowIdentity):
    pkt = IP(dst=_IP_)/ICMP(type=0,code=0,id=NowIdentity,seq=0x4147)/data_
    send(pkt) 
    pass

if __name__=="__main__":
    Send_scapy('127.0.0.1','test',0x0001)
    print 'test'