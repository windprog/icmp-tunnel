#!/usr/bin/env python

import globalvar
from Queue import Queue
import struct
import time
import datetime
import icmp
import thread
import threading

global packet
global outputPacket
packet = None
outputPacket = None
def init():
    global packet
    global outputPacket    
    packet = icmp.ICMPPacket()
    
    outputPacket = {globalvar.DefaultServerIP:Queue()}
    for sip in globalvar.ElseServersIP:
        outputPacket[sip] = Queue()    

def sendPacket(server,buf,tm=globalvar.oneSendTime):
    try:
        globalvar.tun.icmpfd.sendto(buf, (server, 22))
    except:
        time.sleep(tm)
        sendPacket(server,buf)
    else:
        time.sleep(tm)
def sendPacketNowait(server,buf,tm=globalvar.oneSendTime):
    try:
        globalvar.tun.icmpfd.sendto(buf, (server, 22))
    except:
        time.sleep(tm)
        sendPacket(server,buf)

def OneSend(items,server):
    buf = "".join(items)#lianjie
    #add header
    buf = packet.create(0,0,globalvar.NowIdentity,globalvar.Password, buf)
    #send packet
    sendPacket(server,buf) 

def close():
    globalvar.cond.notify()
    globalvar.Opened=False

def processSend():
    while globalvar.Opened:
        globalvar.cond.acquire()
        Isempty = True
        for (server,queue) in outputPacket.items():
            if not queue.empty():
                Isempty = False
        if Isempty:
            globalvar.cond.wait()
        globalvar.cond.release()
        for (server,queue) in outputPacket.items():
            tempbyteCount = 0
            items = []
            #while not queue.empty():
                #item = queue.get()
                #temp = struct.pack('!H'+str(len(item))+"s", len(item),item)
                #if tempbyteCount+len(temp)>globalvar.oneSendCount and tempbyteCount>0:
                    #if len(temp)>globalvar.oneSendCount:
                        #print 'error packet length over SendCount'
                        #continue
                    #OneSend(items,server)
                    #tempbyteCount=0
                    #items = []
                #items.append(temp)
                #tempbyteCount+=len(temp)
            #if len(items)!=0:
                #OneSend(items,server)
            fmt = "!"
            while not queue.empty():
                item = queue.get()
                l = len(item)
                if tempbyteCount+l>globalvar.oneSendCount and tempbyteCount>0:
                    if l+2>globalvar.oneSendCount:
                        print 'error packet length over SendCount'
                        continue
                    buf = struct.pack(fmt, *items)
                    buf = packet.create(globalvar.IcmpType,globalvar.IcmpCode,globalvar.NowIdentity,globalvar.Password, buf,globalvar.Ischksum)
                    sendPacket(server,buf) 
                    tempbyteCount=0
                    items = []
                    fmt = "!"
                fmt += ('H%ss'%l)
                items.append(l)
                items.append(item)
                tempbyteCount+=l
            if len(items)!=0:
                buf = struct.pack(fmt, *items)
                buf = packet.create(globalvar.IcmpType,globalvar.IcmpCode,globalvar.NowIdentity,globalvar.Password, buf,globalvar.Ischksum)
                sendPacket(server,buf)           
                
    
def StartThread():
    thread.start_new_thread(processSend,())