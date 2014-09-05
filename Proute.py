#!/usr/bin/env python

import globalvar

IPCache = {}
StaticIPs = {}

def GetServer(ip):
    if IPCache.has_key(ip):
        sn = IPCache[ip]
        if sn==0:
            return globalvar.DefaultServerIP
        else:
            return globalvar.ElseServersIP[sn-1]
    else:
        return None

def InsertIP(ip,server):
    IPCache[ip] = server