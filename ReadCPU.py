#!/usr/bin/python
# -*- coding: UTF-8 -*- 

import re,time
import sys
import thread 

global CPU0
CPU0=0

def _read_cpu_usage(): 
        #"""Read the current system cpu usage from /proc/stat""" 
        statfile = "/proc/stat" 
        cpulist = [] 
        try: 
                f = open(statfile, 'r') 
                lines = f.readlines() 
        except: 
                print "error:无法打开文件%s，系统无法继续运行。" % (statfile) 
                return [] 
        for line in lines: 
                tmplist = line.split() 
                if len(tmplist) < 5: 
                        continue 
                for b in tmplist: 
                        m = re.search(r'cpu\d+',b) 
                        if m is not None: 
                                cpulist.append(tmplist) 
        f.close() 
        return cpulist 

def get_cpu_usage(): 
        cpuusage = {} 
        cpustart = {} 
        cpuend = {} 
        linestart = _read_cpu_usage() 
        if not linestart: 
                return 0 
        for cpustr in linestart: 
                usni=long(cpustr[1])+long(cpustr[2])+long(cpustr[3])+long(cpustr[5])+long(cpustr[6])+long(cpustr[7])+long(cpustr[4]) 
                usn=long(cpustr[1])+long(cpustr[2])+long(cpustr[3]) 
                cpustart[cpustr[0]] = str(usni)+":"+str(usn) 
        sleep = 2 
        time.sleep(sleep) 
        lineend = _read_cpu_usage() 
        if not lineend: 
                return 0 
        for cpustr in lineend: 
                usni=long(cpustr[1])+long(cpustr[2])+long(cpustr[3])+long(cpustr[5])+long(cpustr[6])+long(cpustr[7])+long(cpustr[4]) 
                usn=long(cpustr[1])+long(cpustr[2])+long(cpustr[3]) 
                cpuend[cpustr[0]] = str(usni)+":"+str(usn) 
        for line in cpustart: 
                start = cpustart[line].split(':') 
                usni1,usn1 = float(start[0]),float(start[1]) 
                end = cpuend[line].split(':') 
                usni2,usn2 = float(end[0]),float(end[1]) 
                cpuper=(usn2-usn1)/(usni2-usni1) 
                cpuusage[line] = int(100*cpuper) 
         
        return cpuusage 

def timer():
        while True:
                global CPU0
                CPU0 = get_cpu_usage() ['cpu0']

def Run():
        thread.start_new_thread(timer,())
        

if __name__ == '__main__': 
        Run()
        while True:
                print CPU0
                time.sleep(2)
                