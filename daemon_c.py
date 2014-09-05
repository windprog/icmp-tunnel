#!/usr/bin/env python

import os
import sys
import globalvar

sys.path.append("./")
os.chdir(globalvar.Runloc)

def monitor(appName):
    pid = os.fork()

    if 0 == pid:	# child process
        os.system(appName)
        sys.exit(0)

    else:  # parent process
        os.wait()

if __name__ == '__main__' :
    while 1:
        monitor('./client_s.py -c 108.170.4.20 -l 10.1.104.2/24')
