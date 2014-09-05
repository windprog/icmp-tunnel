#!/usr/bin/env python

import icmp
import time

if __name__=="__main__":
    starttime = time.time()
    for t in range(0,102400):#100mb Test 11sec
        test = icmp.enZipData('idosjdfiuyrteiso'*64)
        icmp.deZipData(test)
    endtime = time.time()
    print endtime-starttime
        