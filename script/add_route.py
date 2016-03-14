#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/14
Desc    :   
"""
import os
import re
import sys
from netaddr import IPNetwork, IPAddress
from ip_builder import IPN_FILE


def get_dev_name(ip):
    dev_name = None
    ifconfig = os.popen('ifconfig').read().replace('\r\n', '\n').split('\n')
    for i in xrange(len(ifconfig)):
        if ip in ifconfig[i]:
            line = ifconfig[i - 1]
            line = line[:line.find('Link')]
            dev_name = line.strip()
            dev_name = re.match('[a-zA-z0-9]*', dev_name).group()
            break
    return dev_name


if __name__ == '__main__':
    action = sys.argv[1]
    ip_or_dev = sys.argv[2]
    dev = ip_or_dev
    try:
        IPAddress(ip_or_dev)
        dev = get_dev_name(ip_or_dev)
    except:
        pass
    with file(IPN_FILE) as f:
        for ipn in f.xreadlines():
            if action == 'add':
                os.system('sudo route add %s -interface %s' % (ipn.strip(), dev))
            else:
                os.system('sudo route delete %s' % ipn.strip())
