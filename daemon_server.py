#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   15/9/18
Desc    :   
"""
import os
import sys


def monitor(appName):
    pid = os.fork()

    if 0 == pid:  # child process
        os.system(appName)
        sys.exit(0)
    else:  # parent process
        os.wait()
    # 重启
    os.system('git pull && reboot')


if __name__ == '__main__':
    args_str = " ".join(sys.argv[1:])
    monitor('python %s %s' % (os.path.join(os.path.abspath(os.path.dirname(__file__)), 'server.py'), args_str))
