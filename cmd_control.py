#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/11
Desc    :   
"""
import time


class CommandControl(object):
    def __init__(self, pkg_sender):
        self.pkg_sender = pkg_sender

    def recv_heartbeat(self, req_data):
        print 'recv heartbeat from %s time:%s' % (self.pkg_sender.server_ip, time.time())
        res_data = "res:" + req_data[4:]
        self.pkg_sender.send(res_data)

    def check(self, data):
        if data.startswith('res:') or data.startswith('req:'):
            if data.startswith('req:'):
                self.recv_heartbeat(data)
                return True
            elif data.startswith('res:'):
                # print 'recv heartbeat response'
                pass
