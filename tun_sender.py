#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/11
Desc    :   
"""
import os
from interface import BaseTun, BUFFER_SIZE
from tun import Tun


class TunInstance(BaseTun):
    def __init__(self, tun_ip, tun_peer):
        self.tfd, self.tname = Tun().create_tun(tun_ip, tun_peer)

    def send(self, data):
        os.write(self.tfd, data)

    def recv(self):
        return [os.read(self.tfd, BUFFER_SIZE)]

    def tfd(self):
        return self.tfd
