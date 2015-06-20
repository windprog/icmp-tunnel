#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015 Windpro

Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   15/6/20
Desc    :   
"""
from abc import ABCMeta, abstractmethod


class NodeInfo(object):
    def __init__(self, ip, tun_info):
        pass


class TunInfo(object):
    def __init__(self, addr, dstaddr):
        self.addr = addr
        self.dstaddr = dstaddr


class BaseTun(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, addr, dstaddr, netmask="255.255.255.0", mtu=1300):
        pass

    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def write(self, data):
        pass

    @abstractmethod
    def read(self, length=2048):
        pass

class BaseDhcpControl(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def new(self, session_id):
        pass


class BaseServer(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def run(self):
        pass


class BaseConnection(object):
    __metaclass__ = ABCMeta
    connections = {}  # key:(session_id, _src数据包来源ip), value connection

    @abstractmethod
    def login(self, username, password):
        pass

    @abstractmethod
    def send(self, data):
        pass

    @abstractmethod
    def send_command(self, info):
        pass

    @abstractmethod
    def close(self):
        pass


class BasePacketControl(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def from_tun(self, data):
        pass

    @abstractmethod
    def from_internet(self, packet):
        pass

    @abstractmethod
    def get_command(self, command_id):
        pass


class BaseIoCallback(object):
    __metaclass__ = ABCMeta

    def __init__(self, source):
        pass

    @abstractmethod
    def __call__(self):
        pass


class BaseIoControl(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def register(self, fileno, io_callback):
        pass

    @abstractmethod
    def serve_forever(self):
        pass
