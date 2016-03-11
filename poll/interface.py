#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/11
Desc    :   
"""
from abc import ABCMeta, abstractmethod


class BasePoll(object):
    __metaclass__ = ABCMeta

    def __init__(self):
        self.fmap = {}

    def add(self, fd):
        self.fmap[fd.fileno()] = fd
        self.register(fd)

    @abstractmethod
    def register(self, f):
        pass

    @abstractmethod
    def unregister(self, f):
        pass

    @abstractmethod
    def wait(self, timeout=0.01):
        pass
