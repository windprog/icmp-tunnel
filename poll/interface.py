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

    def add(self, f):
        # 添加文件
        self.fmap[f.fileno()] = f
        self.register(f)

    @abstractmethod
    def register(self, f):
        # f 文件描述符
        pass

    @abstractmethod
    def unregister(self, f):
        # f 文件描述符
        pass

    @abstractmethod
    def wait(self, timeout=0.01):
        pass