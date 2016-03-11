#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/11
Desc    :   
"""
from abc import ABCMeta, abstractmethod

BUFFER_SIZE = 8192


#
# 各驱动调用接口规范。
#


class BaseSender(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def send(self, data):
        pass

    @abstractmethod
    def recv(self):
        # 读到不能读 返回一个列表
        pass

    @abstractmethod
    def fd(self):
        pass

    def __str__(self):
        return repr(self)


class BaseTun(BaseSender):
    __metaclass__ = ABCMeta
