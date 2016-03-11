#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/11
Desc    :   
"""
from select import epoll, EPOLLIN, EPOLLERR
from interface import BasePoll


class Poll(BasePoll):
    def __init__(self):
        super(Poll, self).__init__()
        self.epoll = epoll()

    def register(self, f):
        self.epoll.register(f, EPOLLIN | EPOLLERR)

    def unregister(self, f):
        self.epoll.unregister(f)

    def wait(self, timeout=0.01):
        return self.epoll.poll(timeout=timeout)
