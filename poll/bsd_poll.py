#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/11
Desc    :   
"""
from select import kqueue, kevent, KQ_EV_ADD, KQ_EV_DELETE, KQ_FILTER_READ
from interface import BasePoll


class Poll(BasePoll):
    def __init__(self):
        super(Poll, self).__init__()
        self.kqueue = kqueue()

    def register(self, f):
        self.kqueue.control([kevent(f, KQ_FILTER_READ, KQ_EV_ADD)], 0)

    def unregister(self, f):
        self.kqueue.control([kevent(f, KQ_FILTER_READ, KQ_EV_DELETE)], 0)

    def wait(self, timeout=0.01):
        for event in self.kqueue.control(None, 1, timeout):
            yield event.ident, event.filter
