#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/11
Desc    :   全平台select方案
"""
import select
from interface import BasePoll


class Poll(BasePoll):
    def __init__(self):
        super(Poll, self).__init__()
        self._wait_select_list = []
        self.SELECT_NAME = '_select_rset'

    def register(self, f):
        self._wait_select_list.append(f)

    def unregister(self, f):
        self._wait_select_list.remove(f)
        if hasattr(self, self.SELECT_NAME):
            delattr(self, self.SELECT_NAME)

    def wait(self, timeout=0.01):
        rset = select.select(self._wait_select_list, [], [], timeout)[0]
        for r in rset:
            yield r.fileno(), None
