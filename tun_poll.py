#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/13
Desc    :   
"""
from poll import OS
from poll import Poll as DefaultPoll, BasePoll
from poll.default_poll import Poll as SelectPoll
from interface import BUFFER_SIZE


class LinuxTunPoll(DefaultPoll):
    def register_socket(self, f):
        return self.register(f)

    def register_tun(self, f):
        return self.register(f)


if OS == 'darwin':
    from poll.default_poll import Poll as SelectPoll
    import os
    import sys
    import threading
    #
    #
    # class SelectTun(object):
    #     def __init__(self, tun_fd):
    #         self.poll = SelectPoll()
    #         self.poll.register(tun_fd)
    #         self.tun_fd = tun_fd
    #         self.read_pipe, self.write_pipe = os.pipe()
    #         # processid = os.fork()
    #         # if not processid:
    #             # child process
    #             # self.forever()
    #         # thread exp
    #         # self.thread = threading.Thread(target=self.forever)
    #         # self.thread.start()
    #
    #     def forever(self):
    #         while True:
    #             self.process()
    #
    #     def process(self):
    #         for fileno, event in self.poll.wait(timeout=0.001):
    #             if fileno == self.tun_fd:
    #                 os.write(self.write_pipe, '-')
    #                 print 'recv tun'

    class BsdTunPoll(LinuxTunPoll):
        # TODO try to fix
        def __init__(self):
            super(BsdTunPoll, self).__init__()
            self.select_poll = SelectPoll()

        def register_tun(self, f):
            # 只能运行一次
            self.select_poll.register(f)

        def wait(self, timeout=0.001):
            for event in self.kqueue.control(None, 1, timeout):
                yield event.ident, event.filter
            for fileno, event in self.select_poll.wait(timeout=0.01):
                yield fileno, event

    class SelectTunPoll(SelectPoll):
        def register_socket(self, f):
            return self.register(f)

        def register_tun(self, f):
            return self.register(f)


    # TunPoll = BsdTunPoll
    TunPoll = SelectTunPoll
else:
    TunPoll = LinuxTunPoll
