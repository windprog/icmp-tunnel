#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/11
Desc    :   
"""
import platform
from .interface import BasePoll

OS = platform.system().lower()

if OS == 'linux':
    # Linux下采用epoll
    from .linux_poll import Poll
elif OS == 'freebsd' or OS == 'darwin':
    # FreeBSD下采用kqueue
    from .bsd_poll import Poll
else:
    # 其他使用通用方案select
    from .default_poll import Poll
