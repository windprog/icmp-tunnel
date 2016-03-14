#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/14
Desc    :
"""
import socket
import traceback
from packet import TunnelPacket
from interface import BaseSender, BUFFER_SIZE
from cmd_control import CommandControl


class TCPSender(BaseSender):
    def __init__(self, server_ip=''):
        self.server_ip = server_ip
        self.port = 0x4147
        self.pending_list = []
        self.cmd_control = CommandControl(self)
        self.debug = False

    def send(self, data):
        try:
            ret = self.connection.sendall(data)
            if self.debug:
                print 'send ip:%s type:tcp port:%s data_count:%s data:%s' % (
                    self.server_ip, self.port, len(data), repr(data))
            return ret
        except socket.error, e:
            print 'socket error', e.errno

    def f(self):
        return self.connection

    def fd(self):
        return self.connection.fileno()


class ServerTCPSender(TCPSender):
    def __init__(self, server_ip=''):
        super(ServerTCPSender, self).__init__()
        self.tcpfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcpfd.bind(("", 0x4147))
        self.tcpfd.listen(1)
        print 'waiting for a connection'
        self.connection, client_address = self.tcpfd.accept()
        self.server_ip = client_address[0]
        self.port = client_address[1]

    def recv(self):
        data = self.connection.recv(BUFFER_SIZE)
        is_command = self.cmd_control.check(data)
        if self.debug:
            print 'recv ip:%s type:tcp port:%s data_count:%s data:%s' % (
                self.server_ip, self.port, len(data), repr(data))
        if is_command:
            return []
        return [data]


class ClientTCPSender(TCPSender):
    def __init__(self, server_ip=''):
        super(ClientTCPSender, self).__init__()
        self.tcpfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcpfd.connect((server_ip, 0x4147))
        self.connection = self.tcpfd

    def recv(self):
        data = self.connection.recv(BUFFER_SIZE)
        is_command = self.cmd_control.check(data)
        if self.debug:
            print 'recv ip:%s type:tcp port:%s data_count:%s data:%s' % (
                self.server_ip, self.port, len(data), repr(data))
        if is_command:
            return []
        return [data]


if __name__ == '__main__':
    import sys, select, time

    if not sys.argv[1:]:
        sender = ServerTCPSender()
    else:
        # 预设server ip
        sender = ClientTCPSender(sys.argv[1])
    sender.debug = True
    next_sleep_time = 0.01

    stop = False


    def print_result():
        try:
            while not stop:
                rset = select.select([sender.f()], [], [], next_sleep_time)[0]
                for r in rset:
                    if r == sender.f():
                        result = sender.recv()
                        print repr(result), [len(item) for item in result]
        except KeyboardInterrupt:
            pass
        except:
            print traceback.format_exc()
        finally:
            # Cleanup something.
            pass


    import threading

    thread = threading.Thread(target=print_result)
    thread.start()

    try:
        while True:
            data = raw_input('input data：')
            if not data:
                stop = True
                break
            if data.isdigit():
                next_sleep_time = int(data)
                continue
            else:
                next_sleep_time = 0.01
            print u'-' * 50
            sender.send(data)
    except KeyboardInterrupt:
        pass
    except:
        print traceback.format_exc()
    finally:
        # Cleanup something.
        pass
