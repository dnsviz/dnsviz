#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2014-2015 VeriSign, Inc.
#
# DNSViz is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# DNSViz is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with DNSViz.  If not, see <http://www.gnu.org/licenses/>.
#

import bisect
import fcntl
import os
import Queue
import random
import select
import socket
import struct
import threading
import time

import dns.exception

from ipaddr import IPAddr

MAX_PORT_BIND_ATTEMPTS=10
MAX_WAIT_FOR_REQUEST=30

class DNSQueryTransportMeta:
    require_queryid_match = True
    require_question_case_match = True

    def __init__(self, msg, dst, tcp, timeout, dport=53, src=None, sport=None, processed_queue=None):
        self.req = msg
        self.req_len = len(self.req)
        self.req_index = None

        self.queryid_wire = self.req[:2]
        index = 12
        while ord(self.req[index]) != 0:
            index += ord(self.req[index]) + 1
        index += 4
        self.question_wire = self.req[12:index]

        if tcp:
            self.transport_type = socket.SOCK_STREAM
            self.req = struct.pack('!H', self.req_len) + self.req
            self.req_len += struct.calcsize('H')
        else:
            self.transport_type = socket.SOCK_DGRAM

        self.res = None
        self.res_len = None
        self.res_len_buf = None
        self.res_index = None
        self.err = None

        self.dst = dst
        self.dport = dport
        self.src = src
        self.sport = sport

        self.timeout = timeout
        self._processed_queue = processed_queue

        self.expiration = None
        self.sock = None
        self.sockfd = None
        self.start_time = None
        self.end_time = None

    def prepare(self):
        self._prepare_socket()
        self.req_index = 0
        self.res = ''
        self.res_len_buf = ''
        self.res_index = 0

    def _prepare_socket(self):
        if self.dst.version == 6:
            af = socket.AF_INET6
        else:
            af = socket.AF_INET

        self.sock = socket.socket(af, self.transport_type)
        self.sock.setblocking(0)
        self._bind_socket()

    def _bind_socket(self):
        if self.src is not None:
            src = self.src
        else:
            if self.sock.family == socket.AF_INET6:
                src = IPAddr('::')
            else:
                src = IPAddr('0.0.0.0')

        if self.sport is not None:
            self.sock.bind((src, self.sport))
        else:
            i = 0
            while True:
                sport = random.randint(1024, 65535)
                try:
                    self.sock.bind((src, sport))
                    break
                except socket.error, e:
                    i += 1
                    if i > MAX_PORT_BIND_ATTEMPTS or e.errno != socket.errno.EADDRINUSE:
                        raise
        self.sockfd = self.sock.fileno()

    def connect(self):
        self.expiration = self.timeout + time.time()
        self.start_time = time.time()
        self._connect_socket()
        src, sport = self.sock.getsockname()[:2]
        self.src = IPAddr(src)
        self.sport = sport

    def _connect_socket(self):
        try:
            self.sock.connect((self.dst, self.dport))
        except socket.error, e:
            if e.errno != socket.errno.EINPROGRESS:
                raise

    def cleanup(self):
        self.end_time = time.time()
        if self.start_time is None:
            self.start_time = self.end_time
        if self.sock is not None:
            self.sock.close()

        # clear out any partial responses if there was an error
        if self.err is not None:
            self.res = None

        # place in processed queue, if specified
        if self._processed_queue is not None:
            self._processed_queue.put(self)

    def check_response_consistency(self):
        if self.require_queryid_match and self.res[:2] != self.queryid_wire:
            return False
        # if a question case match is required :
        # check that if the question count is greater than 0 and
        # there is actually a question section (message > 12), then
        # make sure the case matches
        if self.require_question_case_match and \
                self.res[4:6] != '\x00\x00' and len(self.res) > 12 and \
                self.res[12:12+len(self.question_wire)] != self.question_wire:
            return False
        return True

class DNSQueryTransportMetaLoose(DNSQueryTransportMeta):
    require_queryid_match = False
    require_question_case_match = False

class _DNSQueryTransport:
    '''A class that handles'''

    #TODO might need FD_SETSIZE to support lots of fds
    def __init__(self):
        self._notify_read_fd, self._notify_write_fd = os.pipe()
        fcntl.fcntl(self._notify_read_fd, fcntl.F_SETFL, os.O_NONBLOCK)
        self._query_queue = Queue.Queue()
        self._event_map = {}

        self._close = threading.Event()
        t = threading.Thread(target=self._loop)
        t.start()

    def close(self):
        self._close.set()
        os.write(self._notify_write_fd, struct.pack('!B', 0))

    def query(self, qtm):
        self._event_map[qtm] = threading.Event()
        self._query(qtm)
        self._event_map[qtm].wait()
        del self._event_map[qtm]

    def query_nowait(self, qtm):
        self._query(qtm)

    def _query(self, qtm):
        self._query_queue.put(qtm)
        os.write(self._notify_write_fd, struct.pack('!B', 0))

    def _loop(self):
        '''Return the data resulting from a UDP transaction.'''

        query_meta = {}
        expirations = []

        # initalize "in" fds for select
        rlist_in = [self._notify_read_fd]
        wlist_in = []
        xlist_in = []

        while True:
            # determine the new expiration
            if expirations:
                timeout = max(expirations[0][0] - time.time(), 0)
            else:
                timeout = MAX_WAIT_FOR_REQUEST

            finished_fds = []

            rlist_out, wlist_out, xlist_out = select.select(rlist_in, wlist_in, xlist_in, timeout)

            # if we have been signalled to exit, then do that
            if self._close.is_set():
                break

            # handle the requests
            for fd in wlist_out:
                qtm = query_meta[fd]

                try:
                    qtm.req_index += qtm.sock.send(qtm.req[qtm.req_index:])
                    if qtm.req_index >= qtm.req_len:
                        wlist_in.remove(fd)
                        rlist_in.append(fd)
                except socket.error, e:
                    qtm.err = e
                    qtm.cleanup()
                    finished_fds.append(fd)

            # handle the responses
            for fd in rlist_out:
                if fd == self._notify_read_fd:
                    continue

                qtm = query_meta[fd]

                # UDP
                if qtm.sock.type == socket.SOCK_DGRAM:
                    try:
                        qtm.res = qtm.sock.recv(65536)
                        if qtm.check_response_consistency():
                            qtm.cleanup()
                            finished_fds.append(fd)
                        else:
                            qtm.res = ''
                    except socket.error, e:
                        qtm.err = e
                        qtm.cleanup()
                        finished_fds.append(fd)

                # TCP
                else:
                    try:
                        if qtm.res_len is None:
                            if qtm.res_len_buf:
                                buf = qtm.sock.recv(1)
                            else:
                                buf = qtm.sock.recv(2)
                            if buf == '':
                                raise EOFError()

                            qtm.res_len_buf += buf
                            if len(qtm.res_len_buf) == 2:
                                qtm.res_len = struct.unpack('!H', qtm.res_len_buf)[0]

                        if qtm.res_len is not None:
                            buf = qtm.sock.recv(qtm.res_len - qtm.res_index)
                            if buf == '':
                                raise EOFError()

                            qtm.res += buf
                            qtm.res_index = len(qtm.res)

                            if qtm.res_index >= qtm.res_len:
                                qtm.cleanup()
                                finished_fds.append(fd)

                    except (socket.error, EOFError), e:
                        if isinstance(e, socket.error) and e.errno == socket.errno.EAGAIN:
                            pass
                        else:
                            qtm.err = e
                            qtm.cleanup()
                            finished_fds.append(fd)

            # handle the expired queries
            future_index = bisect.bisect_right(expirations, ((time.time(), None)))
            for i in range(future_index):
                qtm = expirations[i][1]

                # perhaps this query actually finished earlier in the loop
                if qtm.end_time is not None:
                    continue

                qtm.err = dns.exception.Timeout()
                qtm.cleanup()
                finished_fds.append(qtm.sockfd)
            expirations = expirations[future_index:]

            # for any fds that need to be finished, do it now
            for fd in finished_fds:
                try:
                    rlist_in.remove(fd)
                except ValueError:
                    wlist_in.remove(fd)
                if query_meta[fd] in self._event_map:
                    self._event_map[query_meta[fd]].set()
                del query_meta[fd]

            # handle the new queries
            if self._notify_read_fd in rlist_out:
                while True:
                    try:
                        qtm = self._query_queue.get_nowait()
                        try:
                            qtm.prepare()
                            qtm.connect()

                            # if we successfully bound and connected the
                            # socket, then put this socket in the write fd list
                            fd = qtm.sock.fileno()
                            query_meta[fd] = qtm
                            bisect.insort(expirations, (qtm.expiration, qtm))
                            wlist_in.append(fd)
                        except socket.error, e:
                            qtm.err = e
                            qtm.cleanup()
                    except Queue.Empty:
                        break

                # empty the pipe
                os.read(self._notify_read_fd, 65535)

class DNSQueryTransport:
    def __init__(self):
        self._th = _DNSQueryTransport()

    def __del__(self):
        self._th.close()

    def query(self, qtm):
        return self._th.query(qtm)

    def query_nowait(self, qtm):
        return self._th.query_nowait(qtm)
