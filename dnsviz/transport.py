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

import base64
import bisect
import collections
import fcntl
import json
import os
import Queue
import random
import re
import select
import socket
import struct
import threading
import time
import urllib

import dns.exception

from ipaddr import IPAddr

MAX_PORT_BIND_ATTEMPTS=10
MAX_WAIT_FOR_REQUEST=30
HTTP_HEADER_END_RE = re.compile(r'(\r\n\r\n|\n\n|\r\r)')
HTTP_STATUS_RE = re.compile(r'^HTTP/\S+ (?P<status>\d+) ')
CONTENT_LENGTH_RE = re.compile(r'^Content-Length: (?P<length>\d+)', re.MULTILINE)
CHUNKED_ENCODING_RE = re.compile(r'^Transfer-Encoding: chunked(\r\n|\r|\n)', re.MULTILINE)
CHUNK_SIZE_RE = re.compile(r'^(?P<length>[0-9a-fA-F]+)(;[^\r\n]+)?(\r\n|\r|\n)')
CRLF_START_RE = re.compile(r'^(\r\n|\n|\r)')

class HTTPQueryTransportError(Exception):
    pass

class DNSQueryTransportMeta(object):
    def __init__(self, req, dst, tcp, timeout, dport, src=None, sport=None):
        self.req = req
        self.dst = dst
        self.tcp = tcp
        self.timeout = timeout
        self.dport = dport
        self.src = src
        self.sport = sport

        self.res = None
        self.err = None

        self.start_time = None
        self.end_time = None

    def serialize_response(self):
        if self.res is not None:
            res = base64.b64encode(self.res)
        else:
            res = None
        if self.err is None:
            err = None
            errno = None
        else:
            if isinstance(self.err, (socket.error, EOFError)):
                err = 'NETWORK_ERROR'
            elif isinstance(self.err, dns.exception.Timeout):
                err = 'TIMEOUT'
            else:
                err = 'ERROR'
            if hasattr(self.err, 'errno'):
                errno = self.err.errno
            else:
                errno = None
        d = collections.OrderedDict((
                ('res', res),
                ('src', self.src),
                ('sport', self.sport),
                ('start_time', self.start_time),
                ('end_time', self.end_time),
                ('err', err),
                ('errno', errno),
        ))
        return d

class DNSQueryTransportHandler(object):
    singleton = False

    def __init__(self, processed_queue=None, factory=None):
        self.req = None
        self.req_len = None
        self.req_index = None

        self.res = None
        self.res_len = None
        self.res_buf = None
        self.res_index = None
        self.err = None

        self.dst = None
        self.dport = None
        self.src = None
        self.sport = None

        self.transport_type = None

        self.timeout = None
        self._processed_queue = processed_queue
        self.factory = factory

        self.expiration = None
        self.sock = None
        self.sockfd = None
        self.start_time = None
        self.end_time = None

        self.qtms = []

    def _set_timeout(self, qtm):
        if self.timeout is None or qtm.timeout > self.timeout:
            self.timeout = qtm.timeout

    def add_qtm(self, qtm):
        if self.singleton and self.qtms:
            raise TypeError('Only one DNSQueryTransportMeta instance allowed for DNSQueryTransportHandlers of singleton type!')
        self.qtms.append(qtm)
        self._set_timeout(qtm)

    def finalize(self):
        assert self.res is not None or self.err is not None, 'Query must have been executed before finalize() can be called'

        # clear out any partial responses if there was an error
        if self.err is not None:
            self.res = None

    def init_req(self):
        raise NotImplemented

    def prepare(self):
        assert self.req is not None, 'Request must be initialized with init_req() before be added before prepare() can be called'

        self._prepare_socket()
        self.req_index = 0
        self.res = ''
        self.res_buf = ''
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

    def _set_socket_info(self):
        src, sport = self.sock.getsockname()[:2]
        self.src = IPAddr(src)
        self.sport = sport

    def connect(self):
        self.expiration = self.timeout + time.time()
        self._set_start_time()
        self._connect_socket()
        self._set_socket_info()

    def _connect_socket(self):
        try:
            self.sock.connect((self.dst, self.dport))
        except socket.error, e:
            if e.errno != socket.errno.EINPROGRESS:
                raise

    def _set_start_time(self):
        self.start_time = time.time()

    def _set_end_time(self):
        self.end_time = time.time()
        if self.start_time is None:
            self.start_time = self.end_time

    def cleanup(self):
        # set end (and start, if necessary) times, as appropriate
        self._set_end_time()

        # close socket
        if self.sock is not None:
            self.sock.close()

        # place in processed queue, if specified
        if self._processed_queue is not None:
            self._processed_queue.put(self)

    def do_write(self):
        try:
            self.req_index += self.sock.send(self.req[self.req_index:])
            if self.req_index >= self.req_len:
                return True
        except socket.error, e:
            self.err = e
            self.cleanup()
            return True

    def do_read(self):
        raise NotImplemented

    def do_timeout(self):
        raise NotImplemented

class DNSQueryTransportHandlerDNS(DNSQueryTransportHandler):
    require_queryid_match = True
    singleton = True

    def finalize(self):
        super(DNSQueryTransportHandlerDNS, self).finalize()
        qtm = self.qtms[0]
        qtm.src = self.src
        qtm.sport = self.sport
        qtm.res = self.res
        qtm.err = self.err
        qtm.start_time = self.start_time
        qtm.end_time = self.end_time

    def init_req(self):
        assert self.qtms, 'At least one DNSQueryTransportMeta must be added before init_req() can be called'

        qtm = self.qtms[0]

        self.dst = qtm.dst
        self.dport = qtm.dport
        self.src = qtm.src
        self.sport = qtm.sport

        self.req = qtm.req
        self.req_len = len(qtm.req)

        self._queryid_wire = self.req[:2]
        index = 12
        while ord(self.req[index]) != 0:
            index += ord(self.req[index]) + 1
        index += 4
        self._question_wire = self.req[12:index]

        if qtm.tcp:
            self.transport_type = socket.SOCK_STREAM
            self.req = struct.pack('!H', self.req_len) + self.req
            self.req_len += struct.calcsize('H')
        else:
            self.transport_type = socket.SOCK_DGRAM

    def _check_response_consistency(self):
        if self.require_queryid_match and self.res[:2] != self._queryid_wire:
            return False
        return True

    def do_read(self):
        # UDP
        if self.sock.type == socket.SOCK_DGRAM:
            try:
                self.res = self.sock.recv(65536)
                if self._check_response_consistency():
                    self.cleanup()
                    return True
                else:
                    self.res = ''
            except socket.error, e:
                self.err = e
                self.cleanup()
                return True

        # TCP
        else:
            try:
                if self.res_len is None:
                    if self.res_buf:
                        buf = self.sock.recv(1)
                    else:
                        buf = self.sock.recv(2)
                    if buf == '':
                        raise EOFError()

                    self.res_buf += buf
                    if len(self.res_buf) == 2:
                        self.res_len = struct.unpack('!H', self.res_buf)[0]

                if self.res_len is not None:
                    buf = self.sock.recv(self.res_len - self.res_index)
                    if buf == '':
                        raise EOFError()

                    self.res += buf
                    self.res_index = len(self.res)

                    if self.res_index >= self.res_len:
                        self.cleanup()
                        return True

            except (socket.error, EOFError), e:
                if isinstance(e, socket.error) and e.errno == socket.errno.EAGAIN:
                    pass
                else:
                    self.err = e
                    self.cleanup()
                    return True

    def do_timeout(self):
        self.err = dns.exception.Timeout()
        self.cleanup()

class DNSQueryTransportHandlerDNSLoose(DNSQueryTransportHandlerDNS):
    require_queryid_match = False

class DNSQueryTransportHandlerHTTP(DNSQueryTransportHandler):
    singleton = False

    def __init__(self, host, port, path, processed_queue=None, factory=None):
        super(DNSQueryTransportHandlerHTTP, self).__init__(processed_queue=processed_queue, factory=factory)

        self.host = host
        self.path = path

        try:
            addrinfo = socket.getaddrinfo(host, port)
        except socket.gaierror:
            raise HTTPQueryTransportError('Unable to resolve name of HTTP host')
        self.dst = IPAddr(addrinfo[0][4][0])

        self.transport_type = socket.SOCK_STREAM
        self.dport = port

        self.chunked_encoding = None

    def _set_timeout(self, qtm):
        timeout2 = qtm.timeout * 2
        if self.timeout is None or timeout2 > self.timeout:
            self.timeout = timeout2

    def _finalize_qtm(self, index, content):
        qtm = self.qtms[index]
        try:
            qtm_content = content[index]
        except IndexError:
            raise HTTPQueryTransportError('DNS response missing from HTTP response')

        if 'err' in qtm_content and qtm_content['err'] is not None:
            if qtm_content['err'] == 'NETWORK_ERROR':
                qtm.err = socket.error()
                if 'errno' in qtm_content and qtm_content['errno'] is not None:
                    try:
                        qtm.err.errno = int(qtm_content['errno'])
                    except ValueError:
                        raise HTTPQueryTransportError('Non-numeric value provided for errno in HTTP response: %s' % qtm_content['errno'])
            elif qtm_content['err'] == 'TIMEOUT':
                qtm.err = dns.exception.Timeout()
            else:
                raise HTTPQueryTransportError('Unknown DNS response error in HTTP response: %s' % qtm_content['err'])

        elif not ('res' in qtm_content and qtm_content['res'] is not None):
            raise HTTPQueryTransportError('No DNS response or response error found in HTTP response')

        else:
            try:
                qtm.res = base64.b64decode(qtm_content['res'])
            except TypeError:
                raise HTTPQueryTransportError('Base64 decoding of DNS response failed: %s' % qtm_content['res'])

        if 'src' in qtm_content and qtm_content['src'] is not None:
            try:
                qtm.src = IPAddr(qtm_content['src'])
            except ValueError:
                raise HTTPQueryTransportError('Invalid source IP address found in HTTP response: %s' % qtm_content['src'])
        elif not isinstance(qtm.err, socket.error):
            raise HTTPQueryTransportError('No source IP address included in HTTP response')

        if 'sport' in qtm_content and qtm_content['sport'] is not None:
            try:
                qtm.sport = int(qtm_content['sport'])
            except ValueError:
                raise HTTPQueryTransportError('Non-numeric value provided for source port in HTTP response: %s' % qtm_content['sport'])
            if qtm.sport < 0 or qtm.sport > 65535:
                raise HTTPQueryTransportError('Invalid value provided for source port in HTTP response %s' % qtm_content['sport'])
        elif not isinstance(qtm.err, socket.error):
            raise HTTPQueryTransportError('No source port value included in HTTP response')

        if 'start_time' in qtm_content and qtm_content['start_time'] is not None:
            try:
                qtm.start_time = float(qtm_content['start_time'])
            except ValueError:
                raise HTTPQueryTransportError('Non-float value provided for start time in HTTP response: %s' % qtm_content['start_time'])
            if qtm.start_time < 0:
                raise HTTPQueryTransportError('Negative value provided for start time in HTTP response: %s' % qtm_content['start_time'])
        else:
            raise HTTPQueryTransportError('No start time value included in HTTP response')

        if 'end_time' in qtm_content and qtm_content['end_time'] is not None:
            try:
                qtm.end_time = float(qtm_content['end_time'])
            except ValueError:
                raise HTTPQueryTransportError('Non-float value provided for end time in HTTP response: %s' % qtm_content['end_time'])
            if qtm.end_time < 0:
                raise HTTPQueryTransportError('Negative value provided for end time in HTTP response: %s' % qtm_content['end_time'])
        else:
            raise HTTPQueryTransportError('No end time value included in HTTP response')

        if qtm.end_time < qtm.start_time:
            raise HTTPQueryTransportError('End time is before start time in HTTP response')

    def finalize(self):
        super(DNSQueryTransportHandlerHTTP, self).finalize()

        # if there was an error, then re-raise it here
        if self.err is not None:
            raise self.err

        # if there is no content, raise an exception
        if self.res is None:
            raise HTTPQueryTransportError('No content in HTTP response')

        # load the json content
        try:
            content = json.loads(self.res)
        except ValueError:
            raise HTTPQueryTransportError('JSON decoding of HTTP response failed: %s' % self.res)

        for i in range(len(self.qtms)):
            self._finalize_qtm(i, content)

    def _post_data(self, index, msg, dst, tcp, timeout, dport, src, sport):
        msg = urllib.quote(base64.b64encode(msg))
        if tcp:
            tcp = 't'
        else:
            tcp = 'f'
        s = 'msg%d=%s&dst%d=%s&tcp%d=%s&timeout%d=%f' % (index, msg, index, dst, index, tcp, index, timeout)
        if dport is not None:
            s += '&dport%d=%d' % (index, dport)
        if src is not None:
            s += '&src%d=%s' % (index, src)
        if sport is not None:
            s += '&sport%d=%d' % (index, sport)
        return s

    def init_req(self):
        data = ''
        for i in range(len(self.qtms)):
            qtm = self.qtms[i]
            data += '&' + self._post_data(i, qtm.req, qtm.dst, qtm.tcp, qtm.timeout, qtm.dport, qtm.src, qtm.sport)
        data = data[1:]
        self.req = 'POST %s HTTP/1.1\nHost: %s\nUser-Agent: DNSViz/0.5.0\nAccept: */*\nContent-Length: %d\nContent-Type: application/x-www-form-urlencoded\n\n%s' % (self.path, self.host, len(data), data)
        self.req_len = len(self.req)

    def do_write(self):
        val = super(DNSQueryTransportHandlerHTTP, self).do_write()
        if self.err is not None:
            self.err = HTTPQueryTransportError('Error making HTTP request: %s' % self.err)
        return val

    def do_read(self):
        try:
            buf = self.sock.recv(65536)
            if buf == '':
                raise EOFError
            self.res_buf += buf

            # still reading status and headers
            if self.chunked_encoding is None and self.res_len is None:
                headers_end_match = HTTP_HEADER_END_RE.search(self.res_buf)
                if headers_end_match is not None:
                    headers = self.res_buf[:headers_end_match.start()]
                    self.res_buf = self.res_buf[headers_end_match.end():]

                    # check HTTP status
                    status_match = HTTP_STATUS_RE.search(headers)
                    if status_match is None:
                        self.err = HTTPQueryTransportError('Malformed HTTP status line')
                        self.cleanup()
                        return True
                    status = int(status_match.group('status'))
                    if status != 200:
                        self.err = HTTPQueryTransportError('%d HTTP status' % status)
                        self.cleanup()
                        return True

                    # get content length or determine whether "chunked"
                    # transfer encoding is used
                    content_length_match = CONTENT_LENGTH_RE.search(headers)
                    if content_length_match is not None:
                        self.chunked_encoding = False
                        self.res_len = int(content_length_match.group('length'))
                    else:
                        self.chunked_encoding = CHUNKED_ENCODING_RE.search(headers) is not None

            # handle chunked encoding first
            if self.chunked_encoding:
                # look through as many chunks as are readily available
                # (without having to read from socket again)
                while self.res_buf:
                    if self.res_len is None:
                        # looking for chunk length

                        # strip off beginning CRLF, if any
                        # (this is for chunks after the first one)
                        crlf_start_match = CRLF_START_RE.search(self.res_buf)
                        if crlf_start_match is not None:
                            self.res_buf = self.res_buf[crlf_start_match.end():]

                        # find the chunk length
                        chunk_len_match = CHUNK_SIZE_RE.search(self.res_buf)
                        if chunk_len_match is not None:
                            self.res_len = int(chunk_len_match.group('length'), 16)
                            self.res_buf = self.res_buf[chunk_len_match.end():]
                            self.res_index = 0
                        else:
                            # if we don't currently know the length of the next
                            # chunk, and we don't have enough data to find the
                            # length, then break out of the loop because we
                            # don't have any more data to go off of.
                            break

                    if self.res_len is not None:
                        # we know a length of the current chunk

                        if self.res_len == 0:
                            # no chunks left, so clean up and return
                            self.cleanup()
                            return True

                        # read remaining bytes
                        bytes_remaining = self.res_len - self.res_index
                        if len(self.res_buf) > bytes_remaining:
                            self.res += self.res_buf[:bytes_remaining]
                            self.res_index = 0
                            self.res_buf = self.res_buf[bytes_remaining:]
                            self.res_len = None
                        else:
                            self.res += self.res_buf
                            self.res_index += len(self.res_buf)
                            self.res_buf = ''

            elif self.chunked_encoding == False:
                # output is not chunked, so we're either reading until we've
                # read all the bytes specified by the content-length header (if
                # specified) or until the server closes the connection (or we
                # time out)
                if self.res_len is not None:
                    bytes_remaining = self.res_len - self.res_index
                    self.res += self.res_buf[:bytes_remaining]
                    self.res_buf = self.res_buf[bytes_remaining:]
                    self.res_index = len(self.res)

                    if self.res_index >= self.res_len:
                        self.cleanup()
                        return True
                else:
                    self.res += self.res_buf
                    self.res_buf = ''

        except (socket.error, EOFError), e:
            if isinstance(e, socket.error) and e.errno == socket.errno.EAGAIN:
                pass
            else:
                # if we weren't passed any content length header, and we're not
                # using chunked encoding, then don't throw an error.  If the
                # content was bad, then it will be reflected in the decoding of
                # the content
                if self.chunked_encoding == False and self.res_len is None:
                    pass
                else:
                    self.err = e
                self.cleanup()
                return True

    def do_timeout(self):
        self.err = HTTPQueryTransportError('HTTP request timed out')
        self.cleanup()

class DNSQueryTransportHandlerFactory(object):
    cls = DNSQueryTransportHandler

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.kwargs['factory'] = self

    def build(self, **kwargs):
        for name in self.kwargs:
            if name not in kwargs:
                kwargs[name] = self.kwargs[name]
        return self.cls(*self.args, **kwargs)

class DNSQueryTransportHandlerDNSFactory(DNSQueryTransportHandlerFactory):
    cls = DNSQueryTransportHandlerDNS

class DNSQueryTransportHandlerHTTPFactory(DNSQueryTransportHandlerFactory):
    cls = DNSQueryTransportHandlerHTTP

class _DNSQueryTransportManager:
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

                if qtm.do_write():
                    if qtm.err is not None:
                        finished_fds.append(fd)
                    else:
                        wlist_in.remove(fd)
                        rlist_in.append(fd)

            # handle the responses
            for fd in rlist_out:
                if fd == self._notify_read_fd:
                    continue

                qtm = query_meta[fd]

                if qtm.do_read():
                    finished_fds.append(fd)

            # handle the expired queries
            future_index = bisect.bisect_right(expirations, ((time.time(), None)))
            for i in range(future_index):
                qtm = expirations[i][1]

                # perhaps this query actually finished earlier in the loop
                if qtm.end_time is not None:
                    continue

                qtm.do_timeout()
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
                # empty the pipe
                os.read(self._notify_read_fd, 65536)

                while True:
                    try:
                        qtm = self._query_queue.get_nowait()
                        try:
                            qtm.prepare()
                            qtm.connect()
                        except socket.error, e:
                            qtm.err = e
                            qtm.cleanup()
                            if qtm in self._event_map:
                                self._event_map[qtm].set()
                        else:
                            # if we successfully bound and connected the
                            # socket, then put this socket in the write fd list
                            fd = qtm.sock.fileno()
                            query_meta[fd] = qtm
                            bisect.insort(expirations, (qtm.expiration, qtm))
                            wlist_in.append(fd)
                    except Queue.Empty:
                        break

class DNSQueryTransportManager:
    def __init__(self):
        self._th = _DNSQueryTransportManager()

    def __del__(self):
        self.close()

    def query(self, qtm):
        return self._th.query(qtm)

    def query_nowait(self, qtm):
        return self._th.query_nowait(qtm)

    def close(self):
        return self._th.close()
