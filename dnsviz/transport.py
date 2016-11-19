#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2014-2016 VeriSign, Inc.
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

from __future__ import unicode_literals

import base64
import bisect
import codecs
import errno
import fcntl
import json
import os
import random
import re
import select
import socket
import ssl
import struct
import threading
import time

# minimal support for python2.6
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

# python3/python2 dual compatibility
try:
    import queue
except ImportError:
    import Queue as queue
try:
    import urllib.parse
except ImportError:
    import urlparse
    import urllib
    urlquote = urllib
else:
    urlparse = urllib.parse
    urlquote = urllib.parse

import dns.exception

from .ipaddr import IPAddr, ANY_IPV6, ANY_IPV4
from .format import latin1_binary_to_string as lb2s

DNS_TRANSPORT_VERSION = 1.0

MAX_PORT_BIND_ATTEMPTS=10
MAX_WAIT_FOR_REQUEST=30
HTTP_HEADER_END_RE = re.compile(r'(\r\n\r\n|\n\n|\r\r)')
HTTP_STATUS_RE = re.compile(r'^HTTP/\S+ (?P<status>\d+) ')
CONTENT_LENGTH_RE = re.compile(r'^Content-Length: (?P<length>\d+)', re.MULTILINE)
CHUNKED_ENCODING_RE = re.compile(r'^Transfer-Encoding: chunked(\r\n|\r|\n)', re.MULTILINE)
CHUNK_SIZE_RE = re.compile(r'^(?P<length>[0-9a-fA-F]+)(;[^\r\n]+)?(\r\n|\r|\n)')
CRLF_START_RE = re.compile(r'^(\r\n|\n|\r)')

class RemoteQueryTransportError(Exception):
    pass

class TransportMetaDeserializationError(Exception):
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

    def serialize_request(self):
        d = OrderedDict()
        d['req'] = lb2s(base64.b64encode(self.req))
        d['dst'] = self.dst
        d['dport'] = self.dport
        if self.src is not None:
            d['src'] = self.src
        if self.sport is not None:
            d['sport'] = self.sport
        d['tcp'] = self.tcp
        d['timeout'] = int(self.timeout*1000)
        return d

    @classmethod
    def deserialize_request(cls, d):
        if 'req' not in d or d['req'] is None:
            raise TransportMetaDeserializationError('Missing "req" field in input.')
        try:
            req = base64.b64decode(d['req'])
        except TypeError:
            raise TransportMetaDeserializationError('Base64 decoding DNS request failed: %s' % d['req'])

        if 'dst' not in d or d['dst'] is None:
            raise TransportMetaDeserializationError('Missing "dst" field in input.')
        try:
            dst = IPAddr(d['dst'])
        except ValueError:
            raise TransportMetaDeserializationError('Invalid destination IP address: %s' % d['dst'])

        if 'dport' not in d or d['dport'] is None:
            raise TransportMetaDeserializationError('Missing "dport" field in input.')
        try:
            dport = int(d['dport'])
            if dport < 0 or dport > 65535:
                raise ValueError()
        except ValueError:
            raise TransportMetaDeserializationError('Invalid destination port: %s' % d['dport'])

        if 'src' not in d or d['src'] is None:
            src = None
        else:
            try:
                src = IPAddr(d['src'])
            except ValueError:
                raise TransportMetaDeserializationError('Invalid source IP address: %s' % d['src'])

        if 'sport' not in d or d['sport'] is None:
            sport = None
        else:
            try:
                sport = int(d['sport'])
                if sport < 0 or sport > 65535:
                    raise ValueError()
            except ValueError:
                raise TransportMetaDeserializationError('Invalid source port: %s' % d['sport'])

        if 'tcp' not in d or d['tcp'] is None:
            raise TransportMetaDeserializationError('Missing "tcp" field in input.')
        else:
            tcp = bool(d['tcp'])

        if 'timeout' not in d or d['timeout'] is None:
            raise TransportMetaDeserializationError('Missing "timeout" field in input.')
        else:
            try:
                timeout = int(d['timeout'])/1000.0
            except ValueError:
                raise TransportMetaDeserializationError('Invalid timeout value: %s' % d['timeout'])

        return cls(req, dst, tcp, timeout, dport, src, sport)

    def serialize_response(self):
        d = OrderedDict()
        if self.res is not None:
            d['res'] = lb2s(base64.b64encode(self.res))
        else:
            d['res'] = None
        if self.err is not None:
            if isinstance(self.err, (socket.error, EOFError)):
                d['err'] = 'NETWORK_ERROR'
            elif isinstance(self.err, dns.exception.Timeout):
                d['err'] = 'TIMEOUT'
            else:
                d['err'] = 'ERROR'
            if hasattr(self.err, 'errno'):
                errno_name = errno.errorcode.get(self.err.errno, None)
                if errno_name is not None:
                    d['errno'] = errno_name
        d['src'] = self.src
        d['sport'] = self.sport
        d['time_elapsed'] = int((self.end_time - self.start_time)*1000)
        return d

    def deserialize_response(self, d):
        if 'err' in d and d['err'] is not None:
            if d['err'] == 'NETWORK_ERROR':
                self.err = socket.error()
                if 'errno' in d and d['errno'] is not None:
                    if hasattr(errno, d['errno']):
                        self.err.errno = getattr(errno, d['errno'])
                    else:
                        raise TransportMetaDeserializationError('Unknown errno name: %s' % d['errno'])
            elif d['err'] == 'TIMEOUT':
                self.err = dns.exception.Timeout()
            else:
                raise TransportMetaDeserializationError('Unknown DNS response error: %s' % d['err'])

        elif not ('res' in d and d['res'] is not None):
            raise TransportMetaDeserializationError('Missing DNS response or response error in input.')

        else:
            try:
                self.res = base64.b64decode(d['res'])
            except TypeError:
                raise TransportMetaDeserializationError('Base64 decoding of DNS response failed: %s' % d['res'])

        if 'src' in d and d['src'] is not None:
            try:
                self.src = IPAddr(d['src'])
            except ValueError:
                raise TransportMetaDeserializationError('Invalid source IP address: %s' % d['src'])
        elif not isinstance(self.err, socket.error):
            raise TransportMetaDeserializationError('Missing "src" field in input')

        if 'sport' in d and d['sport'] is not None:
            try:
                self.sport = int(d['sport'])
                if self.sport < 0 or self.sport > 65535:
                    raise ValueError()
            except ValueError:
                raise TransportMetaDeserializationError('Invalid source port: %s' % d['sport'])
        elif not isinstance(self.err, socket.error):
            raise TransportMetaDeserializationError('Missing "sport" field in input.')

        if 'time_elapsed' in d and d['time_elapsed'] is not None:
            try:
                elapsed = int(d['time_elapsed'])
                if elapsed < 0:
                    raise ValueError()
            except ValueError:
                raise TransportMetaDeserializationError('Invalid time elapsed value: %s' % d['time_elapsed'])
        else:
            raise TransportMetaDeserializationError('Missing "time_elapsed" field in input.')

        self.end_time = time.time()
        self.start_time = self.end_time - (elapsed/1000.0)

class DNSQueryTransportHandler(object):
    singleton = False
    allow_loopback_query = False
    allow_private_query = False
    timeout_baseline = 0.0

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

    def _check_source(self):
        if self.src in (ANY_IPV6, ANY_IPV4):
            self.src = None

    def finalize(self):
        assert self.res is not None or self.err is not None, 'Query must have been executed before finalize() can be called'

        self._check_source()

        # clear out any partial responses if there was an error
        if self.err is not None:
            self.res = None

    def init_req(self):
        raise NotImplemented

    def _init_res_buffer(self):
        self.res = b''
        self.res_buf = b''
        self.res_index = 0

    def prepare(self):
        assert self.req is not None, 'Request must be initialized with init_req() before be added before prepare() can be called'

        if self.timeout is None:
            self.timeout = self.timeout_baseline

        self._init_res_buffer()
        try:
            self._create_socket()
            self._configure_socket()
            self._bind_socket()
            self._set_start_time()
            self._connect_socket()
        except socket.error as e:
            self.err = e
            self.cleanup()

    def _get_af(self):
        if self.dst.version == 6:
            return socket.AF_INET6
        else:
            return socket.AF_INET

    def _create_socket(self):
        af = self._get_af()
        self.sock = socket.socket(af, self.transport_type)
        self.sockfd = self.sock.fileno()

    def _configure_socket(self):
        self.sock.setblocking(0)

    def _bind_socket(self):
        if self.src is not None:
            src = self.src
        else:
            if self.sock.family == socket.AF_INET6:
                src = ANY_IPV6
            else:
                src = ANY_IPV4

        if self.sport is not None:
            self.sock.bind((src, self.sport))
        else:
            i = 0
            while True:
                sport = random.randint(1024, 65535)
                try:
                    self.sock.bind((src, sport))
                    break
                except socket.error as e:
                    i += 1
                    if i > MAX_PORT_BIND_ATTEMPTS or e.errno != socket.errno.EADDRINUSE:
                        raise

    def _set_socket_info(self):
        src, sport = self.sock.getsockname()[:2]
        self.src = IPAddr(src)
        self.sport = sport

    def _get_connect_arg(self):
        return (self.dst, self.dport)

    def _connect_socket(self):
        try:
            self.sock.connect(self._get_connect_arg())
        except socket.error as e:
            if e.errno != socket.errno.EINPROGRESS:
                raise

    def _set_start_time(self):
        self.expiration = self.timeout + time.time()
        self.start_time = time.time()

    def _set_end_time(self):
        self.end_time = time.time()
        if self.start_time is None:
            self.start_time = self.end_time

    def cleanup(self):
        # set end (and start, if necessary) times, as appropriate
        self._set_end_time()

        self._set_socket_info()

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
        except socket.error as e:
            self.err = e
            self.cleanup()
            return True

    def do_read(self):
        raise NotImplemented

    def do_timeout(self):
        raise NotImplemented

    def serialize_requests(self):
        d = {
            'version': DNS_TRANSPORT_VERSION,
            'requests': [q.serialize_request() for q in self.qtms]
        }
        return d

class DNSQueryTransportHandlerDNS(DNSQueryTransportHandler):
    singleton = True

    require_queryid_match = True

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
        self.req_index = 0

        # python3/python2 dual compatibility
        if isinstance(self.req, str):
            map_func = lambda x: ord(x)
        else:
            map_func = lambda x: x

        self._queryid_wire = self.req[:2]
        index = 12
        while map_func(self.req[index]) != 0:
            index += map_func(self.req[index]) + 1
        index += 4
        self._question_wire = self.req[12:index]

        if qtm.tcp:
            self.transport_type = socket.SOCK_STREAM
            self.req = struct.pack(b'!H', self.req_len) + self.req
            self.req_len += struct.calcsize(b'H')
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
                    self.res = b''
            except socket.error as e:
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
                    if buf == b'':
                        raise EOFError()

                    self.res_buf += buf
                    if len(self.res_buf) == 2:
                        self.res_len = struct.unpack(b'!H', self.res_buf)[0]

                if self.res_len is not None:
                    buf = self.sock.recv(self.res_len - self.res_index)
                    if buf == b'':
                        raise EOFError()

                    self.res += buf
                    self.res_index = len(self.res)

                    if self.res_index >= self.res_len:
                        self.cleanup()
                        return True

            except (socket.error, EOFError) as e:
                if isinstance(e, socket.error) and e.errno == socket.errno.EAGAIN:
                    pass
                else:
                    self.err = e
                    self.cleanup()
                    return True

    def do_timeout(self):
        self.err = dns.exception.Timeout()
        self.cleanup()

class DNSQueryTransportHandlerDNSPrivate(DNSQueryTransportHandlerDNS):
    allow_loopback_query = True
    allow_private_query = True

class DNSQueryTransportHandlerDNSLoose(DNSQueryTransportHandlerDNS):
    require_queryid_match = False

class DNSQueryTransportHandlerMulti(DNSQueryTransportHandler):
    singleton = False

    def finalize(self):
        super(DNSQueryTransportHandlerMulti, self).finalize()

        # if there was an error, then re-raise it here
        if self.err is not None:
            raise self.err

        # if there is no content, raise an exception
        if self.res is None:
            raise RemoteQueryTransportError('No content in response')

        # load the json content
        try:
            content = json.loads(lb2s(self.res))
        except ValueError:
            raise RemoteQueryTransportError('JSON decoding of response failed: %s' % self.res)

        if 'version' not in content:
            raise RemoteQueryTransportError('No version information in response.')
        try:
            major_vers, minor_vers = [int(x) for x in str(content['version']).split('.', 1)]
        except ValueError:
            raise RemoteQueryTransportError('Version of JSON input in response is invalid: %s' % content['version'])

        # ensure major version is a match and minor version is no greater
        # than the current minor version
        curr_major_vers, curr_minor_vers = [int(x) for x in str(DNS_TRANSPORT_VERSION).split('.', 1)]
        if major_vers != curr_major_vers or minor_vers > curr_minor_vers:
            raise RemoteQueryTransportError('Version %d.%d of JSON input in response is incompatible with this software.' % (major_vers, minor_vers))

        if 'error' in content:
            raise RemoteQueryTransportError('Remote query error: %s' % content['error'])

        if 'responses' not in content:
            raise RemoteQueryTransportError('No DNS response information in response.')

        for i in range(len(self.qtms)):
            try:
                self.qtms[i].deserialize_response(content['responses'][i])
            except IndexError:
                raise RemoteQueryTransportError('DNS response information missing from response')
            except TransportMetaDeserializationError as e:
                raise RemoteQueryTransportError(str(e))

class DNSQueryTransportHandlerHTTP(DNSQueryTransportHandlerMulti):
    timeout_baseline = 5.0

    def __init__(self, url, insecure=False, processed_queue=None, factory=None):
        super(DNSQueryTransportHandlerHTTP, self).__init__(processed_queue=processed_queue, factory=factory)

        self.transport_type = socket.SOCK_STREAM

        parse_result = urlparse.urlparse(url)
        scheme = parse_result.scheme
        if not scheme:
            scheme = 'http'
        elif scheme not in ('http', 'https'):
            raise RemoteQueryTransportError('Invalid scheme: %s' % scheme)

        self.use_ssl = scheme == 'https'
        self.host = parse_result.hostname
        self.dport = parse_result.port
        if self.dport is None:
           if scheme == 'http':
               self.dport = 80
           else: # scheme == 'https'
               self.dport = 443
        self.path = parse_result.path
        self.username = parse_result.username
        self.password = parse_result.password
        self.insecure = insecure

        af = 0
        try:
            addrinfo = socket.getaddrinfo(self.host, self.dport, af, self.transport_type)
        except socket.gaierror:
            raise RemoteQueryTransportError('Unable to resolve name of HTTP host: %s' % self.host)
        self.dst = IPAddr(addrinfo[0][4][0])

        self.chunked_encoding = None

    def _set_timeout(self, qtm):
        if self.timeout is None:
            # allow 5 seconds for HTTP overhead, as a baseline
            self.timeout = self.timeout_baseline
        # account for worst case, in which case queries are performed serially
        # on the remote end
        self.timeout += qtm.timeout

    def _create_socket(self):
        super(DNSQueryTransportHandlerHTTP, self)._create_socket()

        if self.use_ssl:
            #XXX this is python >= 2.7.9 only
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)

    def _post_data(self):
        return 'content=' + urlquote.quote(json.dumps(self.serialize_requests()))

    def _authentication_header(self):
        if not self.username:
            return ''

        # set username/password
        username = self.username
        if self.password:
            username += ':' + self.password
        return 'Authorization: Basic %s\r\n' % (lb2s(base64.b64encode(codecs.encode(username, 'utf-8'))))

    def init_req(self):
        data = self._post_data()
        self.req = codecs.encode('POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: DNSViz/0.6.5\r\nAccept: application/json\r\n%sContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s' % (self.path, self.host, self._authentication_header(), len(data), data), 'latin1')
        self.req_len = len(self.req)
        self.req_index = 0

    def prepare(self):
        super(DNSQueryTransportHandlerHTTP, self).prepare()
        if self.err is not None:
            self.err = RemoteQueryTransportError('Error making HTTP connection: %s' % self.err)

    def do_write(self):
        val = super(DNSQueryTransportHandlerHTTP, self).do_write()
        if self.err is not None:
            self.err = RemoteQueryTransportError('Error making HTTP request: %s' % self.err)
        return val

    def do_read(self):
        try:
            buf = self.sock.recv(65536)
            if buf == b'':
                raise EOFError
            self.res_buf += buf

            # still reading status and headers
            if self.chunked_encoding is None and self.res_len is None:
                headers_end_match = HTTP_HEADER_END_RE.search(lb2s(self.res_buf))
                if headers_end_match is not None:
                    headers = self.res_buf[:headers_end_match.start()]
                    self.res_buf = self.res_buf[headers_end_match.end():]

                    # check HTTP status
                    status_match = HTTP_STATUS_RE.search(lb2s(headers))
                    if status_match is None:
                        self.err = RemoteQueryTransportError('Malformed HTTP status line')
                        self.cleanup()
                        return True
                    status = int(status_match.group('status'))
                    if status != 200:
                        self.err = RemoteQueryTransportError('%d HTTP status' % status)
                        self.cleanup()
                        return True

                    # get content length or determine whether "chunked"
                    # transfer encoding is used
                    content_length_match = CONTENT_LENGTH_RE.search(lb2s(headers))
                    if content_length_match is not None:
                        self.chunked_encoding = False
                        self.res_len = int(content_length_match.group('length'))
                    else:
                        self.chunked_encoding = CHUNKED_ENCODING_RE.search(lb2s(headers)) is not None

            # handle chunked encoding first
            if self.chunked_encoding:
                # look through as many chunks as are readily available
                # (without having to read from socket again)
                while self.res_buf:
                    if self.res_len is None:
                        # looking for chunk length

                        # strip off beginning CRLF, if any
                        # (this is for chunks after the first one)
                        crlf_start_match = CRLF_START_RE.search(lb2s(self.res_buf))
                        if crlf_start_match is not None:
                            self.res_buf = self.res_buf[crlf_start_match.end():]

                        # find the chunk length
                        chunk_len_match = CHUNK_SIZE_RE.search(lb2s(self.res_buf))
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
                            self.res_buf = b''

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
                    self.res_buf = b''

        except (socket.error, EOFError) as e:
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
                    self.err = RemoteQueryTransportError('Error communicating with HTTP server: %s' % e)
                self.cleanup()
                return True

    def do_timeout(self):
        self.err = RemoteQueryTransportError('HTTP request timed out')
        self.cleanup()

class DNSQueryTransportHandlerHTTPPrivate(DNSQueryTransportHandlerHTTP):
    allow_loopback_query = True
    allow_private_query = True

class DNSQueryTransportHandlerWebSocket(DNSQueryTransportHandlerMulti):
    timeout_baseline = 5.0

    def __init__(self, path, processed_queue=None, factory=None):
        super(DNSQueryTransportHandlerWebSocket, self).__init__(processed_queue=processed_queue, factory=factory)

        self.dst = path
        self.transport_type = socket.SOCK_STREAM

        self.mask_mapping = []
        self.has_more = None

    def _set_timeout(self, qtm):
        if self.timeout is None:
            # allow 5 seconds for browser overhead, as a baseline
            self.timeout = self.timeout_baseline
        # account for worst case, in which case queries are performed serially
        # on the remote end
        self.timeout += qtm.timeout

    def _get_af(self):
        return socket.AF_UNIX

    def _bind_socket(self):
        pass

    def _set_socket_info(self):
        pass

    def _get_connect_arg(self):
        return self.dst

    def prepare(self):
        super(DNSQueryTransportHandlerWebSocket, self).prepare()
        if self.err is not None:
            self.err = RemoteQueryTransportError('Error connecting to UNIX domain socket: %s' % self.err)

    def do_write(self):
        val = super(DNSQueryTransportHandlerWebSocket, self).do_write()
        if self.err is not None:
            self.err = RemoteQueryTransportError('Error writing to UNIX domain socket: %s' % self.err)
        return val

    def finalize(self):
        new_res = b''
        for i, mask_index in enumerate(self.mask_mapping):
            mask_octets = struct.unpack(b'!BBBB', self.res[mask_index:mask_index + 4])
            if i >= len(self.mask_mapping) - 1:
                buf = self.res[mask_index + 4:]
            else:
                buf = self.res[mask_index + 4:self.mask_mapping[i + 1]]
            for j in range(len(buf)):
                b = struct.unpack(b'!B', buf[j])[0]
                new_res += struct.pack(b'!B', b ^ mask_octets[j % 4]);
        self.res = new_res

        super(DNSQueryTransportHandlerWebSocket, self).finalize()

    def init_req(self):
        data = json.dumps(self.serialize_requests())

        header = b'\x81'
        l = len(data)
        if l <= 125:
            header += struct.pack(b'!B', l)
        elif l <= 0xffff:
            header += struct.pack(b'!BH', 126, l)
        else: # 0xffff < len <= 2^63
            header += struct.pack(b'!BL', 127, l)
        self.req = header + data
        self.req_len = len(self.req)
        self.req_index = 0

    def init_empty_req(self):
        self.req = b'\x81\x00'
        self.req_len = len(self.req)
        self.req_index = 0

    def do_read(self):
        try:
            buf = self.sock.recv(65536)
            if buf == b'':
                raise EOFError
            self.res_buf += buf

            # look through as many frames as are readily available
            # (without having to read from socket again)
            while self.res_buf:
                if self.res_len is None:
                    # looking for frame length
                    if len(self.res_buf) >= 2:
                        byte0, byte1 = struct.unpack(b'!BB', self.res_buf[0:2])
                        byte1b = byte1 & 0x7f

                        # mask must be set
                        if not byte1 & 0x80:
                            if self.err is not None:
                                self.err = RemoteQueryTransportError('Mask bit not set in message from server')
                                self.cleanup()
                                return True

                        # check for FIN flag
                        self.has_more = not bool(byte0 & 0x80)

                        # determine the header length
                        if byte1b <= 125:
                            header_len = 2
                        elif byte1b == 126:
                            header_len = 4
                        else: # byte1b == 127:
                            header_len = 10

                        if len(self.res_buf) >= header_len:
                            if byte1b <= 125:
                                self.res_len = byte1b
                            elif byte1b == 126:
                                self.res_len = struct.unpack(b'!H', self.res_buf[2:4])[0]
                            elif byte1b == 127:
                                self.res_len = struct.unpack(b'!Q', self.res_buf[2:10])[0]

                            # handle mask
                            self.mask_mapping.append(len(self.res))
                            self.res_len += 4

                            self.res_buf = self.res_buf[header_len:]

                        else:
                            # if we don't currently know the length of the next
                            # frame, and we don't have enough data to find the
                            # length, then break out of the loop because we
                            # don't have any more data to go off of.
                            break

                if self.res_len is not None:
                    # we know a length of the current chunk

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
                        self.res_buf = b''

                    if self.res_index >= self.res_len and not self.has_more:
                        self.cleanup()
                        return True

        except (socket.error, EOFError) as e:
            if isinstance(e, socket.error) and e.errno == socket.errno.EAGAIN:
                pass
            else:
                self.err = e
                self.cleanup()
                return True

    def do_timeout(self):
        self.err = RemoteQueryTransportError('Read of UNIX domain socket timed out')
        self.cleanup()

class DNSQueryTransportHandlerWebSocketPrivate(DNSQueryTransportHandlerWebSocket):
    allow_loopback_query = True
    allow_private_query = True

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

class DNSQueryTransportHandlerDNSPrivateFactory(DNSQueryTransportHandlerFactory):
    cls = DNSQueryTransportHandlerDNSPrivate

class DNSQueryTransportHandlerHTTPFactory(DNSQueryTransportHandlerFactory):
    cls = DNSQueryTransportHandlerHTTP

class DNSQueryTransportHandlerHTTPPrivateFactory(DNSQueryTransportHandlerFactory):
    cls = DNSQueryTransportHandlerHTTPPrivate

class _DNSQueryTransportHandlerWebSocketFactory(DNSQueryTransportHandlerFactory):
    cls = DNSQueryTransportHandlerWebSocket

class DNSQueryTransportHandlerWebSocketFactory:
    def __init__(self, *args, **kwargs):
        self._f = _DNSQueryTransportHandlerWebSocketFactory(*args, **kwargs)

    def __del__(self):
        try:
            qth = self._f.build()
            qth.init_empty_req()
            qth.prepare()
            qth.do_write()
        except:
            pass

    @property
    def cls(self):
        return self._f.__class__.cls

    def build(self, **kwargs):
        return self._f.build(**kwargs)

class _DNSQueryTransportHandlerWebSocketPrivateFactory(DNSQueryTransportHandlerFactory):
    cls = DNSQueryTransportHandlerWebSocketPrivate

class DNSQueryTransportHandlerWebSocketPrivateFactory:
    def __init__(self, *args, **kwargs):
        self._f = _DNSQueryTransportHandlerWebSocketPrivateFactory(*args, **kwargs)

    def __del__(self):
        try:
            qth = self._f.build()
            qth.init_empty_req()
            qth.prepare()
            qth.do_write()
        except:
            pass

    @property
    def cls(self):
        return self._f.__class__.cls

    def build(self, **kwargs):
        return self._f.build(**kwargs)

class DNSQueryTransportHandlerWrapper(object):
    def __init__(self, qh):
        self.qh = qh

    def __eq__(self, other):
        return False

    def __lt__(self, other):
        return False

class _DNSQueryTransportManager:
    '''A class that handles'''

    #TODO might need FD_SETSIZE to support lots of fds
    def __init__(self):
        self._notify_read_fd, self._notify_write_fd = os.pipe()
        fcntl.fcntl(self._notify_read_fd, fcntl.F_SETFL, os.O_NONBLOCK)
        self._query_queue = queue.Queue()
        self._event_map = {}

        self._close = threading.Event()
        t = threading.Thread(target=self._loop)
        t.start()

    def close(self):
        self._close.set()
        os.write(self._notify_write_fd, struct.pack(b'!B', 0))

    def query(self, qh):
        self._event_map[qh] = threading.Event()
        self._query(qh)
        self._event_map[qh].wait()
        del self._event_map[qh]

    def query_nowait(self, qh):
        self._query(qh)

    def _query(self, qh):
        self._query_queue.put(qh)
        os.write(self._notify_write_fd, struct.pack(b'!B', 0))

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
                qh = query_meta[fd]

                if qh.do_write():
                    if qh.err is not None:
                        finished_fds.append(fd)
                    else:
                        wlist_in.remove(fd)
                        rlist_in.append(fd)

            # handle the responses
            for fd in rlist_out:
                if fd == self._notify_read_fd:
                    continue

                qh = query_meta[fd]

                if qh.do_read():
                    finished_fds.append(fd)

            # handle the expired queries
            future_index = bisect.bisect_right(expirations, ((time.time(), DNSQueryTransportHandlerWrapper(None))))
            for i in range(future_index):
                qh = expirations[i][1].qh

                # this query actually finished earlier in this iteration of the
                # loop, so don't indicate that it timed out
                if qh.end_time is not None:
                    continue

                qh.do_timeout()
                finished_fds.append(qh.sockfd)
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
                        qh = self._query_queue.get_nowait()
                        qh.prepare()
                        if qh.err is not None:
                            if qh in self._event_map:
                                self._event_map[qh].set()
                        else:
                            # if we successfully bound and connected the
                            # socket, then put this socket in the write fd list
                            fd = qh.sock.fileno()
                            query_meta[fd] = qh
                            bisect.insort(expirations, (qh.expiration, DNSQueryTransportHandlerWrapper(qh)))
                            wlist_in.append(fd)
                    except queue.Empty:
                        break

class DNSQueryTransportHandlerHTTPPrivate(DNSQueryTransportHandlerHTTP):
    allow_loopback_query = True
    allow_private_query = True

class DNSQueryTransportManager:
    def __init__(self):
        self._th = _DNSQueryTransportManager()

    def __del__(self):
        self.close()

    def query(self, qh):
        return self._th.query(qh)

    def query_nowait(self, qh):
        return self._th.query_nowait(qh)

    def close(self):
        return self._th.close()
