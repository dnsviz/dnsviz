#!/usr/bin/env python
#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2016-2021 Casey Deccio
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

import codecs
import io
import json
import threading
import sys

# python3/python2 dual compatibility
try:
    import queue
except ImportError:
    import Queue as queue

from dnsviz import transport

class RemoteQueryError(Exception):
    pass

def main(argv):
    sock = transport.ReaderWriter(io.open(sys.stdin.fileno(), 'rb'), io.open(sys.stdout.fileno(), 'wb'))
    sock.lock = threading.Lock()
    qth_reader = transport.DNSQueryTransportHandlerWebSocketClientReader(sock)
    qth_writer = transport.DNSQueryTransportHandlerWebSocketClientWriter(sock)

    response_queue = queue.Queue()
    queries_in_waiting = set()
    th_factory = transport.DNSQueryTransportHandlerDNSFactory()
    tm = transport.DNSQueryTransportManager()
    try:
        while True:
            try:
                qth_writer.qtms = []

                tm.handle_msg(qth_reader)
                qth_reader.finalize()

                if len(qth_reader.msg_recv) == 0:
                    break

                # load the json content
                try:
                    content = json.loads(codecs.decode(qth_reader.msg_recv, 'utf-8'))
                except ValueError:
                    raise RemoteQueryError('JSON decoding of request failed: %s' % qth_reader.msg_recv)

                if 'version' not in content:
                    raise RemoteQueryError('No version information in request.')
                try:
                    major_vers, minor_vers = [int(x) for x in str(content['version']).split('.', 1)]
                except ValueError:
                    raise RemoteQueryError('Version of JSON input in request is invalid: %s' % content['version'])

                # ensure major version is a match and minor version is no greater
                # than the current minor version
                curr_major_vers, curr_minor_vers = [int(x) for x in str(transport.DNS_TRANSPORT_VERSION).split('.', 1)]
                if major_vers != curr_major_vers or minor_vers > curr_minor_vers:
                    raise RemoteQueryError('Version %d.%d of JSON input in request is incompatible with this software.' % (major_vers, minor_vers))

                if 'requests' not in content:
                    raise RemoteQueryError('No request information in request.')

                for i, qtm_serialized in enumerate(content['requests']):
                    try:
                        qtm = transport.DNSQueryTransportMeta.deserialize_request(qtm_serialized)
                    except transport.TransportMetaDeserializationError as e:
                        raise RemoteQueryError('Error deserializing request information: %s' % e)

                    qth_writer.add_qtm(qtm)
                    th = th_factory.build(processed_queue=response_queue)
                    th.add_qtm(qtm)
                    th.init_req()
                    tm.handle_msg_nowait(th)
                    queries_in_waiting.add(th)

                while queries_in_waiting:
                    th = response_queue.get()
                    th.finalize()
                    queries_in_waiting.remove(th)

                qth_writer.init_req()

            except RemoteQueryError as e:
                qth_writer.init_err_send(str(e))

            tm.handle_msg(qth_writer)

    except EOFError:
        pass
    finally:
        tm.close()

if __name__ == '__main__':
    main()
