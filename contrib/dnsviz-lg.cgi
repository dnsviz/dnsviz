#!/usr/bin/env python
#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2015-2016 VeriSign, Inc.
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

import cgi
import json
import os
import Queue
import re
import sys

from dnsviz.ipaddr import *
from dnsviz import transport

FALSE_RE = re.compile(r'^(0|f(alse)?)?$', re.IGNORECASE)

try:
    MAX_QUERIES = int(os.environ.get('MAX_QUERIES', 200))
except ValueError:
    MAX_QUERIES = 200
ALLOW_PRIVATE_QUERY = not bool(FALSE_RE.search(os.environ.get('ALLOW_PRIVATE_QUERY', 'f')))
ALLOW_LOOPBACK_QUERY = not bool(FALSE_RE.search(os.environ.get('ALLOW_LOOPBACK_QUERY', 'f')))

class RemoteQueryError(Exception):
    pass

def check_dst(dst):
    # check for local addresses
    if not ALLOW_PRIVATE_QUERY and (RFC_1918_RE.search(dst) is not None or \
            LINK_LOCAL_RE.search(dst) is not None or \
            UNIQ_LOCAL_RE.search(dst) is not None):
        raise RemoteQueryError('Issuing queries to %s not allowed' % dst)
    if not ALLOW_LOOPBACK_QUERY and (LOOPBACK_IPV4_RE.search(dst) is not None or \
            dst == LOOPBACK_IPV6):
        raise RemoteQueryError('Issuing queries to %s not allowed' % dst)

def main():
    sys.stdout.write('Content-type: application/json\r\n\r\n')
    try:
        if os.environ.get('REQUEST_METHOD', '') != 'POST':
            raise RemoteQueryError('Request method %s not supported' % os.environ.get('REQUEST_METHOD'))
        form = cgi.FieldStorage()

        response_queue = Queue.Queue()
        queries_in_waiting = set()
        th_factory = transport.DNSQueryTransportHandlerDNSFactory()
        tm = transport.DNSQueryTransportManager()
        qtms = []
        try:
            if 'content' not in form:
                raise RemoteQueryError('No "content" field found in input')

            # load the json content
            try:
                content = json.loads(form['content'].value)
            except ValueError:
                raise RemoteQueryError('JSON decoding of HTTP request failed: %s' % form['content'])

            if 'version' not in content:
                raise RemoteQueryError('No version information in HTTP request.')
            try:
                major_vers, minor_vers = map(int, str(content['version']).split('.', 1))
            except ValueError:
                raise RemoteQueryError('Version of JSON input in HTTP request is invalid: %s' % content['version'])

            # ensure major version is a match and minor version is no greater
            # than the current minor version
            curr_major_vers, curr_minor_vers = map(int, str(transport.DNS_TRANSPORT_VERSION).split('.', 1))
            if major_vers != curr_major_vers or minor_vers > curr_minor_vers:
                raise RemoteQueryError('Version %d.%d of JSON input in HTTP request is incompatible with this software.' % (major_vers, minor_vers))

            if 'requests' not in content:
                raise RemoteQueryError('No request information in HTTP request.')

            for i, qtm_serialized in enumerate(content['requests']):
                if i >= MAX_QUERIES:
                    raise RemoteQueryError('Maximum requests exceeded.')

                try:
                    qtm = transport.DNSQueryTransportMeta.deserialize_request(qtm_serialized)
                except transport.TransportMetaDeserializationError, e:
                    raise RemoteQueryError('Error deserializing request information: %s' % e)

                check_dst(qtm.dst)

                qtms.append(qtm)
                th = th_factory.build(processed_queue=response_queue)
                th.add_qtm(qtm)
                th.init_req()
                tm.query_nowait(th)
                queries_in_waiting.add(th)

            while queries_in_waiting:
                th = response_queue.get()
                th.finalize()
                queries_in_waiting.remove(th)

        finally:
            tm.close()

        ret = {
            'version': transport.DNS_TRANSPORT_VERSION,
            'responses': [qtm.serialize_response() for qtm in qtms],
        }
    except RemoteQueryError, e:
        ret = {
            'version': transport.DNS_TRANSPORT_VERSION,
            'error': str(e),
        }
    sys.stdout.write(json.dumps(ret))

if __name__ == '__main__':
    main()
