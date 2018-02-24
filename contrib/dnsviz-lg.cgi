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

from __future__ import unicode_literals

import cgi
import json
import os
import re
import struct
import sys

# python3/python2 dual compatibility
try:
    import queue
except ImportError:
    import Queue as queue

from dnsviz.ipaddr import *
from dnsviz import transport

FALSE_RE = re.compile(r'^(0|f(alse)?)?$', re.IGNORECASE)

try:
    MAX_QUERIES = int(os.environ.get('MAX_QUERIES', 200))
except ValueError:
    MAX_QUERIES = 200
ALLOW_PRIVATE_QUERY = not bool(FALSE_RE.search(os.environ.get('ALLOW_PRIVATE_QUERY', 'f')))
ALLOW_LOOPBACK_QUERY = not bool(FALSE_RE.search(os.environ.get('ALLOW_LOOPBACK_QUERY', 'f')))
BLACKLIST_FILE = os.environ.get('BLACKLIST_FILE', None)
WHITELIST_FILE = os.environ.get('WHITELIST_FILE', None)

blacklist = None
whitelist = None

class RemoteQueryError(Exception):
    pass

class InvalidName(Exception):
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

def get_qname(msg):
    n = ''
    index = 12
    labels = []
    while True:
        # no label
        if index >= len(msg):
            raise InvalidName()

        # python3/python2 dual compatibility
        if isinstance(msg, str):
            l = struct.unpack(b'!B', msg[index])[0]
        else:
            l = msg[index]

        # no compression allowed in question
        if l & 0xc0:
            raise InvalidName()

        # account for label length
        index += 1

        # not enough message for label
        if index + l > len(msg):
            raise InvalidName()

        # zero labels - this is the end
        if l == 0:
            break

        # append label to list
        labels.append(msg[index:index + l])

        index += l

    return '.'.join(labels) + '.'

def import_blacklist():
    global blacklist
    global whitelist

    blacklist = set()
    whitelist = set()

    if BLACKLIST_FILE is None:
        return

    with open(BLACKLIST_FILE, 'r') as fh:
        for line in fh:
            name = line.rstrip().lower()
            if not name.endswith('.'):
                name += '.'
            blacklist.add(name)

    if WHITELIST_FILE is None:
        return

    with open(WHITELIST_FILE, 'r') as fh:
        for line in fh:
            name = line.rstrip().lower()
            if not name.endswith('.'):
                name += '.'
            whitelist.add(name)

def check_qname(msg):
    global blacklist
    global whitelist

    try:
        qname = get_qname(msg)
    except InvalidName:
        return

    if blacklist is None:
        import_blacklist()

    subdomain = qname.lower()
    while True:
        if subdomain in whitelist:
            return

        if subdomain in blacklist:
            raise RemoteQueryError('Querying %s not allowed' % qname)

        try:
            nextdot = subdomain.index('.')
        except ValueError:
            break
        else:
            subdomain = subdomain[nextdot+1:]

def main():
    try:
        if not os.environ.get('REQUEST_METHOD', None):
            os.environ['REQUEST_METHOD'] = 'POST'
        if os.environ['REQUEST_METHOD'] != 'POST':
            raise RemoteQueryError('Request method %s not supported' % os.environ['REQUEST_METHOD'])
        form = cgi.FieldStorage()

        response_queue = queue.Queue()
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
                major_vers, minor_vers = [int(x) for x in str(content['version']).split('.', 1)]
            except ValueError:
                raise RemoteQueryError('Version of JSON input in HTTP request is invalid: %s' % content['version'])

            # ensure major version is a match and minor version is no greater
            # than the current minor version
            curr_major_vers, curr_minor_vers = [int(x) for x in str(transport.DNS_TRANSPORT_VERSION).split('.', 1)]
            if major_vers != curr_major_vers or minor_vers > curr_minor_vers:
                raise RemoteQueryError('Version %d.%d of JSON input in HTTP request is incompatible with this software.' % (major_vers, minor_vers))

            if 'requests' not in content:
                raise RemoteQueryError('No request information in HTTP request.')

            for i, qtm_serialized in enumerate(content['requests']):
                if i >= MAX_QUERIES:
                    raise RemoteQueryError('Maximum requests exceeded.')

                try:
                    qtm = transport.DNSQueryTransportMeta.deserialize_request(qtm_serialized)
                except transport.TransportMetaDeserializationError as e:
                    raise RemoteQueryError('Error deserializing request information: %s' % e)

                check_dst(qtm.dst)
                check_qname(qtm.req)

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
    except RemoteQueryError as e:
        ret = {
            'version': transport.DNS_TRANSPORT_VERSION,
            'error': str(e),
        }
    sys.stdout.write('Content-type: application/json\r\n\r\n')
    sys.stdout.write(json.dumps(ret))

if __name__ == '__main__':
    main()
