#!/usr/bin/env python
#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2015 VeriSign, Inc.
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
import cgi
import json
import os
import Queue
import re
import struct
import sys

import dns.edns, dns.message, dns.name, dns.rdatatype, dns.rdataclass

from dnsviz.ipaddr import IPAddr
from dnsviz import transport

import time

MAX_QUERIES = 1000
FALSE_RE = re.compile(r'^(0|f(alse)?)?$', re.IGNORECASE)

LOOPBACK_IPV4_RE = re.compile(r'^127')
LOOPBACK_IPV6 = IPAddr('::1')
RFC_1918_RE = re.compile(r'^(0?10|172\.0?(1[6-9]|2[0-9]|3[0-1])|192\.168)\.')
LINK_LOCAL_RE = re.compile(r'^fe[89ab][0-9a-f]:', re.IGNORECASE)
UNIQ_LOCAL_RE = re.compile(r'^fd[0-9a-f]{2}:', re.IGNORECASE)

def options_from_wire(value):
    value = base64.b64decode(value)
    options = []
    index = 0
    while index < len(value):
        (otype, olen) = struct.unpack('!HH', value[index:index + 4])
        index += 4
        opt = dns.edns.option_from_wire(otype, value, index, olen)
        options.append(opt)
        index += olen
    return options

def positive_int(value):
    value = int(value)
    if value < 0:
        raise ValueError
    return value

def positive_float(value):
    value = float(value)
    if value < 0.0:
        raise ValueError
    return value

def get_field_value(form, name, validate_func, error_cls):
    try:
        return validate_func(form[name].value)
    except error_cls:
        sys.stdout.write('Invalid value for %s: %s\n' % (name, form[name].value))
        sys.exit(0)

def msg_in_parts_from_form(form, index):
    flags_key = 'flags%d' % index
    qname_key = 'qname%d' % index
    qclass_key = 'qclass%d' % index
    qtype_key = 'qtype%d' % index
    edns_version_key = 'edns_version%d' % index
    edns_flags_key = 'edns_flags%d' % index
    edns_max_udp_payload_key = 'edns_max_udp_payload%d' % index
    edns_options_key = 'edns_options%d' % index

    if flags_key in form:
        flags = get_field_value(form, flags_key, int, ValueError)
    else:
        flags = 0

    if qname_key in form:
        qname = get_field_value(form, qname_key, dns.name.from_text, dns.exception.DNSException)
        if qclass_key in form:
            qclass = get_field_value(form, qclass_key, dns.rdataclass.from_text, dns.exception.DNSException)
        else:
            qclass = dns.rdataclass.IN
        if qtype_key in form:
            qtype = get_field_value(form, qtype_key, dns.rdatatype.from_text, dns.exception.DNSException)
        else:
            qtype = dns.rdatatype.A
    else:
        qname = dns.name.root
        if qclass_key in form:
            qclass = get_field_value(form, qclass_key, dns.rdataclass.from_text, dns.exception.DNSException)
        else:
            qclass = dns.rdataclass.IN
        if qtype_key in form:
            qtype = get_field_value(form, qtype_key, dns.rdatatype.from_text, dns.exception.DNSException)
        else:
            qtype = dns.rdatatype.NS

    if edns_version_key in form:
        edns_version = get_field_value(form, edns_version_key, positive_int, ValueError)
        if edns_flags_key in form:
            edns_flags = get_field_value(form, edns_flags_key, positive_int, ValueError)
        else:
            edns_flags = 0
        if edns_max_udp_payload_key in form:
            edns_max_udp_payload = get_field_value(form, edns_max_udp_payload_key, positive_int, ValueError)
        else:
            edns_max_udp_payload = 4096
        if edns_options_key in form:
            edns_options = get_field_value(form, edns_options_key, options_from_wire, (TypeError, struct.error, dns.exception.DNSException))
        else:
            edns_options = []

    req = dns.message.Message()
    req.flags = flags
    req.find_rrset(req.question, qname, qclass, qtype, create=True, force_unique=True)
    if edns_version_key in form:
        req.use_edns(edns_version, edns_flags, edns_max_udp_payload, edns_options)
    return req.to_wire()

def msg_from_form(form, index):
    msg_key = 'msg%d' % index

    # if the message itself was encoded in the form, then simply decode and
    # return it
    if msg_key in form:
        try:
            return base64.b64decode(form[msg_key].value)
        except TypeError:
            sys.stdout.write('Error decoding JSON: %s' % form[msg_key].value)
            sys.exit(0)

    # otherwise, collect the parts from the form and compile a message
    else:
        return msg_in_parts_from_form(form, index)

def get_qtm(form, index):
    dst_key = 'dst%d' % index
    src_key = 'src%d' % index
    dport_key = 'dport%d' % index
    sport_key = 'sport%d' % index
    tcp_key = 'tcp%d' % index
    timeout_key = 'timeout%d' % index

    # a destination is the minimum value we need to make a query.  If it
    # doesn't exist, then we simply return None
    if dst_key in form:
        dst = get_field_value(form, dst_key, IPAddr, ValueError)
    else:
        return None

    # check for local addresses
    allow_private_query = not bool(FALSE_RE.search(os.environ.get('ALLOW_PRIVATE_QUERY', 'f')))
    allow_loopback_query = not bool(FALSE_RE.search(os.environ.get('ALLOW_LOOPBACK_QUERY', 'f')))
    if not allow_private_query and (RFC_1918_RE.search(dst) is not None or \
            LINK_LOCAL_RE.search(dst) is not None or \
            UNIQ_LOCAL_RE.search(dst) is not None):
        sys.stdout.write('Querying %s not allowed\n' % dst)
        sys.exit(0)
    if not allow_loopback_query and (LOOPBACK_IPV4_RE.search(dst) is not None or \
            dst == LOOPBACK_IPV6):
        sys.stdout.write('Querying %s not allowed\n' % dst)
        sys.exit(0)

    if src_key in form:
        src = get_field_value(form, src_key, IPAddr, ValueError)
    else:
        src = None

    if dport_key in form:
        dport = get_field_value(form, dport_key, positive_int, ValueError)
    else:
        dport = 53

    if sport_key in form:
        sport = get_field_value(form, sport_key, positive_int, ValueError)
    else:
        sport = None

    if tcp_key in form:
        tcp = not bool(get_field_value(form, tcp_key, FALSE_RE.search, Exception))
    else:
        tcp = False

    if timeout_key in form:
        timeout = get_field_value(form, timeout_key, positive_float, ValueError)
    else:
        timeout = 3.0

    msg = msg_from_form(form, index)
    return transport.DNSQueryTransportMeta(msg, dst, tcp, timeout, dport, src=src, sport=sport)

def main():
    sys.stdout.write('Content-type: application/json\n\n')
    if os.environ.get('REQUEST_METHOD', '') != 'POST':
        sys.exit(0)
    else:
        form = cgi.FieldStorage()

    response_queue = Queue.Queue()
    queries_in_waiting = set()
    th_factory = transport.DNSQueryTransportHandlerDNSFactory()
    tm = transport.DNSQueryTransportManager()
    qtms = []
    try:
        for i in range(MAX_QUERIES):
            qtm = get_qtm(form, i)
            if qtm is None:
                break
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

    response_data = [qtm.serialize() for qtm in qtms]
    sys.stdout.write(json.dumps(response_data))

if __name__ == '__main__':
    main()
