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
import re
import struct
import sys

import dns.edns, dns.message, dns.name, dns.rdatatype, dns.rdataclass

from dnsviz.ipaddr import IPAddr
from dnsviz import transport

import time

FALSE_RE = re.compile(r'^(0|f(alse)?)?$', re.IGNORECASE)

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
        print 'Invalid value for %s: %s' % (name, form[name].value)
        sys.exit(0)

def msg_in_parts_from_form(form):
    if 'flags' in form:
        flags = get_field_value(form, 'flags', int, ValueError)
    else:
        flags = 0

    if 'qname' in form:
        qname = get_field_value(form, 'qname', dns.name.from_text, dns.exception.DNSException)
        if 'qclass' in form:
            qclass = get_field_value(form, 'qclass', dns.rdataclass.from_text, dns.exception.DNSException)
        else:
            qclass = dns.rdataclass.IN
        if 'qtype' in form:
            qtype = get_field_value(form, 'qtype', dns.rdatatype.from_text, dns.exception.DNSException)
        else:
            qtype = dns.rdatatype.A
    else:
        qname = dns.name.root
        if 'qclass' in form:
            qclass = get_field_value(form, 'qclass', dns.rdataclass.from_text, dns.exception.DNSException)
        else:
            qclass = dns.rdataclass.IN
        if 'qtype' in form:
            qtype = get_field_value(form, 'qtype', dns.rdatatype.from_text, dns.exception.DNSException)
        else:
            qtype = dns.rdatatype.NS

    if 'edns_version' in form:
        edns_version = get_field_value(form, 'edns_version', positive_int, ValueError)
        if 'edns_flags' in form:
            edns_flags = get_field_value(form, 'edns_flags', positive_int, ValueError)
        else:
            edns_flags = 0
        if 'edns_max_udp_payload' in form:
            edns_max_udp_payload = get_field_value(form, 'edns_max_udp_payload', positive_int, ValueError)
        else:
            edns_max_udp_payload = 4096
        if 'edns_options' in form:
            edns_options = get_field_value(form, 'edns_options', option_from_wire, (TypeError, struct.error, dns.exception.DNSException))
        else:
            edns_options = []

    req = dns.message.Message()
    req.flags = flags
    req.find_rrset(req.question, qname, qclass, qtype, create=True, force_unique=True)
    if 'edns_version' in form:
        req.use_edns(edns_version, edns_flags, edns_max_udp_payload, edns_options)
    return req.to_wire()

def msg_from_form(form):
    # if the message itself was encoded in the form, then simply decode and
    # return it
    if 'msg' in form:
        try:
            return base64.b64decode(form['msg'].value)
        except TypeError:
            print 'Error decoding JSON: %s' % form['msg'].value
            sys.exit(0)

    # otherwise, collect the parts from the form and compile a message
    else:
        return msg_in_parts_from_form(form)

def main():
    print 'Content-type: application/json'
    print
    if os.environ.get('REQUEST_METHOD', '') != 'POST':
        print ''
    else:
        form = cgi.FieldStorage()

    msg = msg_from_form(form)

    if 'dst' in form:
        dst = get_field_value(form, 'dst', IPAddr, ValueError)
    else:
        print 'No server specified'
        sys.exit(0)

    if 'src' in form:
        src = get_field_value(form, 'src', IPAddr, ValueError)
    else:
        src = None

    if 'dport' in form:
        dport = get_field_value(form, 'dport', positive_int, ValueError)
    else:
        dport = 53

    if 'sport' in form:
        sport = get_field_value(form, 'sport', positive_int, ValueError)
    else:
        sport = None

    if 'tcp' in form:
        tcp = not bool(get_field_value(form, 'tcp', FALSE_RE.search, Exception))
    else:
        tcp = False

    if 'timeout' in form:
        timeout = get_field_value(form, 'timeout', positive_float, ValueError)
    else:
        timeout = 3.0

    try:
        tm = transport.DNSQueryTransportManager()
        t = transport.DNSQueryTransportMetaNative(msg, dst, tcp, timeout, dport, src=src, sport=sport)
        tm.query(t)
        f = t.serialize_response()
        print json.dumps(f)
    finally:
        tm.close()

if __name__ == '__main__':
    main()
