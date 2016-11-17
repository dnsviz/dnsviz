#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.  This file (or some portion thereof) is a
# derivative work authored by VeriSign, Inc., and created in 2014, based on
# code originally developed at Sandia National Laboratories.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2012-2014 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government retains
# certain rights in this software.
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

import io
import os
import re
import socket

import dns.message, dns.rdatatype

from .config import DNSVIZ_SHARE_PATH
from . import format as fmt
from .ipaddr import IPAddr

TRUSTED_KEYS_ROOT = os.path.join(DNSVIZ_SHARE_PATH, 'trusted-keys', 'root.txt')
ROOT_HINTS = os.path.join(DNSVIZ_SHARE_PATH, 'hints', 'named.root')

CR_RE = re.compile(r'\r\n', re.MULTILINE)
ZONE_COMMENTS_RE = re.compile(r'\s*;.*', re.MULTILINE)
BLANK_LINES_RE = re.compile(r'\n\s*\n')

ROOT_HINTS_STR_DEFAULT = '''
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
.                        3600000      NS    B.ROOT-SERVERS.NET.
B.ROOT-SERVERS.NET.      3600000      A     192.228.79.201
B.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:84::b
.                        3600000      NS    C.ROOT-SERVERS.NET.
C.ROOT-SERVERS.NET.      3600000      A     192.33.4.12
C.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2::c
.                        3600000      NS    D.ROOT-SERVERS.NET.
D.ROOT-SERVERS.NET.      3600000      A     199.7.91.13
D.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2d::d
.                        3600000      NS    E.ROOT-SERVERS.NET.
E.ROOT-SERVERS.NET.      3600000      A     192.203.230.10
E.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:a8::e
.                        3600000      NS    F.ROOT-SERVERS.NET.
F.ROOT-SERVERS.NET.      3600000      A     192.5.5.241
F.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2f::f
.                        3600000      NS    G.ROOT-SERVERS.NET.
G.ROOT-SERVERS.NET.      3600000      A     192.112.36.4
G.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:12::d0d
.                        3600000      NS    H.ROOT-SERVERS.NET.
H.ROOT-SERVERS.NET.      3600000      A     198.97.190.53
H.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:1::53
.                        3600000      NS    I.ROOT-SERVERS.NET.
I.ROOT-SERVERS.NET.      3600000      A     192.36.148.17
I.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fe::53
.                        3600000      NS    J.ROOT-SERVERS.NET.
J.ROOT-SERVERS.NET.      3600000      A     192.58.128.30
J.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:c27::2:30
.                        3600000      NS    K.ROOT-SERVERS.NET.
K.ROOT-SERVERS.NET.      3600000      A     193.0.14.129
K.ROOT-SERVERS.NET.      3600000      AAAA  2001:7fd::1
.                        3600000      NS    L.ROOT-SERVERS.NET.
L.ROOT-SERVERS.NET.      3600000      A     199.7.83.42
L.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:9f::42
.                        3600000      NS    M.ROOT-SERVERS.NET.
M.ROOT-SERVERS.NET.      3600000      A     202.12.27.33
M.ROOT-SERVERS.NET.      3600000      AAAA  2001:dc3::35
'''

def tuple_to_dict(t):
    d = {}
    for n, v in t:
        if n not in d:
            d[n] = []
        d[n].append(v)
    return d

def get_trusted_keys(s):
    trusted_keys = []

    s = CR_RE.sub('\n', s)
    s = ZONE_COMMENTS_RE.sub('', s)
    s = BLANK_LINES_RE.sub(r'\n', s)
    s = s.strip()
    m = dns.message.from_text(str(';ANSWER\n'+s))
    for rrset in m.answer:
        if rrset.rdtype != dns.rdatatype.DNSKEY:
            continue
        for dnskey in rrset:
            if dnskey.flags & fmt.DNSKEY_FLAGS['revoke']:
                continue
            trusted_keys.append((rrset.name,dnskey))

    return trusted_keys

def get_default_trusted_keys():
    try:
        tk_str = io.open(TRUSTED_KEYS_ROOT, 'r', encoding='utf-8').read()
    except IOError as e:
        return []
    return get_trusted_keys(tk_str)

def get_hints(s):
    hints = {}

    s = CR_RE.sub('\n', s)
    s = ZONE_COMMENTS_RE.sub('', s)
    s = BLANK_LINES_RE.sub(r'\n', s)
    s = s.strip()
    m = dns.message.from_text(str(';ANSWER\n'+s))
    for rrset in m.answer:
        if rrset.rdtype not in (dns.rdatatype.NS, dns.rdatatype.A, dns.rdatatype.AAAA):
            continue
        hints[(rrset.name, rrset.rdtype)] = rrset

    return hints

def get_root_hints():
    try:
        return get_hints(io.open(ROOT_HINTS, 'r', encoding='utf-8').read())
    except IOError:
        return get_hints(ROOT_HINTS_STR_DEFAULT)

def get_client_address(server):
    if server.version == 6:
        af = socket.AF_INET6
    else:
        af = socket.AF_INET
    s = socket.socket(af, socket.SOCK_DGRAM)
    try:
        s.connect((server, 53))
    except socket.error:
        return None
    return IPAddr(s.getsockname()[0])
