#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2012-2014 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government retains
# certain rights in this software.
#
# Copyright 2014-2016 VeriSign, Inc.
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

import datetime
import io
import os
import re
import socket

import dns.message, dns.name, dns.rdataclass, dns.rdatatype, dns.rrset

from .config import DNSVIZ_SHARE_PATH
from . import format as fmt
from .ipaddr import IPAddr

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
B.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:200::b
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

HISTORICAL_ROOT_IPS = (
        (dns.name.from_text('h.root-servers.net.'), IPAddr('2001:500:1::803f:235')), # 2015-12-01
        (dns.name.from_text('l.root-servers.net.'), IPAddr('2001:500:3::42')), # 2016-03-24
        (dns.name.from_text('b.root-servers.net.'), IPAddr('2001:500:84::b')), # 2017-06-01
)

# The following list should include all current and historical trust anchors
# for the root zone.  This makes it possible to perform analysis of current DNS
# responses, but also archived DNS responses.
#
# For each root zone trust anchor, the start value is the day it is first
# published in the root zone.  Even though the key is not yet signing, this
# draws attention to the fact that it will be signing and likely replacing its
# predecessor.  The end value is (at least) the minimum of the TTL and the
# expiration of its last published RRSIG.  This allows us to query caches with
# contents referring to the old key, even after its replacement has taken over.
TRUSTED_KEYS_ROOT = (
        ('. IN DNSKEY 257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=',
            datetime.datetime(2010, 7, 16, 0, 0, 0, 0, fmt.utc),
            datetime.datetime(2018, 10, 15, 16, 0, 0, 0, fmt.utc)), # 2018-10-11 16:00:00 UTC + 4 days (2*TTL)
        ('. IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU=',
            datetime.datetime(2017, 8, 11, 0, 0, 0, 0, fmt.utc), # 2017-07-12 00:00:00 UTC + 30 days (RFC 5011 add hold-down time)
            None),
)

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

def get_default_trusted_keys(date):
    tk_str = ''
    for tk, start, end in TRUSTED_KEYS_ROOT:
        if start is not None and date < start:
            continue
        if end is not None and date > end:
            continue
        tk_str += tk + '\n'
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
        with io.open(ROOT_HINTS, 'r', encoding='utf-8') as fh:
            return get_hints(fh.read())
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
        ip = None
    else:
        ip = IPAddr(s.getsockname()[0])
    s.close()
    return ip
