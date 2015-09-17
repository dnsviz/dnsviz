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

import os
import re
import socket

import dns.message, dns.rdatatype

from config import DNSVIZ_SHARE_PATH
import format as fmt
from ipaddr import IPAddr

TRUSTED_KEYS_ROOT = os.path.join(DNSVIZ_SHARE_PATH, 'trusted-keys', 'root.txt')

CR_RE = re.compile(r'\r\n', re.MULTILINE)
ZONE_COMMENTS_RE = re.compile(r'\s*;.*', re.MULTILINE)
BLANK_LINES_RE = re.compile(r'\n\s*\n')

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
        tk_str = open(TRUSTED_KEYS_ROOT).read()
    except IOError, e:
        return []
    return get_trusted_keys(tk_str)

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
