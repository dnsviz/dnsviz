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
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import re

import dns.message, dns.rdatatype

import format as fmt

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
