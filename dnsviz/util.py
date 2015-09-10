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
# with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import re

import dns.exception, dns.message, dns.rdatatype

from config import DNSVIZ_SHARE_PATH
import format as fmt

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

def get_default_trusted_keys_with_sanity_check():
    import resolver as Resolver

    class Ans:
        def __init__(self):
            self.rrset = set()

    trusted_keys = get_default_trusted_keys()
    checked_trusted_keys = []
    dnskey_sets = {}
    r = Resolver.get_standard_resolver()
    for name, dnskey in trusted_keys:
        if name not in dnskey_sets:
            try:
                dnskey_sets[name] = r.query_for_answer(name, dns.rdatatype.DNSKEY)
            except dns.exception.DNSException:
                dnskey_sets[name] = Ans()
        if dnskey in dnskey_sets[name].rrset:
            checked_trusted_keys.append((name, dnskey))
    return checked_trusted_keys
