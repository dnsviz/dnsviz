#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Author: Casey Deccio (ctdecci@sandia.gov)
#
# Copyright 2012-2013 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government retains certain
# rights in this software.
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

import base64
import calendar
import datetime
import hashlib
import struct
import time
import urllib

import dns.dnssec, dns.exception, dns.inet, dns.ipv4, dns.ipv6, dns.name, dns.rdatatype, dns.rdataclass, dns.renderer

import dnssec

from django.utils.html import escape
from django.utils.timezone import utc

DNSKEY_FLAGS = {'ZONE': 0x0100, 'SEP': 0x0001, 'revoke': 0x0080}
DNSKEY_PROTOCOLS = { 'DNSSEC': 3 }
DNSKEY_ALGORITHMS = { 1: 'RSA/MD5', 2: 'Diffie-Hellman', 3: 'DSA/SHA1', 5: 'RSA/SHA-1', 6: 'DSA-NSEC3-SHA1', 7: 'RSASHA1-NSEC3-SHA1', \
        8: 'RSA/SHA-256', 10: 'RSA/SHA-512', 12: 'GOST R 34.10-2001', 13: 'ECDSA Curve P-256 with SHA-256', 14: 'ECDSA Curve P-384 with SHA-384' }
DS_DIGEST_TYPES = { 1: 'SHA-1', 2: 'SHA-256', 3: 'GOST 34.11-94', 4: 'SHA-384' }

NSEC3_FLAGS = {'OPTOUT': 0x01}

DNS_FLAG_DESCRIPTIONS = {
        32768: 'Query Response', 1024: 'Authoritative Answer', 512: 'Truncated Response',
        256: 'Recursion Desired', 128: 'Recursion Available', 32: 'Authentic Data', 16: 'Checking Disabled'
}

EDNS_FLAG_DESCRIPTIONS = { 32768: 'DNSSEC answer OK' }

def ip_to_wire(ip):
    if is_ipv6(ip):
        return dns.ipv6.inet_aton(ip)
    else:
        return dns.ipv4.inet_aton(ip)

def ip_from_wire(ip):
    if len(ip) == 4:
        return dns.ipv4.inet_ntoa(ip)
    else:
        return fix_ipv6(dns.ipv6.inet_ntoa(ip))

def fix_ipv6(ip):
    if ip.endswith('::') and len(ip.split(':')) > 8:
        ip = ip[:-1] + '0'
    return ip

def is_ipv6(ip):
    return ':' in ip

def timestamp_to_datetime_utc(timestamp):
    return datetime.datetime.fromtimestamp(timestamp, utc)

def datetime_to_timestamp(dt):
    return calendar.timegm(dt.timetuple()) + dt.microsecond/1.0e6

def datetime_url_encode(dt):
    timestamp = int(datetime_to_timestamp(dt))
    return base64.urlsafe_b64encode(struct.pack('!L',int(timestamp)))[:-2]

def datetime_url_decode(timestamp):
    timestamp = struct.unpack('!L', base64.urlsafe_b64decode(str(timestamp+'==')))[0]
    return timestamp_to_datetime_utc(timestamp)

def name_url_encode(name):
    if name == dns.name.root:
        return 'root'
    return urllib.quote(name.canonicalize().to_text().rstrip('.').replace('/', 'S'), safe='')

def name_url_decode(name):
    if name == 'root':
        return dns.name.root
    return dns.name.from_text(name.replace('S', '/'), dns.name.root)

def humanize_time(seconds, days=None):
    if days is None:
        days, remainder = divmod(seconds, 86400)
    else:
        remainder = seconds
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    output = ''
    if days > 0:
        if days != 1:
            plural = 's'
        else:
            plural = ''
        output += '%d day%s' % (days, plural)
    else:
        if hours > 0:
            if hours != 1:
                plural = 's'
            else:
                plural = ''
            output += '%d hour%s' % (hours, plural)
        if minutes > 0:
            if output:
                output += ', '
            if minutes != 1:
                plural = 's'
            else:
                plural = ''
            output += '%d minute%s' % (minutes, plural)
        if not output:
            if seconds != 1:
                plural = 's'
            else:
                plural = ''
            output += '%d second%s' % (seconds, plural)
    return output

def format_diff(date_now, date_relative):
    if date_now > date_relative:
        diff = date_now - date_relative
        suffix = 'in the past'
    else:
        diff = date_relative - date_now
        suffix = 'in the future'
    return '%s %s' % (humanize_time(diff.seconds, diff.days), suffix)

def humanize_name(name, idn=False):
    if idn:
        name = name.canonicalize().to_unicode()
    else:
        name = name.canonicalize().to_text()
    if name == '.':
        return name
    return name.rstrip('.')

def humanize_rrset(rrset, idn=False):
    return '%s/%s' % (humanize_name(rrset.name, idn), dns.rdatatype.to_text(rrset.rdtype))

def humanize_dnskey(name, dnskey, idn=False):
    return '%s/DNSKEY (alg %d, id %d)' % (humanize_name(name, idn), dnskey.algorithm, dnssec.key_tag(dnskey))

def humanize_ds(name, ds, rdtype, idn=False):
    digest_types = [d.digest_type for d in ds]
    digest_types.sort()
    digest_types_str = ','.join(map(str, digest_types))
    if len(digest_types) != 1:
        plural = 's'
    else:
        plural = ''
    return '%s/%s (alg %d, id %d) digest alg%s=%s' % (humanize_name(name, idn), dns.rdatatype.to_text(rdtype), ds[0].algorithm, ds[0].key_tag, plural, digest_types_str)

def humanize_non_existent_dnskey(name, algorithm, id, idn=False):
    return '%s/DNSKEY (alg %d, id %d)' % (humanize_name(name, idn), algorithm, id)

def humanize_rrsig(name, rrsig, idn=False):
    try:
        type_str = dns.rdatatype._by_value[rrsig.covers()]
    except KeyError:
        type_str = '[%d]' % rrsig.covers()

    return 'RRSIG %s/%s by %s/DNSKEY alg %d, key %d' % (humanize_name(name, idn), type_str, humanize_name(rrsig.signer, idn), rrsig.algorithm, rrsig.key_tag)

def humanize_non_existent_rrsig(name, covers, signer, algorithm, key_tag, idn=False):
    try:
        type_str = dns.rdatatype._by_value[covers]
    except KeyError:
        type_str = '[%d]' % covers

    return 'RRSIG %s/%s by %s/DNSKEY alg %d, key %d' % (humanize_name(name, idn), type_str, humanize_name(signer, idn), algorithm, key_tag)

def rr_to_html(name, rdclass, rdtype, ttl, rdata):
    s = '<tr class="rr"><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>' % (name, ttl, dns.rdataclass.to_text(rdclass), dns.rdatatype.to_text(rdtype))
    if rdtype == dns.rdatatype.DNSKEY:
        flags = [desc for desc, val in DNSKEY_FLAGS.items() if val & rdata.flags]
        if rdata.protocol == 3:
            protocol = 'DNSSEC'
        else:
            protocol = rdata.protocol
        s += '<abbr title="Flags: %s">%d</abbr> <abbr title="Protocol: %s">%d</abbr> <abbr title="Algorithm: %s">%d</abbr> <abbr title="Key:">%s</abbr> ; id = %d' % \
                (' '.join(flags), rdata.flags, protocol, rdata.protocol, dns.dnssec.algorithm_to_text(rdata.algorithm), rdata.algorithm, base64.b64encode(rdata.key), dnssec.key_tag(rdata))
    else:
        s += escape(rdata.to_text())
    s += '</td></tr>'
    return s

def target_for_rrset(rrset, section, rdata=None):
    target = '%s-%s-%d' % (section.lower()[:3], humanize_name(rrset.name), rrset.rdtype)
    if rrset.rdtype == dns.rdatatype.RRSIG:
        target += '-%d' % rrset.covers
    if rdata:
        m = hashlib.md5()
        m.update(rdata.to_text())
        target += '-%s' % m.hexdigest()
    return target
