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

import calendar
import codecs
import datetime
import re
import time

import dns.name, dns.rdatatype

DNSKEY_FLAGS = {'ZONE': 0x0100, 'SEP': 0x0001, 'revoke': 0x0080}
DNSKEY_PROTOCOLS = { 3: 'DNSSEC' }
DNSKEY_ALGORITHMS = { 1: 'RSA/MD5', 2: 'Diffie-Hellman', 3: 'DSA/SHA1', 5: 'RSA/SHA-1', 6: 'DSA-NSEC3-SHA1', 7: 'RSASHA1-NSEC3-SHA1', \
        8: 'RSA/SHA-256', 10: 'RSA/SHA-512', 12: 'GOST R 34.10-2001', 13: 'ECDSA Curve P-256 with SHA-256', 14: 'ECDSA Curve P-384 with SHA-384',
        15: 'Ed25519', 16: 'Ed448' }
DS_DIGEST_TYPES = { 1: 'SHA-1', 2: 'SHA-256', 3: 'GOST 34.11-94', 4: 'SHA-384' }

NSEC3_FLAGS = {'OPTOUT': 0x01}

DNS_FLAG_DESCRIPTIONS = {
        32768: 'Query Response', 1024: 'Authoritative Answer', 512: 'Truncated Response',
        256: 'Recursion Desired', 128: 'Recursion Available', 32: 'Authentic Data', 16: 'Checking Disabled'
}

EDNS_FLAG_DESCRIPTIONS = { 32768: 'DNSSEC answer OK' }

EDNS_OPT_DESCRIPTIONS = { 3: 'NSID', 8: 'edns-client-subnet', 10: 'COOKIE' }

FMT_MS = '%Y-%m-%d %H:%M:%S.%f %Z'
FMT_NO_MS = '%Y-%m-%d %H:%M:%S %Z'

ZERO = datetime.timedelta(0)
class UTC(datetime.tzinfo):
    '''UTC'''

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        # python3/python2 dual compatibility
        if type(b'') is str:
            return b'UTC'
        else:
            return 'UTC'

    def dst(self, dt):
        return ZERO

utc = UTC()

#################
# Timestamp conversions
def timestamp_to_datetime(timestamp, tz=utc):
    return datetime.datetime.fromtimestamp(timestamp, tz)

def datetime_to_timestamp(dt):
    return calendar.timegm(dt.timetuple()) + dt.microsecond/1.0e6

def str_to_datetime(s, tz=utc):
    return timestamp_to_datetime(str_to_timestamp(s), tz)

def str_to_timestamp(s):
    try:
        return calendar.timegm(time.strptime(s, FMT_NO_MS))
    except ValueError:
        return calendar.timegm(time.strptime(s, FMT_MS))

def datetime_to_str(dt):
    if dt.microsecond:
        return dt.strftime(FMT_MS)
    else:
        return dt.strftime(FMT_NO_MS)

def timestamp_to_str(timestamp):
    return datetime_to_str(timestamp_to_datetime(timestamp))

#################
# Human representation of time
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

#################
# Human representation of DNS names
def format_nsec3_name(name):
    return lb2s(dns.name.from_text(name.labels[0].upper(), name.parent().canonicalize()).to_text())

def format_nsec3_rrset_text(nsec3_rrset_text):
    return re.sub(r'^(\d+\s+\d+\s+\d+\s+\S+\s+)([0-9a-zA-Z]+)', lambda x: '%s%s' % (x.group(1), x.group(2).upper()), nsec3_rrset_text).rstrip('.')

def humanize_name(name, idn=False, canonicalize=True):
    if canonicalize:
        name = name.canonicalize()
    if idn:
        try:
            name = name.to_unicode()
        except UnicodeError:
            name = lb2s(name.to_text())
    else:
        name = lb2s(name.to_text())
    if name == '.':
        return name
    return name.rstrip('.')

def latin1_binary_to_string(s):
    # python3/python2 dual compatibility
    #XXX In places where this method wraps calls to dns.name.Name.to_text(),
    # this is no longer needed with dnspython 1.15.0
    if isinstance(s, bytes):
        return codecs.decode(s, 'latin1')
    return s
lb2s = latin1_binary_to_string
