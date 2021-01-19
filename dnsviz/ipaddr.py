#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
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

import binascii
import codecs
import re
import socket

INTERFACE_RE = re.compile(r'%[a-z0-9]+$')

class IPAddr(str):
    def __new__(cls, string):
        # python 2/3 compatibility
        if isinstance(string, bytes):
            string = codecs.decode(string, 'latin1')
        if ':' in string:
            af = socket.AF_INET6
            vers = 6
            string = INTERFACE_RE.sub('', string)
        else:
            af = socket.AF_INET
            vers = 4

        try:
            ipaddr_bytes = socket.inet_pton(af, string)
        except socket.error:
            raise ValueError('Invalid value for IP address: %s' % string)
        obj = super(IPAddr, cls).__new__(cls, socket.inet_ntop(af, ipaddr_bytes))
        obj._ipaddr_bytes = ipaddr_bytes
        obj.version = vers
        return obj

    def _check_class_for_cmp(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to %s!' % other.__class__.__name__)

    def __lt__(self, other):
        self._check_class_for_cmp(other)
        if len(self._ipaddr_bytes) < len(other._ipaddr_bytes):
            return True
        elif len(self._ipaddr_bytes) > len(other._ipaddr_bytes):
            return False
        else:
            return self._ipaddr_bytes < other._ipaddr_bytes

    def __eq__(self, other):
        if other is None:
            return False
        if isinstance(other, IPAddr):
            return self._ipaddr_bytes == other._ipaddr_bytes
        else:
            return super(IPAddr, self) == other

    def __hash__(self):
        return hash(self._ipaddr_bytes)

    def arpa_name(self):
        if self.version == 6:
            nibbles = [n for n in binascii.hexlify(self._ipaddr_bytes)]
            nibbles.reverse()
            name = '.'.join(nibbles)
            name += '.ip6.arpa.'
        else:
            octets = self.split('.')
            octets.reverse()
            name = '.'.join(octets)
            name += '.in-addr.arpa.'
        return name

LOOPBACK_IPV4_RE = re.compile(r'^127')
IPV4_MAPPED_IPV6_RE = re.compile(r'^::(ffff:)?\d+.\d+.\d+.\d+$', re.IGNORECASE)
LOOPBACK_IPV6 = IPAddr('::1')
RFC_1918_RE = re.compile(r'^(0?10|172\.0?(1[6-9]|2[0-9]|3[0-1])|192\.168)\.')
LINK_LOCAL_RE = re.compile(r'^fe[89ab][0-9a-f]:', re.IGNORECASE)
UNIQ_LOCAL_RE = re.compile(r'^fd[0-9a-f]{2}:', re.IGNORECASE)
ZERO_SLASH8_RE = re.compile(r'^0\.')

ANY_IPV6 = IPAddr('::')
ANY_IPV4 = IPAddr('0.0.0.0')
