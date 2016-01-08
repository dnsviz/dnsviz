# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
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

import binascii
import re
import socket

class IPAddr(str):
    def __new__(cls, string):
        if ':' in string:
            af = socket.AF_INET6
            vers = 6
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

    def __lt__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) < 0

    def __le__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) <= 0

    def __eq__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) == 0

    def __ne__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) != 0

    def __gt__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) > 0

    def __ge__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) >= 0

    def __cmp__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        if len(self._ipaddr_bytes) < len(other._ipaddr_bytes):
            return -1
        elif len(self._ipaddr_bytes) > len(other._ipaddr_bytes):
            return 1
        else:
            return cmp(self._ipaddr_bytes, other._ipaddr_bytes)

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
LOOPBACK_IPV6 = IPAddr('::1')
RFC_1918_RE = re.compile(r'^(0?10|172\.0?(1[6-9]|2[0-9]|3[0-1])|192\.168)\.')
LINK_LOCAL_RE = re.compile(r'^fe[89ab][0-9a-f]:', re.IGNORECASE)
UNIQ_LOCAL_RE = re.compile(r'^fd[0-9a-f]{2}:', re.IGNORECASE)

ANY_IPV6 = IPAddr('::')
ANY_IPV4 = IPAddr('0.0.0.0')
