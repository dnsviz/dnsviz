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

import hashlib

import dns.name, dns.rdatatype

import base32

def _digest_name_for_nsec3(qname, origin, salt, alg, iterations):
    val = qname.canonicalize().to_wire()
    if alg == 1:
        for i in range(iterations + 1):
            val = hashlib.sha1(val + salt).digest()
        return dns.name.from_text(base32.b32encode(val), origin)
    else:
        return None

def _rdtype_exists_in_bitmap(rdtype, nsec_rrset):
    for (window, bitmap) in nsec_rrset[0].windows:
        bits = []
        for i in xrange(0, len(bitmap)):
            byte = ord(bitmap[i])
            for j in xrange(0, 8):
                if byte & (0x80 >> j) and \
                        rdtype == window * 256 + i * 8 + j:
                    return True
    return False

def _nsec_covers(qname, origin, nsec_rrset):
    prev_name = nsec_rrset.name
    next_name = nsec_rrset[0].next
    if not isinstance(next_name, dns.name.Name):
        next_name = dns.name.from_text(base32.b32encode(next_name), origin)

    if prev_name >= next_name:
        return not (next_name < qname < prev_name)
    else:
        return prev_name <= qname <= next_name

def _find_closest_encloser(qname, origin, salt, algorithm, iterations, nsec_mapping):
    closest_encloser_name = None
    closest_encloser = None
    next_closer = None

    sname = qname
    flag = False
    while len(sname) >= len(origin) and closest_encloser is None:
        digest_name = _digest_name_for_nsec3(sname, origin, salt, algorithm, iterations)
        if digest_name not in nsec_mapping:
            flag = False
            next_closer = None
        for nsec_rrset in nsec_mapping.values():
            if _nsec_covers(digest_name, origin, nsec_rrset):
                flag = True
                next_closer = nsec_rrset
                break
        if digest_name in nsec_mapping and flag:
            closest_encloser_name = sname
            closest_encloser = nsec_mapping[digest_name]

        if closest_encloser is not None:
            if not closest_encloser.name.is_subdomain(origin):
                closest_encloser = None
                closest_encloser_name = None
                next_closer = None
            if _rdtype_exists_in_bitmap(dns.rdatatype.DNAME, closest_encloser):
                closest_encloser = None
                closest_encloser_name = None
                next_closer = None
            if _rdtype_exists_in_bitmap(dns.rdatatype.NS, closest_encloser) and \
                    not _rdtype_exists_in_bitmap(dns.rdatatype.SOA, closest_encloser):
                closest_encloser = None
                closest_encloser_name = None
                next_closer = None

        sname = dns.name.Name(sname.labels[1:])

    return closest_encloser_name, next_closer

def _validate_nsec_covering(qname, rdtype, origin, nsec_rrsets, skip_wildcard):
    nsec_mapping = {}
    for nsec in nsec_rrsets:
        nsec_mapping[nsec.name] = nsec

    wildcard_name = dns.name.from_text('*',origin)

    return_val = []

    covered = True
    for name in (qname, wildcard_name):
        name_covered = False

        try:
            nsec_rrset = nsec_mapping[name]
            # if the name matches the owner name of an NSEC RR
            if not _rdtype_exists_in_bitmap(rdtype, nsec_rrset):
                return_val.append(nsec_rrset)
                name_covered = True
            skip_wildcard = True

        except KeyError:
            for nsec_rrset in nsec_rrsets:
                if _nsec_covers(name, origin, nsec_rrset):
                    return_val.append(nsec_rrset)
                    name_covered = True
                    break

        if not name_covered:
            covered = False

        if skip_wildcard:
            break

    if covered:
        return return_val
    else:
        return []

def _validate_nsec3_covering(qname, rdtype, origin, nsec_rrsets, closest_encloser):
    nsec_mapping = {}
    for nsec_rrset in nsec_rrsets:
        params = nsec_rrset[0].algorithm, nsec_rrset[0].iterations, nsec_rrset[0].salt

        if params not in nsec_mapping:
            nsec_mapping[params] = {}
        nsec_mapping[params][nsec_rrset.name] = nsec_rrset

    skip_wildcard = closest_encloser is not None
    for params in nsec_mapping:
        digest_name = _digest_name_for_nsec3(qname, origin, params[2], params[0], params[1])
        if digest_name in nsec_mapping[params]:
            # if the name matches the owner name of an NSEC RR
            nsec_rrset = nsec_mapping[params][digest_name]

            if not _rdtype_exists_in_bitmap(rdtype, nsec_rrset) and \
                    not _rdtype_exists_in_bitmap(dns.rdatatype.CNAME, nsec_rrset):

                # if type DS, then we also must make sure that the NS bit is set
                if rdtype == dns.rdatatype.DS:
                    if _rdtype_exists_in_bitmap(dns.rdatatype.NS, nsec_rrset):
                        return True
                else:
                    return True
            continue

        next_closer = None
        if closest_encloser is None:
            closest_encloser, next_closer  = _find_closest_encloser(qname, origin, params[2], params[0], params[1], nsec_mapping[params])
        if closest_encloser is None:
            continue

        if rdtype in (dns.rdatatype.DS, dns.rdatatype.DLV):
            if next_closer is None:
                for nsec_rrset in nsec_mapping[params].values():
                    if _nsec_covers(digest_name, origin, nsec_rrset):
                        next_closer = nsec_rrset
                        break
                assert next_closer is not None
            return closest_encloser is not None and (next_closer[0].flags & 0x01)

        if skip_wildcard:
            return True

        wildcard_name = dns.name.from_text('*',closest_encloser)
        digest_name = _digest_name_for_nsec3(wildcard_name, origin, params[2], params[0], params[1])

        if digest_name in nsec_mapping[params]:
            # if the name matches the owner name of an NSEC RR
            nsec_rrset = nsec_mapping[params][digest_name]

            if not _rdtype_exists_in_bitmap(rdtype, nsec_rrset) and \
                    not _rdtype_exists_in_bitmap(dns.rdatatype.CNAME, nsec_rrset):
                return True
            continue

        else:
            for nsec_rrset in nsec_mapping[params].values():
                if _nsec_covers(digest_name, origin, nsec_rrset):
                    return True

    return False

def validate_nsec_covering(qname, rdtype, origin, nsec_rrsets, closest_encloser=None):
    nsec3 = nsec_rrsets[0].rdtype == dns.rdatatype.NSEC3

    if nsec3:
        return _validate_nsec3_covering(qname, rdtype, origin, nsec_rrsets, closest_encloser)
    else:
        return _validate_nsec_covering(qname, rdtype, origin, nsec_rrsets, closest_encloser is not None)

