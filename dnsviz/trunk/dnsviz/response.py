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
import collections
import datetime
import logging
import StringIO
import socket
import struct
import time

import dns.flags, dns.message, dns.rcode, dns.rdataclass, dns.rdatatype, dns.rrset

import base32
import crypto
import status
import format as fmt

def _rr_cmp(a, b):
    '''Compare the wire value of rdata a and rdata b.'''

    #XXX This is necessary because of a bug in dnspython
    a_val = a.to_digestable()
    b_val = b.to_digestable()

    if a_val < b_val:
        return -1
    elif a_val > b_val:
        return 1
    else:
        return 0

def tuple_to_dict(t):
    d = {}
    for n, v in t:
        if n not in t:
            d[n] = []
        d[n].append(v)
    return d

class DNSResponse:
    '''A DNS response, including meta information'''

    def __init__(self, message, error, errno, history, response_time, tcp_first):
        self.message = message
        self.error = error
        self.errno = errno
        self.history = history
        self.response_time = response_time
        self.tcp_first = tcp_first

        self.query = None

        self.effective_flags = None
        self.effective_edns = None
        self.effective_edns_max_udp_payload = None
        self.effective_edns_flags = None
        self.effective_edns_options = None

    def __unicode__(self):
        import query
        if self.message is not None:
            return repr(self.message)
        else:
            return query.response_errors.get(self.error)

    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, unicode(self))

    def copy(self):
        clone = DNSResponse(self.message, self.error, self.errno, self.history, self.response_time, self.tcp_first)
        clone.set_effective_request_options(self.effective_flags, self.effective_edns, self.effective_edns_max_udp_payload, self.effective_edns_flags, self.effective_edns_options)
        return clone

    def set_effective_request_options(self, flags, edns, edns_max_udp_payload, edns_flags, edns_options):
        self.effective_flags = flags
        self.effective_edns = edns
        self.effective_edns_max_udp_payload = edns_max_udp_payload
        self.effective_edns_flags = edns_flags
        self.effective_edns_options = edns_options

    def udp_used(self):
        '''Return True if UDP was used (in part) to receive the response from
        the server.'''
        import query

        if not self.tcp_first:
            return True
        for retry in self.history:
            if retry.action == query.RETRY_ACTION_USE_UDP:
                return True
        return False


    def tcp_used(self):
        '''Return True if TCP was used to receive the response from the
        server.'''
        import query

        if self.tcp_first:
            return True
        for retry in self.history:
            if retry.action == query.RETRY_ACTION_USE_TCP:
                return True
        return False

    def recursion_desired_and_available(self):
        '''Return True if the recursion desired (RD) bit was set in the request to the
        server AND the server indicated that recursion was available.'''

        return self.is_valid_response() and self.is_complete_response() and \
                bool(self.effective_flags & dns.flags.RD) and \
                bool(self.message.flags & dns.flags.RA)

    def dnssec_requested(self):
        '''Return True if the DNSSEC OK (DO) bit was set in the request to the
        server.'''

        return self.effective_edns >= 0 and self.effective_edns_flags & dns.flags.DO

    def is_valid_response(self):
        '''Return True if the message has a sane error code, namely NOERROR or
        NXDOMAIN.'''

        return self.message is not None and self.message.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)

    def is_complete_response(self):
        '''Return True if the message does not have the truncation (TC) bit
        set.'''

        return self.message is not None and not bool(self.message.flags & dns.flags.TC)

    def is_authoritative(self):
        '''Return True if the message has the authoritative answer (AA) bit
        set.'''

        return self.message is not None and bool(self.message.flags & dns.flags.AA)

    def is_referral(self, qname):
        '''Return True if this response yields a referral for the queried
        name.'''

        if not (self.is_valid_response() and self.is_complete_response()):
            return False
        return not self.is_authoritative() and \
                self.message.get_rrset(self.message.authority, qname, dns.rdataclass.IN, dns.rdatatype.NS) is not None

    def is_upward_referral(self, qname):
        '''Return True if this response yields an upward referral (i.e., a name
        that is a supedomain of qname).'''

        if not (self.is_valid_response() and self.is_complete_response()):
            return False
        return not self.is_authoritative() and \
                filter(lambda x: x.name != qname and qname.is_subdomain(x.name), self.message.authority)

    def is_answer(self, qname, rdtype):
        '''Return True if this response yields an answer for the queried name
        and type in the answer section.'''

        if not (self.is_valid_response() and self.is_complete_response()):
            return False
        if rdtype == dns.rdatatype.ANY and filter(lambda x: x.name == qname, self.message.answer):
            return True
        if filter(lambda x: x.name == qname and x.rdtype in (rdtype, dns.rdatatype.CNAME), self.message.answer):
            return True
        return False

    def is_nxdomain(self, qname, rdtype):
        '''Return True if this response indicates that the queried name does
        not exist (i.e., is NXDOMAIN).'''

        if not (self.is_valid_response() and self.is_complete_response()):
            return False

        if filter(lambda x: x.name == qname and x.rdtype in (rdtype, dns.rdatatype.CNAME), self.message.answer):
            return False

        if self.message.rcode() == dns.rcode.NXDOMAIN:
            return True

        return False

    def is_delegation(self, qname, rdtype):
        '''Return True if this response (from a request to a server
        authoritative for the immediate parent) yields NS records for the name 
        or provides a referral or NXDOMAIN or no data response.'''

        # if NS or SOA records were found in the answer or authority section
        return self.message.get_rrset(self.message.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS) is not None or \
                self.message.get_rrset(self.message.authority, qname, dns.rdataclass.IN, dns.rdatatype.NS) is not None or \
                self.message.get_rrset(self.message.authority, qname, dns.rdataclass.IN, dns.rdatatype.SOA) is not None

    def not_delegation(self, qname, rdtype):
        return not self.is_delegation(qname, rdtype)

    def ns_ip_mapping_from_additional(self, qname, bailiwick=None):
        ip_mapping = {}

        if not (self.is_valid_response() and self.is_complete_response()):
            return ip_mapping

        try:
            ns_rrset = self.message.find_rrset(self.message.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
        except KeyError:
            try:
                ns_rrset = self.message.find_rrset(self.message.authority, qname, dns.rdataclass.IN, dns.rdatatype.NS)
            except KeyError:
                return ip_mapping

        # iterate over each RR in the RR RRset
        for ns_rr in ns_rrset:
            ip_mapping[ns_rr.target] = set()

            if bailiwick is not None and not ns_rr.target.is_subdomain(bailiwick):
                continue

            for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                try:
                    a_rrset = self.message.find_rrset(self.message.additional, ns_rr.target, dns.rdataclass.IN, rdtype)
                except KeyError:
                    continue

                ip_mapping[ns_rr.target].update([a_rr.to_text() for a_rr in a_rrset])

        return ip_mapping

    def serialize(self):
        import query

        d = collections.OrderedDict()
        if self.message is None:
            d['message'] = None
            d['error'] = query.response_errors[self.error]
            if self.errno:
                d['errno'] = self.errno
        else:
            d['message'] = base64.b64encode(self.message.to_wire())
        d['tcp_first'] = self.tcp_first
        d['response_time'] = self.response_time
        d['history'] = []
        for retry in self.history:
            d['history'].append(retry.serialize())
        return d

    @classmethod
    def deserialize(cls, d):
        import query

        if 'error' in d:
            error = query.response_error_codes[d['error']]
        else:
            error = None
        if 'errno' in d:
            errno = d['errno']
        else:
            errno = None

        if d['message'] is None:
            message = None
        else:
            message = dns.message.from_wire(base64.b64decode(d['message']))

        tcp_first = d['tcp_first']
        response_time = d['response_time']
        history = []
        for retry in d['history']:
            history.append(query.DNSQueryRetryAttempt.deserialize(retry))
        return DNSResponse(message, error, errno, history, response_time, tcp_first)

class RDataMeta(object):
    def __init__(self, name, ttl, rdtype, rdata):
        self.name = name
        self.ttl = ttl
        self.rdtype = rdtype
        self.rdata = rdata
        self.servers_clients = set()
        self.rrset_info = set()
    
class DNSKEYMeta(object):
    def __init__(self, name, rdata, ttl):
        self.name = name
        self.rdata = rdata
        self.ttl = ttl
        self.servers_clients = set()
        self.servers_clients_without = set()
        self.warnings = []
        self.errors = []
        self.rrset_info = []

        self.key_tag = self.calc_key_tag(rdata)
        self.key_tag_no_revoke = self.calc_key_tag(rdata, True)
        self.key_len = self.calc_key_len(rdata)

    def __unicode__(self):
        return 'DNSKEY for %s (algorithm %d (%s), key tag %d)' % (self.name.canonicalize().to_text(), self.rdata.algorithm, fmt.DNSKEY_ALGORITHMS.get(self.rdata.algorithm, self.rdata.algorithm), self.key_tag)

    @classmethod
    def calc_key_tag(cls, rdata, clear_revoke=False):
        '''Return the key_tag for the key, as specified in RFC 4034.  If
        clear_revoke is True, then clear the revoke flag of the DNSKEY RR
        first.'''

        # algorithm 1 is a special case
        if rdata.algorithm == 1:
            key_tag, = struct.unpack('!H', rdata.key[-3:-1])
            return key_tag

        if clear_revoke:
            flags = rdata.flags & (~fmt.DNSKEY_FLAGS['revoke'])
        else:
            flags = rdata.flags

        key_str = struct.pack('!HBB', flags, rdata.protocol, rdata.algorithm) + rdata.key

        ac = 0
        for i in range(len(key_str)):
            b, = struct.unpack('B',key_str[i])
            if i & 1:
                ac += b
            else:
                ac += (b << 8)

        ac += (ac >> 16) & 0xffff
        return ac & 0xffff

    @classmethod
    def calc_key_len(cls, rdata):
        '''Return the length of the key modulus, in bits.'''

        key_str = rdata.key

        # RSA keys
        if rdata.algorithm in (1,5,7,8,10):
            try:
                # get the exponent length
                e_len, = struct.unpack('B',key_str[0])
            except IndexError:
                return 0

            offset = 1
            if e_len == 0:
                e_len, = struct.unpack('!H',key_str[1:3])
                offset = 3

            # get the exponent 
            offset += e_len

            # get the modulus
            return (len(key_str) - offset) << 3

        # DSA keys
        elif rdata.algorithm in (3,6):
            t, = struct.unpack('B',key_str[0])
            return (64 + t*8)<<3

        # GOST keys
        elif rdata.algorithm in (12,):
            return len(key_str)<<3

        # EC keys
        elif rdata.algorithm in (13,14):
            return len(key_str)<<3

        return None

    def message_for_ds(self, clear_revoke=False):
        '''Return the string value suitable for hashing to create a DS
        record.'''

        if clear_revoke:
            flags = self.rdata.flags & (~fmt.DNSKEY_FLAGS['revoke'])
        else:
            flags = self.rdata.flags

        s = StringIO.StringIO()

        self.name.canonicalize().to_wire(s)

        # write DNSKEY rdata in wire format
        rdata_wire = struct.pack('!HBB', flags, self.rdata.protocol, self.rdata.algorithm)
        s.write(rdata_wire)
        s.write(self.rdata.key)

        return s.getvalue()

    def serialize(self, consolidate_clients=True, loglevel=logging.DEBUG):
        show_basic = (self.warnings and loglevel <= logging.WARNING) or (self.errors and loglevel <= logging.ERROR)

        d = collections.OrderedDict()
        if loglevel <= logging.INFO or show_basic:
            d['description'] = unicode(self)
        if loglevel <= logging.DEBUG:
            d['flags'] = self.rdata.flags
            d['protocol'] = self.rdata.protocol
            d['algorithm'] = self.rdata.algorithm
            d['key'] = base64.b64encode(self.rdata.key)
            d['meta'] = collections.OrderedDict((
                ('ttl', self.ttl),
                ('key_length', self.key_len),
                ('key_tag', self.key_tag)
            ))
            if self.rdata.flags & fmt.DNSKEY_FLAGS['revoke']:
                d['meta']['key_tag_pre_revoke'] = self.key_tag_no_revoke

        elif show_basic:
            d['algorithm'] = self.rdata.algorithm
            d['meta'] = collections.OrderedDict((
                ('key_tag', self.key_tag),
            ))
        #TODO: put DNSKEY roles in meta, if it makes sense

        if loglevel <= logging.DEBUG or show_basic:
            servers = tuple_to_dict(self.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

            if self.servers_clients_without:
                servers = tuple_to_dict(self.servers_clients_without)
                if consolidate_clients:
                    servers = list(servers)
                    servers.sort()
                d['servers_without'] = servers

        if self.warnings and loglevel <= logging.WARNING:
            d['warnings'] = [status.dnskey_error_mapping[e] for e in self.warnings]
        if self.errors and loglevel <= logging.ERROR:
            d['errors'] = [status.dnskey_error_mapping[e] for e in self.errors]

        return d

class RRsetInfo(object):
    def __init__(self, rrset, dname_info=None):
        self.rrset = rrset
        self.rrsig_info = {}
        self.servers_clients = set()
        self.wildcard_info = {}

        self.dname_info = dname_info
        if self.dname_info is not None:
            self.servers_clients = dname_info.servers_clients

        self.cname_info_from_dname = []

    def __unicode__(self):
        return 'RRset for %s/%s' % (self.rrset.name.canonicalize().to_text(), dns.rdatatype.to_text(self.rrset.rdtype))

    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, unicode(self))

    def __eq__(self, other):
        return self.rrset == other.rrset and self.rrset.ttl == other.rrset.ttl and self.dname_info == other.dname_info
            
    def get_rrsig_info(self, rrsig):
        return self.rrsig_info[rrsig]

    def create_or_update_rrsig_info(self, rrsig, ttl, server, client):
        try:
            rrsig_info = self.get_rrsig_info(rrsig)
        except KeyError:
            rrsig_info = self.rrsig_info[rrsig] = RDataMeta(self.rrset.name, ttl, dns.rdatatype.RRSIG, rrsig)
        rrsig_info.servers_clients.add((server, client))
        self.set_wildcard_info(rrsig, server, client)

    def create_or_update_cname_from_dname_info(self, synthesized_cname_info, server, client):
        try:
            index = self.cname_info_from_dname.index(synthesized_cname_info)
            synthesized_cname_info = self.cname_info_from_dname[index]
        except ValueError:
            self.cname_info_from_dname.append(synthesized_cname_info)
        synthesized_cname_info.servers_clients.add((server, client))
        return synthesized_cname_info

    def is_wildcard(self, rrsig):
        if self.rrset.name[0] == '*':
            return False
        return len(self.rrset.name) - 1 > rrsig.labels

    def reduce_wildcard(self, rrsig):
        if self.is_wildcard(rrsig):
            return dns.name.Name(('*',)+self.rrset.name.labels[-(rrsig.labels+1):])
        return self.rrset.name

    def set_wildcard_info(self, rrsig, server, client):
        if self.is_wildcard(rrsig):
            wildcard_name = self.reduce_wildcard(rrsig)
            if wildcard_name not in self.wildcard_info:
                self.wildcard_info[wildcard_name] = set()
            self.wildcard_info[wildcard_name].add((server, client))

    def message_for_rrsig(self, rrsig):
        s = StringIO.StringIO()

        # write RRSIG in wire format
        rdata_wire = struct.pack('!HBBIIIH', rrsig.type_covered,
                             rrsig.algorithm, rrsig.labels,
                             rrsig.original_ttl, rrsig.expiration,
                             rrsig.inception, rrsig.key_tag)
        s.write(rdata_wire)
        rrsig.signer.canonicalize().to_wire(s)

        rdata_list = list(self.rrset)
        rdata_list.sort(cmp=_rr_cmp)

        rrset_name = self.reduce_wildcard(rrsig).canonicalize()
        for rdata in rdata_list:
            rdata_wire = rdata.to_digestable()
            rdata_len = len(rdata_wire)

            rrset_name.to_wire(s)
            stuff = struct.pack("!HHIH", self.rrset.rdtype, self.rrset.rdclass,
                                rrsig.original_ttl, rdata_len)
            s.write(stuff)
            s.write(rdata_wire)
        return s.getvalue()

    def serialize(self, include_rrsig_info=True, show_servers=True, consolidate_clients=True):
        d = collections.OrderedDict()
        if self.rrset.rdtype == dns.rdatatype.NSEC3:
            d['name'] = fmt.format_nsec3_name(self.rrset.name)
        else:
            d['name'] = self.rrset.name.canonicalize().to_text()
        d['ttl'] = self.rrset.ttl
        d['type'] = dns.rdatatype.to_text(self.rrset.rdtype)
        d['rdata'] = []
        rdata_list = list(self.rrset)
        rdata_list.sort(cmp=_rr_cmp)
        for rdata in rdata_list:
            if self.rrset.rdtype == dns.rdatatype.NSEC3:
                d['rdata'].append(fmt.format_nsec3_rrset_text(self.rrset[0].to_text()))
            else:
                d['rdata'].append(rdata.to_text())

        if include_rrsig_info:
            #TODO include RRSIG info...
            pass

        if show_servers:
            servers = tuple_to_dict(self.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

        return d

def cname_from_dname(name, dname_rrset):
    synthesized_cname = dns.name.Name(name.labels[:-len(dname_rrset.name)] + dname_rrset[0].target.labels)
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.CNAME)
    rrset.update_ttl(dname_rrset.ttl)
    rrset.add(dns.rdtypes.ANY.CNAME.CNAME(dns.rdataclass.IN, dns.rdatatype.CNAME, synthesized_cname))
    return rrset

class NSECSet(object):
    def __init__(self, rrsets, referral):
        self.rrsets = {}
        self.referral = referral
        self.nsec3_params = {}
        self.use_nsec3 = False
        for rrset in rrsets:
            #XXX There shouldn't be multple NSEC(3) RRsets of the same owner
            # name in the same response, but check for it and address it (if
            # necessary)
            assert rrset.name not in self.rrsets
            self.rrsets[rrset.name] = RRsetInfo(rrset)

            if rrset.rdtype == dns.rdatatype.NSEC3:
                self.use_nsec3 = True
                key = (rrset[0].salt, rrset[0].algorithm, rrset[0].iterations)
                if key not in self.nsec3_params:
                    self.nsec3_params[key] = set()
                self.nsec3_params[key].add(rrset.name)
        self.servers_clients = set()

    def __eq__(self, other):
        return self.rrsets == other.rrsets

    def __repr__(self):
        return '<%s>' % (self.__class__.__name__)

    def project(self, *names):
        if set(names).difference(self.rrsets):
            raise ValueError('NSEC name(s) don\'t exist in NSECSet')

        obj = self.__class__((), self.referral)
        for name in names:
            obj.rrsets[name] = self.rrsets[name]
            rrset = obj.rrsets[name].rrset
            if rrset.rdtype == dns.rdatatype.NSEC3:
                obj.use_nsec3 = True
                key = (rrset[0].salt, rrset[0].algorithm, rrset[0].iterations)
                if key not in obj.nsec3_params:
                    obj.nsec3_params[key] = set()
                obj.nsec3_params[key].add(rrset.name)
        obj.servers_clients = self.servers_clients.copy()
        return obj

    def add_server_client(self, server, client):
        for name, rrset_info in self.rrsets.items():
            rrset_info.servers_clients.add((server, client))
        self.servers_clients.add((server, client))

    def create_or_update_rrsig_info(self, name, rrsig, ttl, server, client):
        self.rrsets[name].create_or_update_rrsig_info(rrsig, ttl, server, client)

    def rdtype_exists_in_bitmap(self, nsec_name, rdtype):
        '''Return True if the rdtype exists in the bitmap of the NSEC(3) record
        corresponding to the name; False otherwise.'''

        rdtype_window = (rdtype >> 8)
        rdtype_bitmap = rdtype & 0x00ff
        bitmap_index, bitmap_offset = divmod(rdtype_bitmap, 8)
        for (window, bitmap) in self.rrsets[nsec_name].rrset[0].windows:
            try:
                if window == rdtype_window and ord(bitmap[bitmap_index]) & (0x80 >> bitmap_offset):
                    return True
            except IndexError:
                pass
        return False

    def name_for_nsec3_next(self, nsec_name):
        '''Convert the next field of an NSEC3 RR to a DNS name.'''

        next_name = self.rrsets[nsec_name].rrset[0].next
        next_name_txt = base32.b32encode(next_name)
        origin = dns.name.Name(nsec_name.labels[1:])
        return dns.name.from_text(next_name_txt, origin)
                    
    def _nsec_covers_name(self, name, nsec_name):
        '''Return True if the NSEC record corresponding to NSEC name provided
        covers a name (i.e., proves its non-existence); False otherwise.'''

        prev_name = nsec_name
        if self.use_nsec3:
            next_name = self.name_for_nsec3_next(nsec_name)
        else:
            next_name = self.rrsets[nsec_name].rrset[0].next

        if prev_name == next_name:
            return prev_name != name
        elif prev_name > next_name:
            return not (next_name <= name <= prev_name)
        else:
            return prev_name < name < next_name

    def nsec_covering_name(self, name):
        '''Return the set of owner names corresponding to NSEC records in the
        response that cover the given name.'''

        excluding_names = set()
        for nsec_name in self.rrsets:
            if self._nsec_covers_name(name, nsec_name):
                excluding_names.add(nsec_name)
        return excluding_names

    def get_digest_name_for_nsec3(self, name, origin, salt, alg, iterations):
        '''Return the DNS name corresponding to the name, origin, and NSEC3
        hash parameters provided.'''

        val = name.canonicalize().to_wire()
        digest = crypto.get_digest_for_nsec3(val, salt, alg, iterations)
        return dns.name.from_text(base32.b32encode(digest), origin)

    def nsec3_covering_name(self, name, salt, alg, iterations):
        '''Return the set of owner names corresponding to NSEC3 records in the
        response that cover the given (digest) name.'''

        excluding_names = set()
        for nsec_name in self.nsec3_params[(salt, alg, iterations)]:
            if self._nsec_covers_name(name, nsec_name):
                excluding_names.add(nsec_name)
        return excluding_names

    def _find_potential_closest_enclosers(self, qname, origin, salt, alg, iterations):
        '''Return a mapping of potential closest enclosers for a given name and
        origin, with digests computed with the given salt, algorithm, and
        iterations parameters.  The mapping maps a name to a set of
        corresponding digest names. The algorithm follows that specified in RFC
        5155 8.3.'''

        closest_enclosers = {}
        nsec3_names = self.nsec3_params[(salt, alg, iterations)]

        sname = qname
        flag = False
        while len(sname) >= len(origin):
            digest_name = self.get_digest_name_for_nsec3(sname, origin, salt, alg, iterations)

            if digest_name not in nsec3_names:
                flag = False

            if self.nsec_covering_name(digest_name):
                flag = True

            if digest_name in nsec3_names:
                if flag:
                    if sname not in closest_enclosers:
                        closest_enclosers[sname] = set()
                    closest_enclosers[sname].add(digest_name)
                break

            sname = dns.name.Name(sname.labels[1:])
        return closest_enclosers

    def check_closest_encloser(self, name, nsec_name, origin):
        '''Return True if the candidate closest encloser meets the requirements
        for a closest encloser in RFC 5155.'''

        if not name.is_subdomain(origin):
            return False
        if self.rdtype_exists_in_bitmap(nsec_name, dns.rdatatype.DNAME):
            return False
        if self.rdtype_exists_in_bitmap(nsec_name, dns.rdatatype.NS) and \
                not self.rdtype_exists_in_bitmap(nsec_name, dns.rdatatype.SOA):
            return False
        return True

    def get_closest_encloser(self, qname, origin):
        '''Return a mapping of closest enclosers for a given name and
        origin.'''

        potential_closest_enclosers = {}
        for salt, alg, iterations in self.nsec3_params:
            ret = self._find_potential_closest_enclosers(qname, origin, salt, alg, iterations)
            for name in ret:
                if name in potential_closest_enclosers:
                    potential_closest_enclosers[name].update(ret[name])
                else:
                    potential_closest_enclosers[name] = ret[name]

        for name in potential_closest_enclosers:
            for nsec_name in potential_closest_enclosers[name]:
                if not self.check_closest_encloser(name, nsec_name, origin):
                    potential_closest_enclosers[name].remove(nsec_name)
            if not potential_closest_enclosers[name]:
                del potential_closest_enclosers[name]

        return potential_closest_enclosers
