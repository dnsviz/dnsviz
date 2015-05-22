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

import base64
import cgi
import collections
import datetime
import hashlib
import logging
import StringIO
import socket
import struct
import time

import dns.flags, dns.message, dns.rcode, dns.rdataclass, dns.rdatatype, dns.rrset

import base32
import crypto
import format as fmt
from ipaddr import IPAddr
from util import tuple_to_dict

class DNSResponse:
    '''A DNS response, including meta information'''

    def __init__(self, message, msg_size, error, errno, history, response_time, query, review_history=True):
        self.message = message
        self.msg_size = msg_size
        self.error = error
        self.errno = errno
        self.history = history
        self.response_time = response_time

        self.query = query

        self.effective_flags = None
        self.effective_edns = None
        self.effective_edns_max_udp_payload = None
        self.effective_edns_flags = None
        self.effective_edns_options = None
        self.effective_tcp = None

        self.udp_attempted = None
        self.udp_responsive = None
        self.tcp_attempted = None
        self.tcp_responsive = None
        self.responsive_cause_index = None

        if review_history:
            self._review_history()

    def __unicode__(self):
        import query as Q
        if self.message is not None:
            return repr(self.message)
        else:
            return Q.response_errors.get(self.error)

    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, unicode(self))

    def section_rr_count(self, section):
        if self.message is None:
            return None
        n = 0
        for i in section:
            n += len(i)
        if section is self.message.additional and self.message.edns >= 0:
            n += 1
        return n

    def section_digest(self, section):
        if self.message is None:
            return None
        d = ''
        rrsets = section[:]
        rrsets.sort()
        for rrset in rrsets:
            d += RRsetInfo.rrset_canonicalized_to_wire(rrset, rrset.name, rrset.ttl)
        return 'md5'+hashlib.md5(d).hexdigest()

    def retries(self):
        return len(self.history)

    def total_response_time(self):
        t = self.response_time
        for retry in self.history:
            t += retry.response_time
        return t

    def copy(self):
        clone = DNSResponse(self.message, self.msg_size, self.error, self.errno, self.history, self.response_time, self.query, review_history=False)
        clone.set_effective_request_options(self.effective_flags, self.effective_edns, self.effective_edns_max_udp_payload, self.effective_edns_flags, self.effective_edns_options, self.effective_tcp)
        clone.set_responsiveness(self.udp_attempted, self.udp_responsive, self.tcp_attempted, self.tcp_responsive, self.responsive_cause_index)
        return clone

    def set_effective_request_options(self, flags, edns, edns_max_udp_payload, edns_flags, edns_options, effective_tcp):
        self.effective_flags = flags
        self.effective_edns = edns
        self.effective_edns_max_udp_payload = edns_max_udp_payload
        self.effective_edns_flags = edns_flags
        self.effective_edns_options = edns_options
        self.effective_tcp = effective_tcp

    def set_responsiveness(self, udp_attempted, udp_responsive, tcp_attempted, tcp_responsive, responsive_cause_index):
        self.udp_attempted = udp_attempted
        self.udp_responsive = udp_responsive
        self.tcp_attempted = tcp_attempted
        self.tcp_responsive = tcp_responsive
        self.responsive_cause_index = responsive_cause_index

    def _review_history(self):
        import query as Q

        flags = self.query.flags
        edns = self.query.edns
        edns_max_udp_payload = self.query.edns_max_udp_payload
        edns_flags = self.query.edns_flags
        edns_options = self.query.edns_options[:]

        # mark whether TCP or UDP was attempted initially
        tcp_attempted = tcp = self.query.tcp
        udp_attempted = not tcp

        tcp_responsive = False
        udp_responsive = False
        tcp_valid = False
        udp_valid = False

        #TODO - there could be room for both a responsiveness check and a valid
        # check here, rather than just a valid check

        responsive_cause_index = None

        prev_index = None
        for i, retry in enumerate(self.history):
            # mark if TCP or UDP was attempted prior to this retry
            if tcp:
                tcp_attempted = True
            else:
                udp_attempted = True

            # Mark responsiveness if this retry wasn't caused by network error
            # or timeout.
            if retry.cause not in (Q.RETRY_CAUSE_NETWORK_ERROR, Q.RETRY_CAUSE_TIMEOUT):
                if tcp:
                    tcp_responsive = True
                else:
                    udp_responsive = True

            # If the last cause/action resulted in a valid response where there
            # wasn't previously on the same protocol, then mark the
            # cause/action.
            if retry.cause in (Q.RETRY_CAUSE_TC_SET, Q.RETRY_CAUSE_DIAGNOSTIC):
                if tcp:
                    if responsive_cause_index is None and \
                            not tcp_valid and prev_index is not None and self.history[prev_index].action != Q.RETRY_ACTION_USE_TCP:
                        responsive_cause_index = prev_index
                    tcp_valid = True
                else:
                    if responsive_cause_index is None and \
                            not udp_valid and prev_index is not None and self.history[prev_index].action != Q.RETRY_ACTION_USE_UDP:
                        responsive_cause_index = prev_index
                    udp_valid = True

            if retry.action == Q.RETRY_ACTION_SET_FLAG:
                flags |= retry.action_arg
            elif retry.action == Q.RETRY_ACTION_CLEAR_FLAG:
                flags &= ~retry.action_arg
            elif retry.action == Q.RETRY_ACTION_DISABLE_EDNS:
                edns = -1
            elif retry.action == Q.RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD:
                edns_max_udp_payload = retry.action_arg
                tcp = False
            elif retry.action == Q.RETRY_ACTION_SET_EDNS_FLAG:
                edns_flags |= retry.action_arg
            elif retry.action == Q.RETRY_ACTION_CLEAR_EDNS_FLAG:
                edns_flags &= ~retry.action_arg
            elif retry.action == Q.RETRY_ACTION_USE_TCP:
                tcp = True
            elif retry.action == Q.RETRY_ACTION_USE_UDP:
                tcp = False
            #TODO do the same with EDNS options

            prev_index = i

        # Mark responsiveness if the ultimate query didn't result in network
        # error or timeout.
        if self.error not in (Q.RESPONSE_ERROR_NETWORK_ERROR, Q.RESPONSE_ERROR_TIMEOUT):
            if tcp:
                tcp_responsive = True
            else:
                udp_responsive = True

        # If the last cause/action resulted in a valid response where there
        # wasn't previously on the same protocol, then mark the cause/action.
        if self.is_valid_response():
            if tcp:
                if responsive_cause_index is None and \
                        not tcp_valid and prev_index is not None and self.history[prev_index].action != Q.RETRY_ACTION_USE_TCP:
                    responsive_cause_index = prev_index
            else:
                if responsive_cause_index is None and \
                        not udp_valid and prev_index is not None and self.history[prev_index].action != Q.RETRY_ACTION_USE_UDP:
                    responsive_cause_index = prev_index

        self.set_effective_request_options(flags, edns, edns_max_udp_payload, edns_flags, edns_options, tcp)
        self.set_responsiveness(udp_attempted, udp_responsive, tcp_attempted, tcp_responsive, responsive_cause_index)

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

    def is_referral(self, qname, rdtype, bailiwick, proper=False):
        '''Return True if this response yields a referral for the queried
        name.'''

        if not (self.is_valid_response() and self.is_complete_response()):
            return False
        # if no bailiwick is specified, then we cannot classify it as a
        # referral
        if bailiwick is None:
            return False
        # if the qname is not a proper subdomain of the bailiwick, then it
        # is not a referral
        if not (qname != bailiwick and qname.is_subdomain(bailiwick)):
            return False
        # if the name exists in the answer section with the requested rdtype or
        # CNAME, then it can't be a referral
        if filter(lambda x: x.name == qname and x.rdtype in (rdtype, dns.rdatatype.CNAME), self.message.answer):
            return False
        # if an SOA record with the given qname exists, then the server
        # is authoritative for the name, so it is a referral
        try:
            self.message.find_rrset(self.message.authority, qname, dns.rdataclass.IN, dns.rdatatype.SOA)
            return False
        except KeyError:
            pass
        # if proper referral is requested and qname is equal to of an NS RRset
        # in the authority, then it is a referral
        if proper:
            if filter(lambda x: qname == x.name and x.rdtype == dns.rdatatype.NS, self.message.authority):
                return True
        # if proper referral is NOT requested and qname is a subdomain of
        # (including equal to) of an NS RRset in the authority, then it is a
        # referral
        else:
            if filter(lambda x: qname.is_subdomain(x.name) and x.rdtype == dns.rdatatype.NS, self.message.authority):
                return True
        return False

    def is_upward_referral(self, qname):
        '''Return True if this response yields an upward referral (i.e., a name
        that is a supedomain of qname).'''

        if not (self.is_valid_response() and self.is_complete_response()):
            return False
        return bool(not self.is_authoritative() and \
                filter(lambda x: x.name != qname and qname.is_subdomain(x.name), self.message.authority))

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

                ip_mapping[ns_rr.target].update([IPAddr(a_rr.to_text()) for a_rr in a_rrset])

        return ip_mapping

    def serialize_meta(self):
        import query as Q

        d = collections.OrderedDict()

        # populate history, if not already populated
        if self.effective_flags is None:
            self._review_history()

        if self.message is None:
            d['error'] = Q.response_errors[self.error]
            if self.errno:
                d['errno'] = self.errno
        else:
            d['rcode'] = dns.rcode.to_text(self.message.rcode())
            if self.message.edns >= 0:
                d['edns_version'] = self.message.edns
            d['answer'] = collections.OrderedDict((
                ('count', self.section_rr_count(self.message.answer)),
                ('digest', self.section_digest(self.message.answer)),
            ))
            d['authority'] = collections.OrderedDict((
                ('count', self.section_rr_count(self.message.authority)),
                ('digest', self.section_digest(self.message.authority)),
            ))
            d['additional'] = collections.OrderedDict((
                ('count', self.section_rr_count(self.message.additional)),
                ('digest', self.section_digest(self.message.additional)),
            ))
            if not d['answer']['count']:
                del d['answer']['digest']
            if not d['authority']['count']:
                del d['authority']['digest']
            if not d['additional']['count']:
                del d['additional']['digest']

        if self.msg_size is not None:
            d['msg_size'] = self.msg_size
        d['response_time'] = self.response_time
        d['retries'] = self.retries()
        if self.history:
            d['cumulative_response_time'] = self.total_response_time()
            d['effective_query_options'] = collections.OrderedDict((
                ('flags', self.effective_flags),
                ('edns_version', self.effective_edns),
                ('edns_max_udp_payload', self.effective_edns_max_udp_payload),
                ('edns_flags', self.effective_edns_flags),
                ('edns_options', []),
            ))
            for o in self.effective_edns_options:
                s = StringIO.StringIO()
                o.to_wire(s)
                d['effective_query_options']['edns_options'].append(base64.b64encode(s.getvalue()))
            d['effective_query_options']['tcp'] = self.effective_tcp

            if self.responsive_cause_index is not None:
                d['responsiveness_impediment'] = collections.OrderedDict((
                    ('cause', Q.retry_causes[self.history[self.responsive_cause_index].cause]),
                    ('action', Q.retry_actions[self.history[self.responsive_cause_index].action])
                ))

        return d

    def serialize(self):
        import query as Q

        d = collections.OrderedDict()
        if self.message is None:
            d['message'] = None
            d['error'] = Q.response_errors[self.error]
            if self.errno:
                d['errno'] = self.errno
        else:
            d['message'] = base64.b64encode(self.message.to_wire())
        if self.msg_size is not None:
            d['msg_size'] = self.msg_size
        d['response_time'] = self.response_time
        d['history'] = []
        for retry in self.history:
            d['history'].append(retry.serialize())
        return d

    @classmethod
    def deserialize(cls, d, query):
        import query as Q

        if 'msg_size' in d:
            msg_size = int(d['msg_size'])
        else:
            msg_size = None
        if 'error' in d:
            error = Q.response_error_codes[d['error']]
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

        response_time = d['response_time']
        history = []
        for retry in d['history']:
            history.append(Q.DNSQueryRetryAttempt.deserialize(retry))
        return DNSResponse(message, msg_size, error, errno, history, response_time, query)

class DNSResponseComponent(object):
    def __init__(self):
        self.servers_clients = {}

    def add_server_client(self, server, client, response):
        if (server, client) not in self.servers_clients:
            self.servers_clients[(server, client)] = []
        self.servers_clients[(server, client)].append(response)

    @classmethod
    def insert_into_list(cls, component_info, component_info_list, server, client, response):
        try:
            index = component_info_list.index(component_info)
            component_info = component_info_list[index]
        except ValueError:
            component_info_list.append(component_info)
        component_info.add_server_client(server, client, response)
        return component_info

class RDataMeta(DNSResponseComponent):
    def __init__(self, name, ttl, rdtype, rdata):
        super(RDataMeta, self).__init__()
        self.name = name
        self.ttl = ttl
        self.rdtype = rdtype
        self.rdata = rdata
        self.rrset_info = set()

class DNSKEYMeta(DNSResponseComponent):
    def __init__(self, name, rdata, ttl):
        super(DNSKEYMeta, self).__init__()
        self.name = name
        self.rdata = rdata
        self.ttl = ttl
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

    def serialize(self, consolidate_clients=True, loglevel=logging.DEBUG, html_format=False):
        from analysis import status as Status

        show_basic = (self.warnings and loglevel <= logging.WARNING) or (self.errors and loglevel <= logging.ERROR)

        d = collections.OrderedDict()

        if html_format:
            formatter = lambda x: cgi.escape(x, True)
        else:
            formatter = lambda x: x

        if loglevel <= logging.INFO or show_basic:
            d['description'] = formatter(unicode(self))
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

            if html_format:
                flags = [t for (t,c) in fmt.DNSKEY_FLAGS.items() if c & self.rdata.flags]
                d['flags'] = '%d (%s)' % (self.rdata.flags, ', '.join(flags))
                d['protocol'] = '%d (%s)' % (self.rdata.protocol, fmt.DNSKEY_PROTOCOLS.get(self.rdata.protocol, self.rdata.protocol))
                d['algorithm'] = '%d (%s)' % (self.rdata.algorithm, fmt.DNSKEY_ALGORITHMS.get(self.rdata.algorithm, self.rdata.algorithm))
                d['meta']['ttl'] = '%d (%s)' % (self.ttl, fmt.humanize_time(self.ttl))
                if self.key_len is None:
                    d['meta']['key_length'] = 'unknown'
                else:
                    d['meta']['key_length'] = '%d bits' % (self.key_len)

        elif show_basic:
            d['algorithm'] = self.rdata.algorithm
            d['meta'] = collections.OrderedDict((
                ('key_tag', self.key_tag),
            ))

            if html_format:
                d['algorithm'] = '%d (%s)' % (self.rdata.algorithm, fmt.DNSKEY_ALGORITHMS.get(self.rdata.algorithm, self.rdata.algorithm))

        #TODO: put DNSKEY roles in meta, if it makes sense

        if loglevel <= logging.DEBUG or show_basic:
            servers = tuple_to_dict(self.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

        if self.warnings and loglevel <= logging.WARNING:
            d['warnings'] = [w.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for w in self.warnings]

        if self.errors and loglevel <= logging.ERROR:
            d['errors'] = [e.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for e in self.errors]

        return d

class RRsetInfo(DNSResponseComponent):
    def __init__(self, rrset, dname_info=None):
        super(RRsetInfo, self).__init__()
        self.rrset = rrset
        self.rrsig_info = {}
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

    @classmethod
    def rdata_cmp(cls, a, b):
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

    @classmethod
    def rrset_canonicalized_to_wire(cls, rrset, name, ttl):
        s = StringIO.StringIO()

        rdata_list = list(rrset)
        rdata_list.sort(cmp=cls.rdata_cmp)

        for rdata in rdata_list:
            rdata_wire = rdata.to_digestable()
            rdata_len = len(rdata_wire)

            name.to_wire(s)
            stuff = struct.pack("!HHIH", rrset.rdtype, rrset.rdclass,
                                ttl, rdata_len)
            s.write(stuff)
            s.write(rdata_wire)

        return s.getvalue()

    def get_rrsig_info(self, rrsig):
        return self.rrsig_info[rrsig]

    def update_rrsig_info(self, server, client, response, section, is_referral):
        try:
            rrsig_rrset = response.message.find_rrset(section, self.rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, self.rrset.rdtype)
            for rrsig in rrsig_rrset:
                self.create_or_update_rrsig_info(rrsig, rrsig_rrset.ttl, server, client, response, is_referral)
        except KeyError:
            pass

        if self.dname_info is not None:
            self.dname_info.update_rrsig_info(server, client, response, section, is_referral)

    def create_or_update_rrsig_info(self, rrsig, ttl, server, client, response, is_referral):
        try:
            rrsig_info = self.get_rrsig_info(rrsig)
        except KeyError:
            rrsig_info = self.rrsig_info[rrsig] = RDataMeta(self.rrset.name, ttl, dns.rdatatype.RRSIG, rrsig)
        rrsig_info.add_server_client(server, client, response)
        self.set_wildcard_info(rrsig, server, client, response, is_referral)

    def create_or_update_cname_from_dname_info(self, synthesized_cname_info, server, client, response):
        return self.insert_into_list(synthesized_cname_info, self.cname_info_from_dname, server, client, response)

    def is_wildcard(self, rrsig):
        if self.rrset.name[0] == '*':
            return False
        return len(self.rrset.name) - 1 > rrsig.labels

    def reduce_wildcard(self, rrsig):
        if self.is_wildcard(rrsig):
            return dns.name.Name(('*',)+self.rrset.name.labels[-(rrsig.labels+1):])
        return self.rrset.name

    def set_wildcard_info(self, rrsig, server, client, response, is_referral):
        if self.is_wildcard(rrsig):
            wildcard_name = self.reduce_wildcard(rrsig)
            if wildcard_name not in self.wildcard_info:
                self.wildcard_info[wildcard_name] = NegativeResponseInfo(self.rrset.name, self.rrset.rdtype)
            self.wildcard_info[wildcard_name].add_server_client(server, client, response)
            self.wildcard_info[wildcard_name].create_or_update_nsec_info(server, client, response, is_referral)

    def message_for_rrsig(self, rrsig):
        s = StringIO.StringIO()

        # write RRSIG in wire format
        rdata_wire = struct.pack('!HBBIIIH', rrsig.type_covered,
                             rrsig.algorithm, rrsig.labels,
                             rrsig.original_ttl, rrsig.expiration,
                             rrsig.inception, rrsig.key_tag)
        s.write(rdata_wire)
        rrsig.signer.canonicalize().to_wire(s)
        rrsig_canonicalized_wire = s.getvalue()

        rrset_name = self.reduce_wildcard(rrsig).canonicalize()
        rrset_canonicalized_wire = self.rrset_canonicalized_to_wire(self.rrset, rrset_name, rrsig.original_ttl)

        return rrsig_canonicalized_wire + rrset_canonicalized_wire

    def serialize(self, include_rrsig_info=True, show_servers=True, consolidate_clients=True, html_format=False):
        d = collections.OrderedDict()

        if html_format:
            formatter = lambda x: cgi.escape(x, True)
        else:
            formatter = lambda x: x

        if self.rrset.rdtype == dns.rdatatype.NSEC3:
            d['name'] = formatter(fmt.format_nsec3_name(self.rrset.name))
        else:
            d['name'] = formatter(self.rrset.name.canonicalize().to_text())
        d['ttl'] = self.rrset.ttl
        d['type'] = dns.rdatatype.to_text(self.rrset.rdtype)
        d['rdata'] = []
        rdata_list = list(self.rrset)
        rdata_list.sort(cmp=self.rdata_cmp)
        for rdata in rdata_list:
            if self.rrset.rdtype == dns.rdatatype.NSEC3:
                d['rdata'].append(fmt.format_nsec3_rrset_text(self.rrset[0].to_text()))
            else:
                d['rdata'].append(formatter(rdata.to_text()))

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

class NegativeResponseInfo(DNSResponseComponent):
    def __init__(self, qname, rdtype):
        super(NegativeResponseInfo, self).__init__()
        self.qname = qname
        self.rdtype = rdtype
        self.soa_rrset_info = []
        self.nsec_set_info = []

    def __repr__(self):
        return '<%s %s/%s>' % (self.__class__.__name__, self.qname, dns.rdatatype.to_text(self.rdtype))

    def __eq__(self, other):
        return self.qname == other.qname and self.rdtype == other.rdtype

    def create_or_update_soa_info(self, server, client, response, is_referral):
        soa_rrsets = filter(lambda x: x.rdtype == dns.rdatatype.SOA and self.qname.is_subdomain(x.name), response.message.authority)
        if not soa_rrsets:
            soa_rrsets = filter(lambda x: x.rdtype == dns.rdatatype.SOA, response.message.authority)
        soa_rrsets.sort(reverse=True)
        try:
            soa_rrset = soa_rrsets[0]
        except IndexError:
            soa_rrset = None

        if soa_rrset is None:
            return None

        soa_rrset_info = RRsetInfo(soa_rrset)
        soa_rrset_info = self.insert_into_list(soa_rrset_info, self.soa_rrset_info, server, client, response)
        soa_rrset_info.update_rrsig_info(server, client, response, response.message.authority, is_referral)

        return soa_rrset_info

    def create_or_update_nsec_info(self, server, client, response, is_referral):
        for rdtype in dns.rdatatype.NSEC, dns.rdatatype.NSEC3:
            nsec_rrsets = filter(lambda x: x.rdtype == rdtype, response.message.authority)
            if not nsec_rrsets:
                continue

            nsec_set_info = NSECSet(nsec_rrsets, is_referral)
            nsec_set_info = self.insert_into_list(nsec_set_info, self.nsec_set_info, server, client, response)

            for name in nsec_set_info.rrsets:
                nsec_set_info.rrsets[name].update_rrsig_info(server, client, response, response.message.authority, is_referral)

class NSECSet(DNSResponseComponent):
    def __init__(self, rrsets, referral):
        super(NSECSet, self).__init__()
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
        self.servers_clients = {}

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

    def add_server_client(self, server, client, response):
        super(NSECSet, self).add_server_client(server, client, response)
        for name, rrset_info in self.rrsets.items():
            rrset_info.add_server_client(server, client, response)

    def create_or_update_rrsig_info(self, name, rrsig, ttl, server, client, response, is_referral):
        self.rrsets[name].create_or_update_rrsig_info(rrsig, ttl, server, client, response, is_referral)

    def get_algorithm_support(self):
        valid_algorithms = set()
        invalid_algorithms = set()
        for (salt, alg, iterations) in self.nsec3_params:
            if crypto.nsec3_alg_is_supported(alg):
                valid_algorithms.add(alg)
            else:
                invalid_algorithms.add(alg)
        return valid_algorithms, invalid_algorithms

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
            return (prev_name < name < next_name) and not next_name.is_subdomain(name)

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
        if digest is None:
            return None
        else:
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

            # unsupported algorithm
            if digest_name is None:
                return closest_enclosers

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

        for name in list(potential_closest_enclosers):
            for nsec_name in list(potential_closest_enclosers[name]):
                if not self.check_closest_encloser(name, nsec_name, origin):
                    potential_closest_enclosers[name].remove(nsec_name)
            if not potential_closest_enclosers[name]:
                del potential_closest_enclosers[name]

        return potential_closest_enclosers

class DNSResponseError(DNSResponseComponent):
    def __init__(self, code, arg):
        super(DNSResponseError, self).__init__()
        self.code = code
        self.arg = arg

    def __eq__(self, other):
        return self.code == other.code and self.arg == other.arg
