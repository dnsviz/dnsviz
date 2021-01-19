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

import base64
import binascii
import copy
import errno
import codecs
import datetime
import hashlib
import io
import logging
import socket
import struct
import time

# minimal support for python2.6
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

# python3/python2 dual compatibility
try:
    from html import escape
except ImportError:
    from cgi import escape

import dns.edns, dns.flags, dns.message, dns.rcode, dns.rdataclass, dns.rdatatype, dns.rrset

from . import base32
from . import crypto
from . import format as fmt
from .ipaddr import IPAddr
from .util import tuple_to_dict
lb2s = fmt.latin1_binary_to_string

class DNSResponse:
    '''A DNS response, including meta information'''

    def __init__(self, message, msg_size, error, errno1, history, response_time, query, server_cookie, server_cookie_status, review_history=True):
        self.message = message
        self.msg_size = msg_size
        self.error = error
        self.errno = errno1
        self.history = history
        self.response_time = response_time

        self.query = query
        self.server_cookie = server_cookie
        self.server_cookie_status = server_cookie_status

        self.effective_flags = None
        self.effective_edns = None
        self.effective_edns_max_udp_payload = None
        self.effective_edns_flags = None
        self.effective_edns_options = None
        self.effective_tcp = None
        self.effective_server_cookie_status = None

        self.udp_attempted = None
        self.udp_responsive = None
        self.tcp_attempted = None
        self.tcp_responsive = None
        self.responsive_cause_index = None

        if review_history:
            self._review_history()

    def __str__(self):
        from . import query as Q
        if self.message is not None:
            return repr(self.message)
        else:
            return Q.response_errors.get(self.error)

    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, str(self))

    @classmethod
    def _query_tag_bind(cls, tcp, flags, edns, edns_flags, edns_max_udp_payload, edns_options, qname):
        s = []
        if flags & dns.flags.RD:
            s.append('+')
        else:
            s.append('-')
        if edns >= 0:
            s.append('E(%d)' % (edns))
        if tcp:
            s.append('T')
        if edns >= 0 and edns_flags & dns.flags.DO:
            s.append('D')
        if flags & dns.flags.CD:
            s.append('C')
        # Flags other than the ones commonly seen in queries
        if flags & dns.flags.AD:
            s.append('A')
        if flags & dns.flags.AA:
            s.append('a')
        if flags & dns.flags.TC:
            s.append('t')
        if flags & dns.flags.RA:
            s.append('r')
        if edns >= 0:
            # EDNS max UDP payload
            s.append('P(%d)' % edns_max_udp_payload)
            # EDNS flags other than DO
            if edns_flags & ~dns.flags.DO:
                s.append('F(0x%x)' % edns_flags)
            # other options
            for opt in edns_options:
                if opt.otype == 3:
                    # NSID
                    s.append('N')
                elif opt.otype == 8:
                    # EDNS Client Subnet
                    s.append('s')
                elif opt.otype == 10:
                    # DNS cookies
                    s.append('K')
        if qname.to_text() != qname.to_text().lower():
            s.append('X')
        return s

    @classmethod
    def _query_tag_human(cls, tcp, flags, edns, edns_flags, edns_max_udp_payload, edns_options, qname):
        s = ''
        if tcp:
            s += 'TCP_'
        else:
            s += 'UDP_'

        if flags & dns.flags.RD:
            s += '+'
        else:
            s += '-'
        if flags & dns.flags.CD:
            s += 'C'
        # Flags other than the ones commonly seen in queries
        if flags & dns.flags.AD:
            s += 'A'
        if flags & dns.flags.AA:
            s += 'a'
        if flags & dns.flags.TC:
            s += 't'
        if flags & dns.flags.RA:
            s += 'r'
        s += '_'

        if edns < 0:
            s += 'NOEDNS_'
        else:
            s += 'EDNS%d_' % (edns)

            # EDNS max UDP payload
            s += '%d_' % edns_max_udp_payload

            if edns_flags & dns.flags.DO:
                s += 'D'
            # EDNS flags other than DO
            if edns_flags & ~dns.flags.DO:
                s += '%d' % edns_flags

            if edns_options:
                s += '_'

            # other options
            for opt in edns_options:
                if opt.otype == 3:
                    # NSID
                    s += 'N'
                elif opt.otype == 8:
                    # EDNS Client Subnet
                    s += 's'
                elif opt.otype == 10:
                    # DNS cookies
                    s += 'K'
                else:
                    # DNS cookies
                    s += 'O(%d)' % opt.otype

        if qname.to_text() != qname.to_text().lower():
            s += '_0x20'
        return s

    def nsid_val(self):
        if self.message is None:
            return None

        if self.message.edns < 0:
            return None

        try:
            nsid_opt = [o for o in self.message.options if o.otype == dns.edns.NSID][0]
        except IndexError:
            return None

        try:
            nsid_val = nsid_opt.data.decode('ascii')
        except UnicodeDecodeError:
            nsid_val = '0x' + lb2s(binascii.hexlify(nsid_opt.data))
        return nsid_val

    def request_cookie_tag(self):
        from . import query as Q

        if self.effective_server_cookie_status == Q.DNS_COOKIE_NO_COOKIE:
            return 'NO_COOKIE'
        elif self.effective_server_cookie_status == Q.DNS_COOKIE_IMPROPER_LENGTH:
            return 'MALFORMED_COOKIE'
        elif self.effective_server_cookie_status == Q.DNS_COOKIE_CLIENT_COOKIE_ONLY:
            return 'CLIENT_COOKIE_ONLY'
        elif self.effective_server_cookie_status == Q.DNS_COOKIE_SERVER_COOKIE_FRESH:
            return 'VALID_SERVER_COOKIE'
        elif self.effective_server_cookie_status == Q.DNS_COOKIE_SERVER_COOKIE_BAD:
            return 'INVALID_SERVER_COOKIE'
        else:
            raise Exception('Unknown cookie status!')

    def response_cookie_tag(self):

        if self.message is None:
            return 'ERROR'

        if self.message.edns < 0:
            return 'NO_EDNS'

        try:
            cookie_opt = [o for o in self.message.options if o.otype == 10][0]
        except IndexError:
            return 'NO_COOKIE_OPT'

        if len(cookie_opt.data) < 8 or len(cookie_opt.data) > 40:
            return 'MALFORMED_COOKIE'

        elif len(cookie_opt.data) == 8:
            return 'CLIENT_COOKIE_ONLY'

        else:
            return 'CLIENT_AND_SERVER_COOKIE'

    def initial_query_tag(self):
        return ''.join(self._query_tag_human(self.query.tcp, self.query.flags, self.query.edns, self.query.edns_flags, self.query.edns_max_udp_payload, self.query.edns_options, self.query.qname))

    def effective_query_tag(self):
        return ''.join(self._query_tag_human(self.effective_tcp, self.effective_flags, self.effective_edns, self.effective_edns_flags, self.query.edns_max_udp_payload, self.effective_edns_options, self.query.qname))

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

    def get_cookie_opt(self):
        if self.message is None:
            return None
        try:
            return [o for o in self.message.options if o.otype == 10][0]
        except IndexError:
            return None

    def get_server_cookie(self):
        cookie_opt = self.get_cookie_opt()
        if cookie_opt is not None and len(cookie_opt.data) > 8:
            return cookie_opt.data[8:]
        return None

    def copy(self):
        clone = DNSResponse(self.message, self.msg_size, self.error, self.errno, self.history, self.response_time, self.query, self.server_cookie, self.server_cookie_status, review_history=False)
        clone.set_effective_request_options(self.effective_flags, self.effective_edns, self.effective_edns_max_udp_payload, self.effective_edns_flags, self.effective_edns_options, self.effective_tcp, self.effective_server_cookie_status)
        clone.set_responsiveness(self.udp_attempted, self.udp_responsive, self.tcp_attempted, self.tcp_responsive, self.responsive_cause_index, self.responsive_cause_index_tcp)
        return clone

    def set_effective_request_options(self, flags, edns, edns_max_udp_payload, edns_flags, edns_options, tcp, server_cookie_status):
        self.effective_flags = flags
        self.effective_edns = edns
        self.effective_edns_max_udp_payload = edns_max_udp_payload
        self.effective_edns_flags = edns_flags
        self.effective_edns_options = edns_options
        self.effective_tcp = tcp
        self.effective_server_cookie_status = server_cookie_status

    def set_responsiveness(self, udp_attempted, udp_responsive, tcp_attempted, tcp_responsive, responsive_cause_index, responsive_cause_index_tcp):
        self.udp_attempted = udp_attempted
        self.udp_responsive = udp_responsive
        self.tcp_attempted = tcp_attempted
        self.tcp_responsive = tcp_responsive
        self.responsive_cause_index = responsive_cause_index
        self.responsive_cause_index_tcp = responsive_cause_index_tcp

    def _review_history(self):
        from . import query as Q

        flags = self.query.flags
        edns = self.query.edns
        edns_max_udp_payload = self.query.edns_max_udp_payload
        edns_flags = self.query.edns_flags
        edns_options = copy.deepcopy(self.query.edns_options)
        server_cookie_status = self.server_cookie_status

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
        responsive_cause_index_tcp = tcp

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
                        responsive_cause_index_tcp = tcp
                    tcp_valid = True
                else:
                    if responsive_cause_index is None and \
                            not udp_valid and prev_index is not None and self.history[prev_index].action != Q.RETRY_ACTION_USE_UDP:
                        responsive_cause_index = prev_index
                        responsive_cause_index_tcp = tcp
                    udp_valid = True

            if retry.action == Q.RETRY_ACTION_NO_CHANGE:
                pass
            elif retry.action == Q.RETRY_ACTION_USE_TCP:
                tcp = True
            elif retry.action == Q.RETRY_ACTION_USE_UDP:
                tcp = False
            elif retry.action == Q.RETRY_ACTION_SET_FLAG:
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
            elif retry.action == Q.RETRY_ACTION_ADD_EDNS_OPTION:
                #TODO option data
                edns_options.append(dns.edns.GenericOption(retry.action_arg, b''))
            elif retry.action == Q.RETRY_ACTION_REMOVE_EDNS_OPTION:
                filtered_options = [x for x in edns_options if retry.action_arg == x.otype]
                if filtered_options:
                    edns_options.remove(filtered_options[0])
                    # If COOKIE option was removed, then reset
                    # server_cookie_status
                    if filtered_options[0].otype == 10:
                        server_cookie_status = Q.DNS_COOKIE_NO_COOKIE
            elif retry.action == Q.RETRY_ACTION_CHANGE_SPORT:
                pass
            elif retry.action == Q.RETRY_ACTION_CHANGE_EDNS_VERSION:
                edns = retry.action_arg
            elif retry.action == Q.RETRY_ACTION_UPDATE_DNS_COOKIE:
                server_cookie_status = Q.DNS_COOKIE_SERVER_COOKIE_FRESH

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
                    responsive_cause_index_tcp = tcp
            else:
                if responsive_cause_index is None and \
                        not udp_valid and prev_index is not None and self.history[prev_index].action != Q.RETRY_ACTION_USE_UDP:
                    responsive_cause_index = prev_index
                    responsive_cause_index_tcp = tcp

        # If EDNS was effectively disabled, reset EDNS options
        if edns < 0:
            edns_max_udp_payload = None
            edns_flags = 0
            edns_options = []
            server_cookie_status = Q.DNS_COOKIE_NO_COOKIE

        self.set_effective_request_options(flags, edns, edns_max_udp_payload, edns_flags, edns_options, tcp, server_cookie_status)
        self.set_responsiveness(udp_attempted, udp_responsive, tcp_attempted, tcp_responsive, responsive_cause_index, responsive_cause_index_tcp)

    def recursion_desired(self):
        '''Return True if the recursion desired (RD) bit was set in the request to the
        server.'''

        return self.is_valid_response() and self.is_complete_response() and \
                bool(self.effective_flags & dns.flags.RD)

    def recursion_available(self):
        '''Return True if the server indicated that recursion was available.'''

        return self.is_valid_response() and self.is_complete_response() and \
                bool(self.message.flags & dns.flags.RA)

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

    def is_referral(self, qname, rdtype, rdclass, bailiwick, proper=False):
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
        if [x for x in self.message.answer if x.name == qname and x.rdtype in (rdtype, dns.rdatatype.CNAME) and x.rdclass == rdclass]:
            return False
        # if an SOA record with the given qname exists, then the server
        # is authoritative for the name, so it is a referral
        try:
            self.message.find_rrset(self.message.authority, qname, rdclass, dns.rdatatype.SOA)
            return False
        except KeyError:
            pass
        # if proper referral is requested and qname is equal to of an NS RRset
        # in the authority, then it is a referral
        if proper:
            if [x for x in self.message.authority if qname == x.name and x.rdtype == dns.rdatatype.NS and x.rdclass == rdclass]:
                return True
        # if proper referral is NOT requested, qname is a subdomain of
        # (including equal to) an NS RRset in the authority, and qname is not
        # equal to bailiwick, then it is a referral
        else:
            if [x for x in self.message.authority if qname.is_subdomain(x.name) and bailiwick != x.name and x.rdtype == dns.rdatatype.NS and x.rdclass == rdclass]:
                return True
        return False

    def is_upward_referral(self, qname):
        '''Return True if this response yields an upward referral (i.e., a name
        that is a superdomain of qname).'''

        if not (self.is_valid_response() and self.is_complete_response()):
            return False
        return bool(not self.is_authoritative() and \
                [x for x in self.message.authority if x.name != qname and qname.is_subdomain(x.name)])

    def is_answer(self, qname, rdtype, include_cname=True):
        '''Return True if this response yields an answer for the queried name
        and type in the answer section.  If include_cname is False, then only
        non-CNAME records count.'''

        if not (self.is_valid_response() and self.is_complete_response()):
            return False
        if rdtype == dns.rdatatype.ANY and [x for x in self.message.answer if x.name == qname]:
            return True
        rdtypes = [rdtype]
        if include_cname:
            rdtypes.append(dns.rdatatype.CNAME)
        if [x for x in self.message.answer if x.name == qname and x.rdtype in rdtypes]:
            return True
        return False

    def is_nxdomain(self, qname, rdtype):
        '''Return True if this response indicates that the queried name does
        not exist (i.e., is NXDOMAIN).'''

        if not (self.is_valid_response() and self.is_complete_response()):
            return False

        if [x for x in self.message.answer if x.name == qname and x.rdtype in (rdtype, dns.rdatatype.CNAME)]:
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
        from . import query as Q

        d = OrderedDict()

        # populate history, if not already populated
        if self.effective_flags is None:
            self._review_history()

        if self.message is None:
            d['error'] = Q.response_errors[self.error]
            if self.errno is not None:
                errno_name = errno.errorcode.get(self.errno, None)
                if errno_name is not None:
                    d['errno'] = errno_name
        else:
            d['rcode'] = dns.rcode.to_text(self.message.rcode())
            if self.message.edns >= 0:
                d['edns_version'] = self.message.edns
            d['answer'] = OrderedDict((
                ('count', self.section_rr_count(self.message.answer)),
                ('digest', self.section_digest(self.message.answer)),
            ))
            d['authority'] = OrderedDict((
                ('count', self.section_rr_count(self.message.authority)),
                ('digest', self.section_digest(self.message.authority)),
            ))
            d['additional'] = OrderedDict((
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
        d['time_elapsed'] = int(self.response_time * 1000)
        d['retries'] = self.retries()
        if self.history:
            d['cumulative_response_time'] = int(self.total_response_time() * 1000)
            d['effective_query_options'] = OrderedDict((
                ('flags', self.effective_flags),
                ('edns_version', self.effective_edns),
                ('edns_max_udp_payload', self.effective_edns_max_udp_payload),
                ('edns_flags', self.effective_edns_flags),
                ('edns_options', []),
            ))
            for o in self.effective_edns_options:
                s = io.BytesIO()
                o.to_wire(s)
                d['effective_query_options']['edns_options'].append((o.type, binascii.hexlify(s.getvalue())))
            d['effective_query_options']['tcp'] = self.effective_tcp

            if self.responsive_cause_index is not None:
                d['responsiveness_impediment'] = OrderedDict((
                    ('cause', Q.retry_causes[self.history[self.responsive_cause_index].cause]),
                    ('action', Q.retry_actions[self.history[self.responsive_cause_index].action])
                ))

        return d

    def serialize(self):
        from . import query as Q

        d = OrderedDict()
        if self.message is None:
            d['message'] = None
            d['error'] = Q.response_errors[self.error]
            if self.errno is not None:
                errno_name = errno.errorcode.get(self.errno, None)
                if errno_name is not None:
                    d['errno'] = errno_name
        else:
            d['message'] = lb2s(base64.b64encode(self.message.to_wire()))
        if self.msg_size is not None:
            d['msg_size'] = self.msg_size
        d['time_elapsed'] = int(self.response_time * 1000)
        d['history'] = []
        for retry in self.history:
            d['history'].append(retry.serialize())
        return d

    @classmethod
    def deserialize(cls, d, query, server_cookie, server_cookie_status):
        from . import query as Q

        if 'msg_size' in d:
            msg_size = int(d['msg_size'])
        else:
            msg_size = None
        if 'error' in d:
            error = Q.response_error_codes[d['error']]
        else:
            error = None
        if 'errno' in d:
            # compatibility with version 1.0
            if isinstance(d['errno'], int):
                errno1 = d['errno']
            else:
                if hasattr(errno, d['errno']):
                    errno1 = getattr(errno, d['errno'])
                else:
                    errno1 = None
        else:
            errno1 = None

        if d['message'] is None:
            message = None
        else:
            wire = base64.b64decode(d['message'])
            try:
                message = dns.message.from_wire(wire)
            except Exception as e:
                message = None
                if isinstance(e, (struct.error, dns.exception.FormError)):
                    error = Q.RESPONSE_ERROR_FORMERR
                #XXX need to determine how to handle non-parsing
                # validation errors with dnspython (e.g., signature with
                # no keyring)
                else:
                    error = Q.RESPONSE_ERROR_OTHER

        # compatibility with version 1.0
        if 'response_time' in d:
            response_time = d['response_time']
        else:
            response_time = d['time_elapsed']/1000.0
        history = []
        for retry in d['history']:
            history.append(Q.DNSQueryRetryAttempt.deserialize(retry))
        return DNSResponse(message, msg_size, error, errno1, history, response_time, query, server_cookie, server_cookie_status)

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

    def __str__(self):
        return 'DNSKEY for %s (algorithm %d (%s), key tag %d)' % (fmt.humanize_name(self.name), self.rdata.algorithm, fmt.DNSKEY_ALGORITHMS.get(self.rdata.algorithm, self.rdata.algorithm), self.key_tag)

    @classmethod
    def calc_key_tag(cls, rdata, clear_revoke=False):
        '''Return the key_tag for the key, as specified in RFC 4034.  If
        clear_revoke is True, then clear the revoke flag of the DNSKEY RR
        first.'''

        # python3/python2 dual compatibility
        if isinstance(rdata.key, bytes):
            if isinstance(rdata.key, str):
                map_func = lambda x, y: ord(x[y])
            else:
                map_func = lambda x, y: x[y]
        else:
            map_func = lambda x, y: struct.unpack(b'B',x[y])[0]

        # algorithm 1 is a special case
        if rdata.algorithm == 1:
            b1 = map_func(rdata.key, -3)
            b2 = map_func(rdata.key, -2)
            return (b1 << 8) | b2

        if clear_revoke:
            flags = rdata.flags & (~fmt.DNSKEY_FLAGS['revoke'])
        else:
            flags = rdata.flags

        key_str = struct.pack(b'!HBB', flags, rdata.protocol, rdata.algorithm) + rdata.key

        ac = 0
        for i in range(len(key_str)):
            b = map_func(key_str, i)
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

        # python3/python2 dual compatibility
        if isinstance(rdata.key, bytes):
            if isinstance(rdata.key, str):
                map_func = lambda x, y: ord(x[y])
            else:
                map_func = lambda x, y: x[y]
        else:
            map_func = lambda x, y: struct.unpack(b'B',x[y])[0]

        # RSA keys
        if rdata.algorithm in (1,5,7,8,10):
            try:
                # get the exponent length
                e_len = map_func(key_str, 0)
            except IndexError:
                return 0

            offset = 1
            if e_len == 0:
                b1 = map_func(key_str, 1)
                b2 = map_func(key_str, 2)
                e_len = (b1 << 8) | b2
                offset = 3

            # get the exponent
            offset += e_len

            # get the modulus
            key_len = len(key_str) - offset

            # if something went wrong here, use key length of rdata key
            if key_len <= 0:
                return len(key_str)<<3

            return key_len << 3

        # DSA keys
        elif rdata.algorithm in (3,6):
            t = map_func(key_str, 0)
            return (64 + t*8)<<3

        # GOST keys
        elif rdata.algorithm in (12,):
            return len(key_str)<<3

        # EC keys
        elif rdata.algorithm in (13,14):
            return len(key_str)<<3

        # EDDSA keys
        elif rdata.algorithm in (15,16):
            return len(key_str)<<3

        # other keys - just guess, based on the length of the raw key material
        else:
            return len(key_str)<<3

    def message_for_ds(self, clear_revoke=False):
        '''Return the string value suitable for hashing to create a DS
        record.'''

        if clear_revoke:
            flags = self.rdata.flags & (~fmt.DNSKEY_FLAGS['revoke'])
        else:
            flags = self.rdata.flags

        name_wire = self.name.canonicalize().to_wire()

        # write DNSKEY rdata in wire format
        rdata_wire = struct.pack(b'!HBB', flags, self.rdata.protocol, self.rdata.algorithm)

        return name_wire + rdata_wire + self.rdata.key

    def serialize(self, consolidate_clients=True, show_servers=True, loglevel=logging.DEBUG, html_format=False, map_ip_to_ns_name=None):
        from .analysis import status as Status

        show_id = loglevel <= logging.INFO or \
                (self.warnings and loglevel <= logging.WARNING) or \
                (self.errors and loglevel <= logging.ERROR)

        d = OrderedDict()

        if html_format:
            formatter = lambda x: escape(x, True)
        else:
            formatter = lambda x: x

        if show_id:
            d['id'] = '%d/%d' % (self.rdata.algorithm, self.key_tag)
        if loglevel <= logging.DEBUG:
            d['description'] = formatter(str(self))
            d['flags'] = self.rdata.flags
            d['protocol'] = self.rdata.protocol
            d['algorithm'] = self.rdata.algorithm
            d['key'] = lb2s(base64.b64encode(self.rdata.key))
            d['ttl'] = self.ttl
            d['key_length'] = self.key_len
            d['key_tag'] = self.key_tag
            if self.rdata.flags & fmt.DNSKEY_FLAGS['revoke']:
                d['key_tag_pre_revoke'] = self.key_tag_no_revoke

            if html_format:
                flags = [t for (t,c) in fmt.DNSKEY_FLAGS.items() if c & self.rdata.flags]
                d['flags'] = '%d (%s)' % (self.rdata.flags, ', '.join(flags))
                d['protocol'] = '%d (%s)' % (self.rdata.protocol, fmt.DNSKEY_PROTOCOLS.get(self.rdata.protocol, self.rdata.protocol))
                d['algorithm'] = '%d (%s)' % (self.rdata.algorithm, fmt.DNSKEY_ALGORITHMS.get(self.rdata.algorithm, self.rdata.algorithm))
                d['ttl'] = '%d (%s)' % (self.ttl, fmt.humanize_time(self.ttl))
                if self.key_len is None:
                    d['key_length'] = 'unknown'
                else:
                    d['key_length'] = '%d bits' % (self.key_len)

        #TODO: put DNSKEY roles in meta, if it makes sense

        if loglevel <= logging.INFO:
            servers = tuple_to_dict(self.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

            if map_ip_to_ns_name is not None:
                ns_names = list(set([lb2s(map_ip_to_ns_name(s)[0][0].canonicalize().to_text()) for s in servers]))
                ns_names.sort()
                d['ns_names'] = ns_names

            tags = set()
            nsids = set()
            for server,client in self.servers_clients:
                for response in self.servers_clients[(server,client)]:
                    tags.add(response.effective_query_tag())
                    nsid = response.nsid_val()
                    if nsid is not None:
                        nsids.add(nsid)

            if nsids:
                d['nsid_values'] = list(nsids)
                d['nsid_values'].sort()

            d['query_options'] = list(tags)
            d['query_options'].sort()

        if self.warnings and loglevel <= logging.WARNING:
            d['warnings'] = [w.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for w in self.warnings]

        if self.errors and loglevel <= logging.ERROR:
            d['errors'] = [e.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for e in self.errors]

        return d

#XXX This class is necessary because of a bug in dnspython, in which
# comparisons are not properly made for the purposes of sorting rdata for RRSIG
# validation
class RdataWrapper(object):
    def __init__(self, rdata):
        self._rdata = rdata

    def __eq__(self, other):
        return self._rdata.to_digestable() == other._rdata.to_digestable()

    def __lt__(self, other):
        return self._rdata.to_digestable() < other._rdata.to_digestable()

class RRsetInfo(DNSResponseComponent):
    def __init__(self, rrset, ttl_cmp, dname_info=None):
        super(RRsetInfo, self).__init__()
        self.rrset = rrset
        self.ttl_cmp = ttl_cmp
        self.rrsig_info = {}
        self.wildcard_info = {}

        self.dname_info = dname_info
        if self.dname_info is not None:
            self.servers_clients = dname_info.servers_clients

        self.cname_info_from_dname = []

    def __str__(self):
        if self.rrset.rdtype == dns.rdatatype.NSEC3:
            return 'RRset for %s/%s' % (fmt.format_nsec3_name(self.rrset.name).rstrip('.'), dns.rdatatype.to_text(self.rrset.rdtype))
        else:
            return 'RRset for %s/%s' % (fmt.humanize_name(self.rrset.name), dns.rdatatype.to_text(self.rrset.rdtype))

    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, str(self))

    def __eq__(self, other):
        if not (self.rrset == other.rrset and self.dname_info == other.dname_info):
            return False
        if self.ttl_cmp and self.rrset.ttl != other.rrset.ttl:
            return False
        return True

    def __hash__(self):
        return hash(id(self))

    @classmethod
    def rrset_canonicalized_to_wire(cls, rrset, name, ttl):
        s = b''
        name_wire = name.to_wire()

        rdata_list = [RdataWrapper(x) for x in rrset]
        rdata_list.sort()

        for rdataw in rdata_list:
            rdata = rdataw._rdata
            rdata_wire = rdata.to_digestable()
            rdata_len = len(rdata_wire)

            stuff = struct.pack(b'!HHIH', rrset.rdtype, rrset.rdclass,
                                ttl, rdata_len)
            s += name_wire + stuff + rdata_wire

        return s

    def get_rrsig_info(self, rrsig):
        return self.rrsig_info[rrsig]

    def update_rrsig_info(self, server, client, response, section, rdclass, is_referral):
        try:
            rrsig_rrset = response.message.find_rrset(section, self.rrset.name, rdclass, dns.rdatatype.RRSIG, self.rrset.rdtype)
            for rrsig in rrsig_rrset:
                self.create_or_update_rrsig_info(rrsig, rrsig_rrset.ttl, server, client, response, rdclass, is_referral)
        except KeyError:
            pass

        if self.dname_info is not None:
            self.dname_info.update_rrsig_info(server, client, response, section, rdclass, is_referral)

    def create_or_update_rrsig_info(self, rrsig, ttl, server, client, response, rdclass, is_referral):
        try:
            rrsig_info = self.get_rrsig_info(rrsig)
        except KeyError:
            rrsig_info = self.rrsig_info[rrsig] = RDataMeta(self.rrset.name, ttl, dns.rdatatype.RRSIG, rrsig)
        rrsig_info.add_server_client(server, client, response)
        self.set_wildcard_info(rrsig, server, client, response, rdclass, is_referral)

    def create_or_update_cname_from_dname_info(self, synthesized_cname_info, server, client, response, rdclass):
        return self.insert_into_list(synthesized_cname_info, self.cname_info_from_dname, server, client, response)

    def is_wildcard(self, rrsig):
        if self.rrset.name[0] == b'*':
            return False
        return len(self.rrset.name) - 1 > rrsig.labels

    def reduce_wildcard(self, rrsig):
        if self.is_wildcard(rrsig):
            return dns.name.Name(('*',)+self.rrset.name.labels[-(rrsig.labels+1):])
        return self.rrset.name

    def set_wildcard_info(self, rrsig, server, client, response, rdclass, is_referral):
        if self.is_wildcard(rrsig):
            wildcard_name = self.reduce_wildcard(rrsig)
            if wildcard_name not in self.wildcard_info:
                self.wildcard_info[wildcard_name] = NegativeResponseInfo(self.rrset.name, self.rrset.rdtype, self.ttl_cmp)
            self.wildcard_info[wildcard_name].add_server_client(server, client, response)
            self.wildcard_info[wildcard_name].create_or_update_nsec_info(server, client, response, rdclass, is_referral)

    def message_for_rrsig(self, rrsig):

        # write RRSIG in wire format
        rdata_wire = struct.pack(b'!HBBIIIH', rrsig.type_covered,
                             rrsig.algorithm, rrsig.labels,
                             rrsig.original_ttl, rrsig.expiration,
                             rrsig.inception, rrsig.key_tag)
        signer_wire = rrsig.signer.canonicalize().to_wire()
        rrsig_canonicalized_wire = rdata_wire + signer_wire

        rrset_name = self.reduce_wildcard(rrsig).canonicalize()
        rrset_canonicalized_wire = self.rrset_canonicalized_to_wire(self.rrset, rrset_name, rrsig.original_ttl)

        return rrsig_canonicalized_wire + rrset_canonicalized_wire

    def serialize(self, consolidate_clients=True, show_servers=True, loglevel=logging.DEBUG, html_format=False, map_ip_to_ns_name=None):
        d = OrderedDict()

        if html_format:
            formatter = lambda x: escape(x, True)
        else:
            formatter = lambda x: x

        if self.rrset.rdtype == dns.rdatatype.NSEC3:
            d['name'] = formatter(fmt.format_nsec3_name(self.rrset.name))
        else:
            d['name'] = formatter(lb2s(self.rrset.name.canonicalize().to_text()))
        d['ttl'] = self.rrset.ttl
        d['type'] = dns.rdatatype.to_text(self.rrset.rdtype)
        d['rdata'] = []
        rdata_list = [RdataWrapper(x) for x in self.rrset]
        rdata_list.sort()
        for rdataw in rdata_list:
            rdata = rdataw._rdata
            if self.rrset.rdtype == dns.rdatatype.NSEC3:
                d['rdata'].append(fmt.format_nsec3_rrset_text(self.rrset[0].to_text()))
            else:
                s = rdata.to_text()
                # python3/python2 dual compatibility
                if not isinstance(s, str):
                    s = lb2s(s)
                d['rdata'].append(formatter(s))

        if loglevel <= logging.INFO:
            servers = tuple_to_dict(self.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

            if map_ip_to_ns_name is not None:
                ns_names = list(set([lb2s(map_ip_to_ns_name(s)[0][0].canonicalize().to_text()) for s in servers]))
                ns_names.sort()
                d['ns_names'] = ns_names

            tags = set()
            nsids = set()
            for server,client in self.servers_clients:
                for response in self.servers_clients[(server,client)]:
                    tags.add(response.effective_query_tag())
                    nsid = response.nsid_val()
                    if nsid is not None:
                        nsids.add(nsid)

            if nsids:
                d['nsid_values'] = list(nsids)
                d['nsid_values'].sort()

            d['query_options'] = list(tags)
            d['query_options'].sort()

        return d

def cname_from_dname(name, dname_rrset):
    synthesized_cname = dns.name.Name(name.labels[:-len(dname_rrset.name)] + dname_rrset[0].target.labels)
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.CNAME)
    rrset.update_ttl(dname_rrset.ttl)
    rrset.add(dns.rdtypes.ANY.CNAME.CNAME(dns.rdataclass.IN, dns.rdatatype.CNAME, synthesized_cname))
    return rrset

class NegativeResponseInfo(DNSResponseComponent):
    def __init__(self, qname, rdtype, ttl_cmp):
        super(NegativeResponseInfo, self).__init__()
        self.qname = qname
        self.rdtype = rdtype
        self.ttl_cmp = ttl_cmp
        self.soa_rrset_info = []
        self.nsec_set_info = []

    def __repr__(self):
        return '<%s %s/%s>' % (self.__class__.__name__, self.qname, dns.rdatatype.to_text(self.rdtype))

    def __eq__(self, other):
        return self.qname == other.qname and self.rdtype == other.rdtype

    def __hash__(self):
        return hash(id(self))

    def create_or_update_soa_info(self, server, client, response, rdclass, is_referral):
        soa_rrsets = [x for x in response.message.authority if x.rdtype == dns.rdatatype.SOA and x.rdclass == rdclass and self.qname.is_subdomain(x.name)]
        if not soa_rrsets:
            soa_rrsets = [x for x in response.message.authority if x.rdtype == dns.rdatatype.SOA and x.rdclass == rdclass]
        soa_rrsets.sort(reverse=True)
        try:
            soa_rrset = soa_rrsets[0]
        except IndexError:
            soa_rrset = None

        if soa_rrset is None:
            return None

        soa_rrset_info = RRsetInfo(soa_rrset, self.ttl_cmp)
        soa_rrset_info = self.insert_into_list(soa_rrset_info, self.soa_rrset_info, server, client, response)
        soa_rrset_info.update_rrsig_info(server, client, response, response.message.authority, rdclass, is_referral)

        return soa_rrset_info

    def create_or_update_nsec_info(self, server, client, response, rdclass, is_referral):
        for rdtype in dns.rdatatype.NSEC, dns.rdatatype.NSEC3:
            nsec_rrsets = [x for x in response.message.authority if x.rdtype == rdtype and x.rdclass == rdclass]
            if not nsec_rrsets:
                continue

            nsec_set_info = NSECSet(nsec_rrsets, is_referral, self.ttl_cmp)
            nsec_set_info = self.insert_into_list(nsec_set_info, self.nsec_set_info, server, client, response)

            for name in nsec_set_info.rrsets:
                nsec_set_info.rrsets[name].update_rrsig_info(server, client, response, response.message.authority, rdclass, is_referral)

class NSECSet(DNSResponseComponent):
    def __init__(self, rrsets, referral, ttl_cmp):
        super(NSECSet, self).__init__()
        self.rrsets = {}
        self.referral = referral
        self.ttl_cmp = ttl_cmp
        self.nsec3_params = {}
        self.invalid_nsec3_owner = set()
        self.invalid_nsec3_hash = set()
        self.use_nsec3 = False
        for rrset in rrsets:
            #XXX There shouldn't be multiple NSEC(3) RRsets of the same owner
            # name in the same response, but check for it and address it (if
            # necessary)
            assert rrset.name not in self.rrsets
            self.rrsets[rrset.name] = RRsetInfo(rrset, self.ttl_cmp)

            if rrset.rdtype == dns.rdatatype.NSEC3:
                self.use_nsec3 = True
                key = (rrset[0].salt, rrset[0].algorithm, rrset[0].iterations)
                if key not in self.nsec3_params:
                    self.nsec3_params[key] = set()
                self.nsec3_params[key].add(rrset.name)
                if not self.is_valid_nsec3_name(rrset.name, rrset[0].algorithm):
                    self.invalid_nsec3_owner.add(rrset.name)
                if not self.is_valid_nsec3_hash(rrset[0].next, rrset[0].algorithm):
                    self.invalid_nsec3_hash.add(rrset.name)

        self.servers_clients = {}

    def __repr__(self):
        return '<%s>' % (self.__class__.__name__)

    def __eq__(self, other):
        return self.rrsets == other.rrsets

    def __hash__(self):
        return hash(id(self))

    def project(self, *names):
        if set(names).difference(self.rrsets):
            raise ValueError('NSEC name(s) don\'t exist in NSECSet')

        obj = self.__class__((), self.referral, self.ttl_cmp)
        for name in names:
            obj.rrsets[name] = self.rrsets[name]
            rrset = obj.rrsets[name].rrset
            if rrset.rdtype == dns.rdatatype.NSEC3:
                obj.use_nsec3 = True
                key = (rrset[0].salt, rrset[0].algorithm, rrset[0].iterations)
                if key not in obj.nsec3_params:
                    obj.nsec3_params[key] = set()
                obj.nsec3_params[key].add(rrset.name)
                if not obj.is_valid_nsec3_name(rrset.name, rrset[0].algorithm):
                    obj.invalid_nsec3_owner.add(rrset.name)
                if not obj.is_valid_nsec3_hash(rrset[0].next, rrset[0].algorithm):
                    obj.invalid_nsec3_hash.add(rrset.name)

        obj.servers_clients = self.servers_clients.copy()
        return obj

    def add_server_client(self, server, client, response):
        super(NSECSet, self).add_server_client(server, client, response)
        for name, rrset_info in self.rrsets.items():
            rrset_info.add_server_client(server, client, response)

    def create_or_update_rrsig_info(self, name, rrsig, ttl, server, client, response, rdclass, is_referral):
        self.rrsets[name].create_or_update_rrsig_info(rrsig, ttl, server, client, response, rdclass, is_referral)

    def is_valid_nsec3_name(self, nsec_name, algorithm):
        # python3/python2 dual compatibility
        if isinstance(nsec_name[0], str):
            map_func = lambda x: codecs.encode(x.upper(), 'latin1')
        else:
            map_func = lambda x: codecs.encode(chr(x).upper(), 'latin1')

        # check that NSEC3 name is valid
        if algorithm == 1:
            # base32hex encoding of SHA1 should be 32 bytes
            if len(nsec_name[0]) != 32:
                return False
        if [x for x in nsec_name[0] if map_func(x) not in base32.b32alphabet]:
            return False
        return True

    def is_valid_nsec3_hash(self, nsec3_hash, algorithm):
        # check that NSEC3 hash is valid
        if algorithm == 1:
            # length of SHA1 hash should be 20 bytes
            if len(nsec3_hash) != 20:
                return False
        return True

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
                # dnspython <= 1.12.x uses strings, but dnspython 1.13 uses bytearray (for python3)
                byte = bitmap[bitmap_index]
                if isinstance(bitmap, str):
                    byte = ord(byte)
                if window == rdtype_window and byte & (0x80 >> bitmap_offset):
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
            # test that NSEC3 names have the same parent
            try:
                if not (name.parent() == nsec_name.parent() == next_name.parent()):
                    return False
            except dns.name.NoParent:
                return False
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
        for nsec_name in set(self.rrsets).difference(self.invalid_nsec3_owner.union(self.invalid_nsec3_hash)):
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
        for nsec_name in set(self.nsec3_params[(salt, alg, iterations)]).difference(self.invalid_nsec3_owner.union(self.invalid_nsec3_hash)):
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

    def __hash__(self):
        return hash(id(self))

class ReferralResponse(DNSResponseComponent):
    def __init__(self, name):
        super(ReferralResponse, self).__init__()
        self.name = name

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(id(self))

class TruncatedResponse(DNSResponseComponent):
    def __init__(self, wire):
        super(TruncatedResponse, self).__init__()
        self.wire = wire

    def __eq__(self, other):
        return self.wire == other.wire

    def __hash__(self):
        return hash(id(self))
