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

import bisect
import io
import math
import random
import threading
import time

from .config import RESOLV_CONF
from . import query
from .ipaddr import *
from . import response as Response
from . import transport
from . import util

import dns.rdataclass, dns.exception, dns.message, dns.rcode, dns.resolver

MAX_CNAME_REDIRECTION = 20

class ResolvConfError(Exception):
    pass

_r = None
def get_standard_resolver():
    global _r
    if _r is None:
        _r = Resolver.from_file(RESOLV_CONF, query.StandardRecursiveQuery)
    return _r

_rd = None
def get_dnssec_resolver():
    global _rd
    if _rd is None:
        _rd = Resolver.from_file(RESOLV_CONF, query.RecursiveDNSSECQuery)
    return _rd

class DNSAnswer:
    '''An answer to a DNS query, including the full DNS response message, the
    RRset requested, and the server.'''

    def __init__(self, qname, rdtype, response, server):
        self.response = response
        self.server = server

        self.rrset = None

        self._handle_nxdomain(response)

        i = 0
        qname_sought = qname
        while i < MAX_CNAME_REDIRECTION:
            try:
                self.rrset = response.find_rrset(response.answer, qname_sought, dns.rdataclass.IN, rdtype)
                i = MAX_CNAME_REDIRECTION
            except KeyError:
                try:
                    rrset = response.find_rrset(response.answer, qname_sought, dns.rdataclass.IN, dns.rdatatype.CNAME)
                    qname_sought = rrset[0].target
                except KeyError:
                    break
            i += 1

        self._handle_noanswer()

    def _handle_nxdomain(self, response):
        if response.rcode() == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN()

    def _handle_noanswer(self):
        if self.rrset is None:
            raise dns.resolver.NoAnswer()

class DNSAnswerNoAnswerAllowed(DNSAnswer):
    '''An answer to a DNS query, including the full DNS response message, the
    RRset requested, and the server.'''

    def _handle_noanswer(self):
        pass

class Resolver:
    '''A simple stub DNS resolver.'''

    def __init__(self, servers, query_cls, timeout=1.0, max_attempts=5, lifetime=15.0, shuffle=False, client_ipv4=None, client_ipv6=None, port=53, transport_manager=None, th_factories=None):
        if lifetime is None and max_attempts is None:
            raise ValueError("At least one of lifetime or max_attempts must be specified for a Resolver instance.")

        self._servers = servers
        self._query_cls = query_cls
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._lifetime = lifetime
        self._shuffle = shuffle
        self._client_ipv4 = client_ipv4
        self._client_ipv6 = client_ipv6
        self._port = port
        self._transport_manager = transport_manager
        self._th_factories = th_factories

    @classmethod
    def from_file(cls, resolv_conf, query_cls, **kwargs):
        servers = []
        try:
            with io.open(resolv_conf, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    words = line.split()
                    if len(words) > 1 and words[0] == 'nameserver':
                        try:
                            servers.append(IPAddr(words[1]))
                        except ValueError:
                            pass
        except IOError as e:
            raise ResolvConfError('Unable to open %s: %s' % (resolv_conf, str(e)))
        if not servers:
            raise ResolvConfError('No servers found in %s' % (resolv_conf))
        return Resolver(servers, query_cls, **kwargs)

    def query(self, qname, rdtype, rdclass=dns.rdataclass.IN, accept_first_response=False, continue_on_servfail=True):
        return list(self.query_multiple((qname, rdtype, rdclass), accept_first_response=accept_first_response, continue_on_servfail=continue_on_servfail).values())[0]

    def query_for_answer(self, qname, rdtype, rdclass=dns.rdataclass.IN, allow_noanswer=False):
        answer = list(self.query_multiple_for_answer((qname, rdtype, rdclass), allow_noanswer=allow_noanswer).values())[0]
        if isinstance(answer, DNSAnswer):
            return answer
        else:
            raise answer

    def query_multiple_for_answer(self, *query_tuples, **kwargs):
        if kwargs.pop('allow_noanswer', False):
            answer_cls = DNSAnswerNoAnswerAllowed
        else:
            answer_cls = DNSAnswer

        responses = self.query_multiple(*query_tuples, accept_first_response=False, continue_on_servfail=True)

        answers = {}
        for query_tuple, (server, response) in responses.items():
            # no servers were queried
            if response is None:
                answers[query_tuple] = dns.resolver.NoNameservers()
            # response was valid
            elif response.is_complete_response() and response.is_valid_response():
                try:
                    answers[query_tuple] = answer_cls(query_tuple[0], query_tuple[1], response.message, server)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
                    answers[query_tuple] = e
            # response was timeout or network error
            elif response.error in (query.RESPONSE_ERROR_TIMEOUT, query.RESPONSE_ERROR_NETWORK_ERROR):
                answers[query_tuple] = dns.exception.Timeout()
            # there was a response, but it was invalid for some reason
            else:
                answers[query_tuple] = dns.resolver.NoNameservers()

        return answers

    def query_multiple(self, *query_tuples, **kwargs):
        valid_servers = {}
        responses = {}
        last_responses = {}
        attempts = {}

        accept_first_response = kwargs.get('accept_first_response', False)
        continue_on_servfail = kwargs.get('continue_on_servfail', True)

        query_tuples = set(query_tuples)
        for query_tuple in query_tuples:
            attempts[query_tuple] = 0
            valid_servers[query_tuple] = set(self._servers)

        if self._shuffle:
            servers = self._servers[:]
            random.shuffle(servers)
        else:
            servers = self._servers

        tuples_to_query = query_tuples.difference(last_responses)
        start = time.time()
        while tuples_to_query and (self._lifetime is None or time.time() - start < self._lifetime):
            now = time.time()
            queries = {}
            for query_tuple in tuples_to_query:
                if not valid_servers[query_tuple]:
                    try:
                        last_responses[query_tuple] = responses[query_tuple]
                    except KeyError:
                        last_responses[query_tuple] = None, None
                    continue

                while query_tuple not in queries:
                    cycle_num, server_index = divmod(attempts[query_tuple], len(servers))
                    # if we've exceeded our maximum attempts, then break out
                    if cycle_num >= self._max_attempts:
                        try:
                            last_responses[query_tuple] = responses[query_tuple]
                        except KeyError:
                            last_responses[query_tuple] = None, None
                        break

                    server = servers[server_index]
                    if server in valid_servers[query_tuple]:
                        if self._lifetime is not None:
                            timeout = min(self._timeout, max((start + self._lifetime) - now, 0))
                        else:
                            timeout = self._timeout
                        q = self._query_cls(query_tuple[0], query_tuple[1], query_tuple[2], server, None, client_ipv4=self._client_ipv4, client_ipv6=self._client_ipv6, port=self._port, query_timeout=timeout, max_attempts=1)
                        queries[query_tuple] = q

                    attempts[query_tuple] += 1

            query.ExecutableDNSQuery.execute_queries(*list(queries.values()), tm=self._transport_manager, th_factories=self._th_factories)

            for query_tuple, q in queries.items():
                # no response means we didn't even try because we don't have
                # proper connectivity
                if not q.responses:
                    server = list(q.servers)[0]
                    valid_servers[query_tuple].remove(server)
                    if not valid_servers[query_tuple]:
                        last_responses[query_tuple] = server, None
                    continue

                server, client_response = list(q.responses.items())[0]
                client, response = list(client_response.items())[0]
                responses[query_tuple] = (server, response)
                # if we received a complete message with an acceptable rcode,
                # then accept it as the last response
                if response.is_complete_response() and response.is_valid_response():
                    last_responses[query_tuple] = responses[query_tuple]
                # if we received a message that was incomplete (i.e.,
                # truncated), had an invalid rcode, was malformed, or was
                # otherwise invalid, then accept the response (if directed),
                # and invalidate the server
                elif response.message is not None or \
                        response.error not in (query.RESPONSE_ERROR_TIMEOUT, query.RESPONSE_ERROR_NETWORK_ERROR):
                    # accept_first_response is true, then accept the response
                    if accept_first_response:
                        last_responses[query_tuple] = responses[query_tuple]
                    # if the response was SERVFAIL, and we were not directed to
                    # continue, then accept the response
                    elif response.message is not None and \
                            response.message.rcode() == dns.rcode.SERVFAIL and not continue_on_servfail:
                        last_responses[query_tuple] = responses[query_tuple]
                    valid_servers[query_tuple].remove(server)

            tuples_to_query = query_tuples.difference(last_responses)

        for query_tuple in tuples_to_query:
            last_responses[query_tuple] = responses[query_tuple]

        return last_responses

class CacheEntry:
    def __init__(self, rrset, source, expiration, rcode, soa_rrset):
        self.rrset = rrset
        self.source = source
        self.expiration = expiration
        self.rcode = rcode
        self.soa_rrset = soa_rrset

class ServFail(Exception):
    pass

class FullResolver:
    '''A full iterative DNS resolver, following hints.'''

    SRC_PRIMARY_ZONE = 0
    SRC_SECONDARY_ZONE = 1
    SRC_AUTH_ANS = 2
    SRC_AUTH_AUTH = 3
    SRC_GLUE_PRIMARY_ZONE = 4
    SRC_GLUE_SECONDARY_ZONE = 5
    SRC_NONAUTH_ANS = 6
    SRC_ADDITIONAL = 7
    SRC_NONAUTH_AUTH = 7

    MIN_TTL = 60
    MAX_CHAIN = 20

    default_th_factory = transport.DNSQueryTransportHandlerDNSFactory()

    def __init__(self, hints=util.get_root_hints(), query_cls=(query.QuickDNSSECQuery, query.DiagnosticQuery), client_ipv4=None, client_ipv6=None, odd_ports=None, cookie_standin=None, transport_manager=None, th_factories=None, max_ttl=None):

        self._hints = hints
        self._query_cls = query_cls
        self._client_ipv4 = client_ipv4
        self._client_ipv6 = client_ipv6
        if odd_ports is None:
            odd_ports = {}
        self._odd_ports = odd_ports
        self._transport_manager = transport_manager
        if th_factories is None:
            self._th_factories = (self.default_th_factory,)
        else:
            self._th_factories = th_factories
        self.allow_loopback_query = not bool([x for x in self._th_factories if not x.cls.allow_loopback_query])
        self.allow_private_query = not bool([x for x in self._th_factories if not x.cls.allow_private_query])

        self._max_ttl = max_ttl

        self._cookie_standin = cookie_standin
        self._cookie_jar = {}
        self._cache = {}
        self._expirations = []
        self._cache_lock = threading.Lock()

    def _allow_server(self, server):
        if not self.allow_loopback_query and (LOOPBACK_IPV4_RE.search(server) is not None or server == LOOPBACK_IPV6):
            return False
        if not self.allow_private_query and (RFC_1918_RE.search(server) is not None or LINK_LOCAL_RE.search(server) is not None or UNIQ_LOCAL_RE.search(server) is not None):
            return False
        if ZERO_SLASH8_RE.search(server) is not None:
            return False
        return True

    def flush_cache(self):
        with self._cache_lock:
            self._cache = {}
            self._expirations = []

    def expire_cache(self):
        t = time.time()

        with self._cache_lock:
            if self._expirations and self._expirations[0][0] > t:
                return

            future_index = bisect.bisect_right(self._expirations, (t, None))
            for i in range(future_index):
                cache_key = self._expirations[i][1]
                del self._cache[cache_key]
            self._expirations = self._expirations[future_index:]

    def cache_put(self, name, rdtype, rrset, source, rcode, soa_rrset, ttl):
        t = time.time()

        if rrset is not None:
            ttl = max(rrset.ttl, self.MIN_TTL)
        elif soa_rrset is not None:
            ttl = max(min(soa_rrset.ttl, soa_rrset[0].minimum), self.MIN_TTL)
        elif ttl is not None:
            ttl = max(ttl, self.MIN_TTL)
        else:
            ttl = self.MIN_TTL

        if self._max_ttl is not None and ttl > self._max_ttl:
            ttl = self._max_ttl

        expiration = math.ceil(t) + ttl

        key = (name, rdtype)
        new_entry = CacheEntry(rrset, source, expiration, rcode, soa_rrset)

        with self._cache_lock:
            try:
                old_entry = self._cache[key]
            except KeyError:
                pass
            else:
                if new_entry.source >= old_entry.source:
                    return

                # remove the old entry from expirations
                old_index = bisect.bisect_left(self._expirations, (old_entry.expiration, key))
                old_key = self._expirations.pop(old_index)[1]
                assert old_key == key, "Old key doesn't match new key!"

            self._cache[key] = new_entry
            bisect.insort(self._expirations, (expiration, key))

    def cache_get(self, name, rdtype):
        try:
            entry = self._cache[(name, rdtype)]
        except KeyError:
            return None
        else:
            t = time.time()
            ttl = max(0, int(entry.expiration - t))

            if entry.rrset is not None:
                entry.rrset.update_ttl(ttl)
            if entry.soa_rrset is not None:
                entry.soa_rrset.update_ttl(ttl)

            return entry

    def cache_dump(self):
        keys = self._cache.keys()
        keys.sort()

        t = time.time()
        for key in keys:
            entry = self._cache[key]

    def query(self, qname, rdtype, rdclass=dns.rdataclass.IN):
        msg = dns.message.make_response(dns.message.make_query(qname, rdtype), True)
        try:
            l = self._query(qname, rdtype, rdclass, 0, self.SRC_NONAUTH_ANS)
        except ServFail:
            msg.set_rcode(dns.rcode.SERVFAIL)
        else:
            msg.set_rcode(l[-1])
            for rrset in l[:-1]:
                if rrset is not None:
                    new_rrset = msg.find_rrset(msg.answer, rrset.name, rrset.rdclass, rrset.rdtype, create=True)
                    new_rrset.update(rrset)
        return msg, None

    def query_for_answer(self, qname, rdtype, rdclass=dns.rdataclass.IN, allow_noanswer=False):
        response, server = self.query(qname, rdtype, rdclass)
        if response.rcode() == dns.rcode.SERVFAIL:
            raise dns.resolver.NoNameservers()
        if allow_noanswer:
            answer_cls = DNSAnswerNoAnswerAllowed
        else:
            answer_cls = DNSAnswer
        return answer_cls(qname, rdtype, response, server)

    def query_multiple_for_answer(self, *query_tuples, **kwargs):
        allow_noanswer = kwargs.pop('allow_noanswer', False)
        answers = {}
        for query_tuple in query_tuples:
            try:
                answers[query_tuple] = self.query_for_answer(query_tuple[0], query_tuple[1], query_tuple[2], allow_noanswer=allow_noanswer)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
                answers[query_tuple] = e
        return answers

    def query_multiple(self, *query_tuples, **kwargs):
        responses = {}
        for query_tuple in query_tuples:
            responses[query_tuple] = self.query(query_tuple[0], query_tuple[1], query_tuple[2])
        return responses

    def _get_answer(self, qname, rdtype, rdclass, max_source):
        # first check cache for answer
        entry = self.cache_get(qname, rdtype)
        if entry is not None and entry.source <= max_source:
            return [entry.rrset, entry.rcode]

        # check hints, if allowed
        if self.SRC_ADDITIONAL <= max_source and (qname, rdtype) in self._hints:
            return [self._hints[(qname, rdtype)], dns.rcode.NOERROR]

        return None

    def _query(self, qname, rdtype, rdclass, level, max_source, starting_domain=None):
        self.expire_cache()

        # check for max chain length
        if level > self.MAX_CHAIN:
            raise ServFail('SERVFAIL - resolution chain too long')

        ans = self._get_answer(qname, rdtype, rdclass, max_source)
        if ans:
            return ans

        # next check cache for alias
        ans = self._get_answer(qname, dns.rdatatype.CNAME, rdclass, max_source)
        if ans:
            return [ans[0]] + self._query(ans[0][0].target, rdtype, rdclass, level + 1, max_source)

        # now check for closest enclosing NS, DNAME, or hint
        closest_zone = qname

        # when rdtype is DS, start at the parent
        if rdtype == dns.rdatatype.DS and qname != dns.name.root:
            closest_zone = qname.parent()
        elif starting_domain is not None:
            assert qname.is_subdomain(starting_domain), 'qname must be a subdomain of starting_domain'
            closest_zone = starting_domain

        ns_names = {}

        # iterative resolution is necessary, so find the closest zone ancestor or DNAME
        while True:
            # if we are a proper superdomain, then look for DNAME
            if closest_zone != qname:
                entry = self.cache_get(closest_zone, dns.rdatatype.DNAME)
                if entry is not None and entry.rrset is not None:
                    cname_rrset = Response.cname_from_dname(qname, entry.rrset)
                    return [entry.rrset, cname_rrset] + self._query(cname_rrset[0].target, rdtype, rdclass, level + 1, max_source)

            # look for NS records in cache
            ans = self._get_answer(closest_zone, dns.rdatatype.NS, rdclass, self.SRC_ADDITIONAL)
            if ans and ans[0] is not None:
                ns_rrset = ans[0]
                for ns_rdata in ans[0]:
                    addrs = set()
                    for a_rdtype in dns.rdatatype.A, dns.rdatatype.AAAA:
                        ans1 = self._get_answer(ns_rdata.target, a_rdtype, rdclass, self.SRC_ADDITIONAL)
                        if ans1 and ans1[0]:
                            for a_rdata in ans1[0]:
                                addrs.add(IPAddr(a_rdata.address))
                    if addrs:
                        ns_names[ns_rdata.target] = addrs
                    else:
                        ns_names[ns_rdata.target] = None

            # if there were NS records associated with the names, then
            # no need to continue
            if ns_names:
                break

            # otherwise, continue upwards until some are found
            try:
                closest_zone = closest_zone.parent()
            except dns.name.NoParent:
                raise ServFail('SERVFAIL - no NS RRs at root')

        ret = None
        soa_rrset = None
        rcode = None

        # iterate, following referrals down the namespace tree
        while True:
            bailiwick = ns_rrset.name
            is_referral = False

            # query names first for which there are addresses
            ns_names_with_addresses = [n for n in ns_names if ns_names[n] is not None]
            random.shuffle(ns_names_with_addresses)
            ns_names_without_addresses = list(set(ns_names).difference(ns_names_with_addresses))
            random.shuffle(ns_names_without_addresses)
            all_ns_names = ns_names_with_addresses + ns_names_without_addresses
            previous_valid_answer = set()

            for query_cls in self._query_cls:
                # query each server until we get a match
                for ns_name in all_ns_names:
                    is_referral = False
                    if ns_names[ns_name] is None:
                        # first get the addresses associated with each name
                        ns_names[ns_name] = set()
                        for a_rdtype in dns.rdatatype.A, dns.rdatatype.AAAA:
                            if ns_name.is_subdomain(bailiwick):
                                if bailiwick == dns.name.root:
                                    sd = bailiwick
                                else:
                                    sd = bailiwick.parent()
                            else:
                                sd = None
                            try:
                                a_rrset = self._query(ns_name, a_rdtype, dns.rdataclass.IN, level + 1, self.SRC_ADDITIONAL, starting_domain=sd)[-2]
                            except ServFail:
                                a_rrset = None
                            if a_rrset is not None:
                                for rdata in a_rrset:
                                    ns_names[ns_name].add(IPAddr(rdata.address))

                    for server in ns_names[ns_name].difference(previous_valid_answer):
                        # server disallowed by policy
                        if not self._allow_server(server):
                            continue

                        q = query_cls(qname, rdtype, rdclass, (server,), bailiwick, self._client_ipv4, self._client_ipv6, self._odd_ports.get((bailiwick, server), 53), cookie_jar=self._cookie_jar, cookie_standin=self._cookie_standin)
                        q.execute(tm=self._transport_manager, th_factories=self._th_factories)
                        is_referral = False

                        if not q.responses:
                            # No network connectivity
                            continue

                        server1, client_response = list(q.responses.items())[0]
                        client, response = list(client_response.items())[0]

                        server_cookie = response.get_server_cookie()
                        if server_cookie is not None:
                            self._cookie_jar[server1] = server_cookie

                        if not (response.is_valid_response() and response.is_complete_response()):
                            continue

                        previous_valid_answer.add(server)

                        soa_rrset = None
                        rcode = response.message.rcode()

                        # response is acceptable
                        try:
                            # first check for exact match
                            ret = [[x for x in response.message.answer if x.name == qname and x.rdtype == rdtype and x.rdclass == rdclass][0]]
                        except IndexError:
                            try:
                                # now look for DNAME
                                dname_rrset = [x for x in response.message.answer if qname.is_subdomain(x.name) and qname != x.name and x.rdtype == dns.rdatatype.DNAME and x.rdclass == rdclass][0]
                            except IndexError:
                                try:
                                    # now look for CNAME
                                    cname_rrset = [x for x in response.message.answer if x.name == qname and x.rdtype == dns.rdatatype.CNAME and x.rdclass == rdclass][0]
                                except IndexError:
                                    ret = [None]
                                    # no answer
                                    try:
                                        soa_rrset = [x for x in response.message.authority if qname.is_subdomain(x.name) and x.rdtype == dns.rdatatype.SOA][0]
                                    except IndexError:
                                        pass
                                # cache the NS RRset
                                else:
                                    cname_rrset = [x for x in response.message.answer if x.name == qname and x.rdtype == dns.rdatatype.CNAME and x.rdclass == rdclass][0]
                                    ret = [cname_rrset]
                            else:
                                # handle DNAME: return the DNAME, CNAME and (recursively) its chain
                                cname_rrset = Response.cname_from_dname(qname, dname_rrset)
                                ret = [dname_rrset, cname_rrset]

                        if response.is_referral(qname, rdtype, rdclass, bailiwick):
                            is_referral = True
                            a_rrsets = {}
                            min_ttl = None
                            ret = None

                            # if response is referral, then we follow it
                            ns_rrset = [x for x in response.message.authority if qname.is_subdomain(x.name) and x.rdtype == dns.rdatatype.NS][0]
                            ns_names = response.ns_ip_mapping_from_additional(ns_rrset.name, bailiwick)
                            for ns_name in ns_names:
                                if not ns_names[ns_name]:
                                    ns_names[ns_name] = None
                                else: # name is in bailiwick
                                    for a_rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                                        try:
                                            a_rrsets[a_rdtype] = response.message.find_rrset(response.message.additional, ns_name, a_rdtype, dns.rdataclass.IN)
                                        except KeyError:
                                            pass
                                        else:
                                            if min_ttl is None or a_rrsets[a_rdtype].ttl < min_ttl:
                                                min_ttl = a_rrsets[a_rdtype].ttl

                                    for a_rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                                        if a_rdtype in a_rrsets:
                                            a_rrsets[a_rdtype].update_ttl(min_ttl)
                                            self.cache_put(ns_name, a_rdtype, a_rrsets[a_rdtype], self.SRC_ADDITIONAL, dns.rcode.NOERROR, None, None)
                                        else:
                                            self.cache_put(ns_name, a_rdtype, None, self.SRC_ADDITIONAL, dns.rcode.NOERROR, None, min_ttl)

                            if min_ttl is not None:
                                ns_rrset.update_ttl(min_ttl)

                            # cache the NS RRset
                            self.cache_put(ns_rrset.name, dns.rdatatype.NS, ns_rrset, self.SRC_NONAUTH_AUTH, rcode, None, None)
                            break

                        elif response.is_authoritative():
                            terminal = True
                            a_rrsets = {}
                            min_ttl = None

                            # if response is authoritative (and not a referral), then we return it
                            try:
                                ns_rrset = [x for x in  response.message.answer + response.message.authority if qname.is_subdomain(x.name) and x.rdtype == dns.rdatatype.NS][0]
                            except IndexError:
                                pass
                            else:

                                ns_names = response.ns_ip_mapping_from_additional(ns_rrset.name, bailiwick)
                                for ns_name in ns_names:
                                    if not ns_names[ns_name]:
                                        ns_names[ns_name] = None
                                    else: # name is in bailiwick
                                        for a_rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                                            try:
                                                a_rrsets[a_rdtype] = response.message.find_rrset(response.message.additional, ns_name, a_rdtype, dns.rdataclass.IN)
                                            except KeyError:
                                                pass
                                            else:
                                                if min_ttl is None or a_rrsets[a_rdtype].ttl < min_ttl:
                                                    min_ttl = a_rrsets[a_rdtype].ttl

                                        for a_rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                                            if a_rdtype in a_rrsets:
                                                a_rrsets[a_rdtype].update_ttl(min_ttl)
                                                self.cache_put(ns_name, a_rdtype, a_rrsets[a_rdtype], self.SRC_ADDITIONAL, dns.rcode.NOERROR, None, None)
                                            else:
                                                self.cache_put(ns_name, a_rdtype, None, self.SRC_ADDITIONAL, dns.rcode.NOERROR, None, min_ttl)

                                if min_ttl is not None:
                                    ns_rrset.update_ttl(min_ttl)

                                self.cache_put(ns_rrset.name, dns.rdatatype.NS, ns_rrset, self.SRC_AUTH_AUTH, rcode, None, None)

                            if ret[-1] == None:
                                self.cache_put(qname, rdtype, None, self.SRC_AUTH_ANS, rcode, soa_rrset, None)

                            else:
                                for rrset in ret:
                                    self.cache_put(rrset.name, rrset.rdtype, rrset, self.SRC_AUTH_ANS, rcode, None, None)

                                if ret[-1].rdtype == dns.rdatatype.CNAME:
                                    ret += self._query(ret[-1][0].target, rdtype, rdclass, level + 1, self.SRC_NONAUTH_ANS)
                                    terminal = False

                            if terminal:
                                ret.append(rcode)
                            return ret

                    # if referral, then break
                    if is_referral:
                        break

                # if referral, then break
                if is_referral:
                    break

            # if not referral, then we're done iterating
            if not is_referral:
                break

            # if we were only to ask the parent, then we're done
            if starting_domain is not None:
                break

            # otherwise continue onward, looking for an authoritative answer

        # return non-authoritative answer
        if ret is not None:
            terminal = True

            if ret[-1] == None:
                self.cache_put(qname, rdtype, None, self.SRC_NONAUTH_ANS, rcode, soa_rrset, None)

            else:
                for rrset in ret:
                    self.cache_put(rrset.name, rrset.rdtype, rrset, self.SRC_NONAUTH_ANS, rcode, None, None)

                if ret[-1].rdtype == dns.rdatatype.CNAME:
                    ret += self._query(ret[-1][0].target, rdtype, rdclass, level + 1, self.SRC_NONAUTH_ANS)
                    terminal = False

            if terminal:
                ret.append(rcode)
            return ret

        raise ServFail('SERVFAIL - no valid responses')

class PrivateFullResolver(FullResolver):
    default_th_factory = transport.DNSQueryTransportHandlerDNSPrivateFactory()

def main():
    import sys
    import getopt

    def usage():
        sys.stderr.write('Usage: %s <name> <type> [<server>...]\n' % (sys.argv[0]))
        sys.exit(1)

    try:
        opts, args = getopt.getopt(sys.argv[1:], '')
        opts = dict(opts)
    except getopt.error:
        usage()

    if len(args) < 2:
        usage()

    if len(args) < 3:
        r = get_standard_resolver()
    else:
        r = Resolver([IPAddr(x) for x in sys.argv[3:]], query.StandardRecursiveQuery)
    a = r.query_for_answer(dns.name.from_text(args[0]), dns.rdatatype.from_text(args[1]))

    print('Response for %s/%s:' % (args[0], args[1]))
    print('   from %s: %s (%d bytes)' % (a.server, repr(a.response), len(a.response.to_wire())))
    print('   answer:\n      %s' % (a.rrset))

if __name__ == '__main__':
    main()
