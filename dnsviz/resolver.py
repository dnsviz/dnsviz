#
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

import io
import random
import time

from . import query
from .ipaddr import IPAddr
from . import transport

import dns.rdataclass, dns.exception, dns.rcode, dns.resolver

MAX_CNAME_REDIRECTION = 20

_r = None
def get_standard_resolver():
    global _r
    if _r is None:
        _r = Resolver.from_file('/etc/resolv.conf', query.StandardRecursiveQuery)
    return _r

_rd = None
def get_dnssec_resolver():
    global _rd
    if _rd is None:
        _rd = Resolver.from_file('/etc/resolv.conf', query.RecursiveDNSSECQuery)
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
        except IOError:
            pass
        return Resolver(servers, query_cls, **kwargs)

    def query(self, qname, rdtype, rdclass=dns.rdataclass.IN, accept_first_response=False, continue_on_servfail=True):
        return self.query_multiple((qname, rdtype, rdclass), accept_first_response=accept_first_response, continue_on_servfail=continue_on_servfail).values()[0]

    def query_for_answer(self, qname, rdtype, rdclass=dns.rdataclass.IN, allow_noanswer=False):
        answer = self.query_multiple_for_answer((qname, rdtype, rdclass), allow_noanswer=allow_noanswer).values()[0]
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

            query.ExecutableDNSQuery.execute_queries(*queries.values(), tm=self._transport_manager, th_factories=self._th_factories)

            for query_tuple, q in queries.items():
                # no response means we didn't even try because we don't have
                # proper connectivity
                if not q.responses:
                    server = list(q.servers)[0]
                    valid_servers[query_tuple].remove(server)
                    if not valid_servers[query_tuple]:
                        last_responses[query_tuple] = server, None
                    continue

                server, client_response = q.responses.items()[0]
                client, response = client_response.items()[0]
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

    print 'Response for %s/%s:' % (args[0], args[1])
    print '   from %s: %s (%d bytes)' % (a.server, repr(a.response), len(a.response.to_wire()))
    print '   answer:\n      %s' % (a.rrset)

if __name__ == '__main__':
    main()
