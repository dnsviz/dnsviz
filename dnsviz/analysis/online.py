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
# with DNSViz.  If not, see <http://www.gnu.org/licenses/>.
#

import collections
import datetime
import logging
import random
import re
import socket
import sys
import threading
import time
import uuid

import dns.flags, dns.name, dns.rdataclass, dns.rdatatype, dns.resolver

import dnsviz.format as fmt
from dnsviz.ipaddr import IPAddr, IP_SCOPE_GLOBAL, IP_SCOPE_UNIQUE_LOCAL, IP_SCOPE_UNIQUE_LOCAL, IP_SCOPE_RFC_1918, IP_SCOPE_LOOPBACK
import dnsviz.query as Q
import dnsviz.resolver as Resolver

_logger = logging.getLogger(__name__)

DNS_RAW_VERSION = 1.0

class DomainNameAnalysisInterruption(Exception):
    pass

class DependencyAnalysisException(DomainNameAnalysisInterruption):
    pass

class NetworkConnectivityException(Exception):
    pass

class IPv4ConnectivityException(NetworkConnectivityException):
    pass

class IPv6ConnectivityException(NetworkConnectivityException):
    pass

ROOT_NS_IPS = set([
        IPAddr('198.41.0.4'), IPAddr('2001:503:ba3e::2:30'),   # A
        IPAddr('192.228.79.201'),                              # B
        IPAddr('192.33.4.12'),                                 # C
        IPAddr('199.7.91.13'), IPAddr('2001:500:2d::d'),       # D
        IPAddr('192.203.230.10'),                              # E
        IPAddr('192.5.5.241'), IPAddr('2001:500:2f::f'),       # F
        IPAddr('192.112.36.4'),                                # G
        IPAddr('128.63.2.53'), IPAddr('2001:500:1::803f:235'), # H
        IPAddr('192.36.148.17'), IPAddr('2001:7fe::53'),       # I
        IPAddr('192.58.128.30'), IPAddr('2001:503:c27::2:30'), # J
        IPAddr('193.0.14.129'), IPAddr('2001:7fd::1'),         # K
        IPAddr('199.7.83.42'), IPAddr('2001:500:3::42'),       # L
        IPAddr('202.12.27.33'), IPAddr('2001:dc3::35'),        # M
])

ROOT_NS_IPS_6 = set(filter(lambda x: x.version == 6, ROOT_NS_IPS))
ROOT_NS_IPS_4 = ROOT_NS_IPS.difference(ROOT_NS_IPS_6)

ARPA_NAME = dns.name.from_text('arpa')
IP6_ARPA_NAME = dns.name.from_text('ip6', ARPA_NAME)
INADDR_ARPA_NAME = dns.name.from_text('in-addr', ARPA_NAME)
E164_ARPA_NAME = dns.name.from_text('e164', ARPA_NAME)

DANE_PORT_RE = re.compile(r'^_(\d+)$')
SRV_PORT_RE = re.compile(r'^_.*[^\d].*$')
PROTO_LABEL_RE = re.compile(r'^_(tcp|udp|sctp)$')

WILDCARD_EXPLICIT_DELEGATION = dns.name.from_text('*')

ANALYSIS_TYPE_AUTHORITATIVE = 0
ANALYSIS_TYPE_RECURSIVE = 1
ANALYSIS_TYPE_CACHE = 2

analysis_types = {
        ANALYSIS_TYPE_AUTHORITATIVE: 'authoritative',
        ANALYSIS_TYPE_RECURSIVE: 'recursive',
        ANALYSIS_TYPE_CACHE: 'cache',
}
analysis_type_codes = {
        'authoritative': ANALYSIS_TYPE_AUTHORITATIVE,
        'recursive': ANALYSIS_TYPE_RECURSIVE,
        'cache': ANALYSIS_TYPE_CACHE,
}

def _get_client_address(server):
    if server.version == 6:
        af = socket.AF_INET6
    else:
        af = socket.AF_INET
    s = socket.socket(af, socket.SOCK_DGRAM)
    try:
        s.connect((server, 53))
    except socket.error:
        return None
    return IPAddr(s.getsockname()[0])

def get_client_addresses(require_ipv4=False, require_ipv6=False, warn_ipv4=True, warn_ipv6=True, logger=_logger):
    client_ipv4 = _get_client_address(list(ROOT_NS_IPS_4)[0])
    if client_ipv4 is None:
        if require_ipv4:
            raise NetworkConnectivityException('No IPv4 interfaces available for analysis!')
        elif warn_ipv4:
            logger.warning('No IPv4 interfaces available for analysis!')
    client_ipv6 = _get_client_address(list(ROOT_NS_IPS_6)[0])
    if client_ipv6 is None:
        if require_ipv6:
            raise NetworkConnectivityException('No IPv6 interfaces available for analysis!')
        elif warn_ipv6:
            logger.warning('No IPv6 interfaces available for analysis!')
    return client_ipv4, client_ipv6

# create a standard recurisve DNS query with checking disabled
class StandardRecursiveQueryCD(Q.StandardRecursiveQuery):
    response_handlers = Q.StandardRecursiveQuery.response_handlers + [Q.SetFlagOnRcodeHandler(dns.flags.CD, dns.rcode.SERVFAIL)]

resolver = Resolver.Resolver.from_file('/etc/resolv.conf', StandardRecursiveQueryCD)
_root_ipv4_connectivity_checker = Resolver.Resolver(list(ROOT_NS_IPS_4), Q.SimpleDNSQuery, max_attempts=1, shuffle=True)
_root_ipv6_connectivity_checker = Resolver.Resolver(list(ROOT_NS_IPS_6), Q.SimpleDNSQuery, max_attempts=1, shuffle=True)

class AggregateResponseInfo(object):
    def __init__(self, qname, rdtype, name_obj, zone_obj):
        self.qname = qname
        self.rdtype = rdtype
        self.name_obj = name_obj
        self.zone_obj = zone_obj
        self.response_info_list = []

    def __repr__(self):
        return '<%s %s/%s>' % (self.__class__.__name__, self.qname, dns.rdatatype.to_text(self.rdtype))

    def add_response_info(self, response_info, cname_info):
        self.response_info_list.append((response_info, cname_info))

class OnlineDomainNameAnalysis(object):
    QUERY_CLASS = Q.MultiQuery

    def __init__(self, name, stub=False, analysis_type=ANALYSIS_TYPE_AUTHORITATIVE):

        ##################################################
        # General attributes
        ##################################################

        # The name that is the focus of the analysis (serialized).
        self.name = name
        self.analysis_type = analysis_type
        self.stub = stub

        # a class for constructing the queries
        self._query_cls = self.QUERY_CLASS

        # A unique identifier for the analysis
        self.uuid = uuid.uuid4()

        # Analysis start and end (serialized).
        self.analysis_start = None
        self.analysis_end = None

        # The record type queried with the name when eliciting a referral.
        # (serialized).
        self.referral_rdtype = None

        # Whether or not the delegation was specified explicitly or learned
        # by delegation.  This is for informational purposes more than
        # functional purposes.
        self.explicit_delegation = False

        # The queries issued to and corresponding responses received from the
        # servers (serialized).
        self.queries = {}

        # A reference to the analysis of the parent authority (and that of the
        # DLV parent, if any).
        self.parent = None

        self._dlv_parent = None
        self._dlv_name = None

        # A reference to the highest ancestor for which NXDOMAIN was received
        # (serialized).
        self.nxdomain_ancestor = None

        # The clients used for queries (serialized - for convenience)
        self.clients_ipv4 = set()
        self.clients_ipv6 = set()

        # Meta information associated with the domain name.  These are
        # set when responses are processed.
        self.has_soa = False
        self.has_ns = False
        self.cname_targets = {}
        self.ns_dependencies = {}
        self.mx_targets = {}
        self.external_signers = {}

        ##################################################
        # Zone-specific attributes
        ##################################################

        # The DNS names and record types queried to analyze negative responses
        # of different types (serialized).
        self.nxdomain_name = None
        self.nxdomain_rdtype = None
        self.nxrrset_name = None
        self.nxrrset_rdtype = None

        # A mapping of names of authoritative servers to IP addresses returned
        # in authoritative responses (serialized).
        self._auth_ns_ip_mapping = {}

        # These are populated as responses are added.
        self._glue_ip_mapping = {}
        self._ns_names_in_child = set()
        self._all_servers_queried = set()
        self._all_servers_clients_queried = set()
        self._all_servers_clients_queried_tcp = set()
        self._responsive_servers_clients_udp = set()
        self._responsive_servers_clients_tcp = set()
        self._auth_servers_clients = set()
        self._valid_servers_clients = set()

    def __repr__(self):
        return u'<%s %s>' % (self.__class__.__name__, self.__unicode__())

    def __unicode__(self):
        return fmt.humanize_name(self.name, True)

    def __str__(self):
        return fmt.humanize_name(self.name)

    def __eq__(self, other):
        return self.name == other.name

    def parent_name(self):
        if self.parent is not None:
            return self.parent.name
        return None

    def dlv_parent_name(self):
        if self.dlv_parent is not None:
            return self.dlv_parent.name
        return None

    def nxdomain_ancestor_name(self):
        if self.nxdomain_ancestor is not None:
            return self.nxdomain_ancestor.name
        return None

    def _set_dlv_parent(self, dlv_parent):
        self._dlv_parent = dlv_parent
        if dlv_parent is None:
            self._dlv_name = None
        else:
            try:
                self._dlv_name = dns.name.Name(self.name.labels[:-1] + dlv_parent.name.labels)
            except dns.name.NameTooLong:
                self._dlv_parent = None
                self._dlv_name = None

    def _get_dlv_parent(self):
        return self._dlv_parent
    dlv_parent = property(_get_dlv_parent, _set_dlv_parent)

    def _get_dlv_name(self):
        return self._dlv_name
    dlv_name = property(_get_dlv_name)

    def is_zone(self):
        return bool(self.has_ns or self.name == dns.name.root or self._auth_ns_ip_mapping)

    def _get_zone(self):
        if self.is_zone():
            return self
        else:
            return self.parent
    zone = property(_get_zone)

    def single_client(self):
        return len(self.clients_ipv4) <= 1 and len(self.clients_ipv6) <= 1

    def get_name(self, name, trace=None):
        #XXX this whole method is a hack
        if trace is None:
            trace = []

        if self in trace:
            return None

        if name in (self.name, self.nxdomain_name, self.nxrrset_name, self.dlv_name):
            return self
        for cname in self.cname_targets:
            for target, cname_obj in self.cname_targets[cname].items():
                #XXX it is possible for cname_obj to be None where
                # this name was populated with level RDTYPES_SECURE_DELEGATION.
                # when this method is refactored appropriately, this check won't
                # be necessary.
                if cname_obj is None:
                    continue
                ref = cname_obj.get_name(name, trace=trace + [self])
                if ref is not None:
                    return ref
        if name in self.external_signers:
            return self.external_signers[name]
        if name in self.ns_dependencies and self.ns_dependencies[name] is not None:
            return self.ns_dependencies[name]
        if name in self.mx_targets and self.mx_targets[name] is not None:
            return self.mx_targets[name]
        if self.name.is_subdomain(name) and self.parent is not None:
            return self.parent.get_name(name, trace=trace + [self])
        elif name == self.dlv_parent_name():
            return self.dlv_parent
        elif name == self.nxdomain_ancestor_name():
            return self.nxdomain_ancestor
        return None

    def get_bailiwick_mapping(self):
        if not hasattr(self, '_bailiwick_mapping') or self._bailiwick_mapping is None:
            if self.parent is None:
                self._bailiwick_mapping = {}, self.name
            else:
                self._bailiwick_mapping = dict([(s,self.parent_name()) for s in self.parent.get_auth_or_designated_servers()]), self.name
        return self._bailiwick_mapping

    def _add_glue_ip_mapping(self, response):
        '''Extract a mapping of NS targets to IP addresses from A and AAAA
        records in the additional section of a referral.'''

        ip_mapping = response.ns_ip_mapping_from_additional(self.name, self.parent_name())
        for name, ip_set in ip_mapping.items():
            if name not in self._glue_ip_mapping:
                self._glue_ip_mapping[name] =  set()
            self._glue_ip_mapping[name].update(ip_set)

            # this includes both out-of-bailiwick names (because
            # ns_ip_mapping_from_additional() is called with
            # self.parent_name()) and those that have no IPs
            # in the additional section.
            if not ip_set:
                self.ns_dependencies[name] = None

    def _handle_mx_response(self, rrset):
        '''Save the targets from an MX RRset with the name which is the
        subject of this analysis.'''

        for mx in rrset:
            self.mx_targets[mx.exchange] = None

    def _handle_cname_response(self, rrset):
        '''Save the targets from a CNAME RRset with the name which is the
        subject of this analysis.'''

        if rrset.name not in self.cname_targets:
            self.cname_targets[rrset.name] = {}
        self.cname_targets[rrset.name][rrset[0].target] = None

    def _handle_ns_response(self, rrset, update_ns_names):
        '''Indicate that there exist NS records for the name which is the
        subject of this analysis, and, if authoritative, save the NS
        targets.'''

        self.has_ns = True
        if update_ns_names:
            for ns in rrset:
                self._ns_names_in_child.add(ns.target)

    def set_ns_dependencies(self):
        # the following check includes explicit delegations
        if self.parent is None:
            return
        for ns in self.get_ns_names_in_child().difference(self.get_ns_names_in_parent()):
            self.ns_dependencies[ns] = None

    def _process_response_answer_rrset(self, rrset, query, response):
        if query.qname in (self.name, self.dlv_name):
            if rrset.rdtype == dns.rdatatype.MX:
                self._handle_mx_response(rrset)
            elif rrset.rdtype == dns.rdatatype.NS:
                self._handle_ns_response(rrset, not self.explicit_delegation)

            # check whether it is signed and whether the signer matches
            try:
                rrsig_rrset = response.message.find_rrset(response.message.answer, query.qname, query.rdclass, dns.rdatatype.RRSIG, rrset.rdtype)

                for rrsig in rrsig_rrset:
                    if rrsig_rrset.covers == dns.rdatatype.DS and self.parent is None:
                        pass
                    elif rrsig_rrset.covers == dns.rdatatype.DS and rrsig.signer == self.parent_name():
                        pass
                    elif rrsig_rrset.covers == dns.rdatatype.DLV and rrsig.signer == self.dlv_parent_name():
                        pass
                    elif rrsig.signer == self.zone.name:
                        pass
                    else:
                        self.external_signers[rrsig.signer] = None
            except KeyError:
                pass

        if rrset.rdtype == dns.rdatatype.CNAME:
            self._handle_cname_response(rrset)

    def _process_response(self, response, server, client, query, bailiwick, detect_ns):
        '''Process a DNS response from a query, setting and updating instance
        variables appropriately, and calling helper methods as necessary.'''

        if response.message is None:
            return

        is_authoritative = response.is_authoritative()

        if response.is_valid_response():
            self._valid_servers_clients.add((server, client))
        if is_authoritative:
            if query.rdtype not in (dns.rdatatype.DS, dns.rdatatype.DLV):
                self._auth_servers_clients.add((server, client))

        if not response.is_complete_response():
            return

        # retrieve the corresponding RRset in the answer section
        rrset = None
        try:
            rrset = response.message.find_rrset(response.message.answer, query.qname, query.rdclass, query.rdtype)
        except KeyError:
            try:
                rrset = response.message.find_rrset(response.message.answer, query.qname, query.rdclass, dns.rdatatype.CNAME)
            except KeyError:
                pass

        # in the case where a corresponding RRset is found, analyze it here
        if rrset is not None:
            self._process_response_answer_rrset(rrset, query, response)

        # look for SOA in authority section, in the case of negative responses
        try:
            soa_rrset = filter(lambda x: x.rdtype == dns.rdatatype.SOA, response.message.authority)[0]
            if soa_rrset.name == self.name:
                self.has_soa = True
        except IndexError:
            pass

        if query.qname == self.name and detect_ns:
            # if this is a referral, also grab the referral information, if it
            # pertains to this name (could alternatively be a parent)
            if response.is_referral(query.qname, query.rdtype, bailiwick):
                try:
                    rrset = response.message.find_rrset(response.message.authority, self.name, dns.rdataclass.IN, dns.rdatatype.NS)
                except KeyError:
                    pass
                else:
                    self._add_glue_ip_mapping(response)
                    self._handle_ns_response(rrset, False)

            # if it is an (authoritative) answer that has authority information, then add it
            else:
                try:
                    rrset = response.message.find_rrset(response.message.authority, query.qname, dns.rdataclass.IN, dns.rdatatype.NS)
                    self._handle_ns_response(rrset, is_authoritative and not self.explicit_delegation)
                except KeyError:
                    pass

    def add_auth_ns_ip_mappings(self, *mappings):
        '''Add one or more mappings from NS targets to IPv4 or IPv6 addresses,
        as resolved by querying authoritative sources.  Arguments are 2-tuples
        of the form (DNS name, address).'''

        for name, ip in mappings:
            if name not in self._auth_ns_ip_mapping:
                self._auth_ns_ip_mapping[name] = set()
            if ip is not None:
                self._auth_ns_ip_mapping[name].add(ip)

    def add_query(self, query, detect_ns=False):
        '''Process a DNS query and its responses, setting and updating instance
        variables appropriately, and calling helper methods as necessary.'''


        bailiwick_map, default_bailiwick = self.get_bailiwick_mapping()

        key = (query.qname, query.rdtype)
        if key not in self.queries:
            self.queries[key] = self._query_cls(query.qname, query.rdtype, query.rdclass)
        self.queries[key].add_query(query, bailiwick_map, default_bailiwick)

        for server in query.responses:
            bailiwick = bailiwick_map.get(server, default_bailiwick)

            # note the fact that servers were queried
            self._all_servers_queried.add(server)

            for client in query.responses[server]:
                response = query.responses[server][client]

                # note clients used
                if client.version == 6:
                    self.clients_ipv6.add(client)
                else:
                    self.clients_ipv4.add(client)

                # note server responsiveness
                if response.udp_attempted:
                    self._all_servers_clients_queried.add((server, client))
                if response.tcp_attempted:
                    self._all_servers_clients_queried_tcp.add((server, client))
                if response.udp_responsive:
                    self._responsive_servers_clients_udp.add((server, client))
                if response.tcp_responsive:
                    self._responsive_servers_clients_tcp.add((server, client))

                self._process_response(query.responses[server][client], server, client, query, bailiwick, detect_ns)

    def get_glue_ip_mapping(self):
        '''Return a reference to the mapping of targets of delegation records
        (i.e., NS records in the parent zone) and their corresponding IPv4 or
        IPv6 glue, if any.'''

        return self._glue_ip_mapping

    def get_auth_ns_ip_mapping(self):
        '''Return a reference to the mapping of NS targets from delegation or
        authoritative source to their authoritative IPv4 and IPv6 addresses.'''

        return self._auth_ns_ip_mapping

    def get_ns_names_in_parent(self):
        '''Return the set of names corresponding to targets of delegation
        records.'''

        return set(self.get_glue_ip_mapping())

    def get_ns_names_in_child(self):
        '''Return the set of names corresponding to targets of authoritative
        NS records.'''

        return self._ns_names_in_child

    def get_ns_names(self):
        '''Return the comprehensive set of names corresponding to NS targets.'''

        return self.get_ns_names_in_parent().union(self.get_ns_names_in_child())

    def get_servers_in_parent(self):
        '''Return the IP addresses of servers corresponding to names in the
        delegation records.  If the name is a subset of the name being queried,
        then glue is required, and the glue is used exclusively.  If the name
        is in-bailiwick and there is glue in the referral, then the glue
        records alone are used; otherwise the authoritative IPs are used.  If
        the name is out-of-bailiwick, then only the authoritative IPs are
        used.'''

        if not hasattr(self, '_servers_in_parent') or self._servers_in_parent is None:
            servers = set()
            if self.parent is None:
                return servers
            glue_ips = self.get_glue_ip_mapping()
            auth_ips = self.get_auth_ns_ip_mapping()
            for name in glue_ips:
                in_bailiwick = name.is_subdomain(self.parent_name())
                glue_required = name.is_subdomain(self.name)
                if glue_required:
                    servers.update(glue_ips[name])
                elif in_bailiwick:
                    if glue_ips[name]:
                        servers.update(glue_ips[name])
                    elif name in auth_ips:
                        servers.update(auth_ips[name])
                elif name in auth_ips:
                    servers.update(auth_ips[name])
            self._servers_in_parent = servers
        return self._servers_in_parent

    def get_servers_in_child(self):
        '''Return the authoritative IP addresses of servers corresponding to
        names in the authoritative NS records.'''

        if not hasattr(self, '_servers_in_child') or self._servers_in_child is None:
            servers = set()
            auth_ips = self.get_auth_ns_ip_mapping()
            for name in self.get_ns_names_in_child():
                if name in auth_ips:
                    servers.update(auth_ips[name])
            self._servers_in_child = servers
        return self._servers_in_child

    def get_designated_servers(self, no_cache=False):
        '''Return the set of glue or authoritative IP addresses of servers
        corresponding to names in the delegation or authoritative NS
        records.'''

        if not hasattr(self, '_designated_servers') or self._designated_servers is None:
            servers = set()
            glue_ips = self.get_glue_ip_mapping()
            auth_ips = self.get_auth_ns_ip_mapping()
            for name in glue_ips:
                servers.update(glue_ips[name])
            for name in auth_ips:
                servers.update(auth_ips[name])
            if no_cache:
                return servers
            self._designated_servers = servers
        return self._designated_servers

    def get_valid_servers(self, proto=None):
        '''Return the set of servers that responded with a valid (rcode of
        NOERROR or NXDOMAIN) response.'''

        valid_servers = set([x[0] for x in self._valid_servers_clients])
        if proto is not None:
            return set(filter(lambda x: x.version == proto, valid_servers))
        else:
            return valid_servers

    def get_responsive_servers_udp(self, proto=None):
        '''Return the set of servers for which some type of response was
        received from any client over UDP.'''

        responsive_servers = set([x[0] for x in self._responsive_servers_clients_udp])
        if proto is not None:
            return set(filter(lambda x: x.version == proto, responsive_servers))
        else:
            return responsive_servers

    def get_responsive_servers_tcp(self, proto=None):
        '''Return the set of servers for which some type of response was
        received from any client over TCP.'''

        responsive_servers = set([x[0] for x in self._responsive_servers_clients_tcp])
        if proto is not None:
            return set(filter(lambda x: x.version == proto, responsive_servers))
        else:
            return responsive_servers

    def get_auth_or_designated_servers(self, proto=None, no_cache=False):
        '''Return the set of servers that either answered authoritatively
        or were explicitly designated by NS and glue or authoritative IP.'''

        if not hasattr(self, '_auth_or_designated_servers') or self._auth_or_designated_servers is None:
            servers = set([x[0] for x in self._auth_servers_clients]).union(self.get_designated_servers(no_cache))
            if not no_cache:
                self._auth_or_designated_servers = servers
        else:
            servers = self._auth_or_designated_servers

        if proto is not None:
            return set(filter(lambda x: x.version == proto, servers))
        else:
            return servers

    def get_responsive_auth_or_designated_servers(self, proto=None, no_cache=False):
        '''Return the set of servers that either answered authoritatively
        or were explicitly designated by NS and glue or authoritative IP and
        were responsive to queries.'''

        return self.get_auth_or_designated_servers(proto, no_cache).intersection(self.get_responsive_servers_udp(proto))

    def get_valid_auth_or_designated_servers(self, proto=None, no_cache=False):
        '''Return the set of servers that either answered authoritatively
        or were explicitly designated by NS and glue or authoritative IP and
        returned a valid (rcode of NOERROR or NXDOMAIN) response.'''

        return self.get_auth_or_designated_servers(proto, no_cache).intersection(self.get_valid_servers(proto))

    def get_stealth_servers(self):
        '''Return the set of servers that authoritatively but weren't
        explicitly designated by NS and glue or authoritative IP.'''

        if not hasattr(self, '_stealth_auth_servers') or self._stealth_auth_servers is None:
            servers = self.get_auth_or_designated_servers().difference(self.get_designated_servers())
            self._stealth_auth_servers = servers
        return self._stealth_auth_servers

    def get_ip_ns_name_mapping(self):
        '''Return a mapping of each designated server to the NS target name
        that it resolves to.  The result for each IP is a list of names in
        which names that resolve to it authoritatively appear before names
        that map to it in glue.'''

        if not hasattr(self, '_ip_ns_name_mapping') or self._ip_ns_name_mapping is None:
            self._ip_ns_name_mapping = {}
            glue_ips = self.get_glue_ip_mapping()
            auth_ips = self.get_auth_ns_ip_mapping()
            if self.stub:
                auth_names = set(auth_ips)
            else:
                auth_names = self.get_ns_names()

            # if there are no names from glue or from authoritative responses,
            # then use the authoritative IP.  Such is the case with explicit
            # delegation
            if not auth_names:
                auth_names = auth_ips

            for name in auth_names:
                if name in auth_ips:
                    for ip in auth_ips[name]:
                        if ip not in self._ip_ns_name_mapping:
                            self._ip_ns_name_mapping[ip] = []
                        self._ip_ns_name_mapping[ip].append(name)

            for name in glue_ips:
                for ip in glue_ips[name]:
                    if ip not in self._ip_ns_name_mapping:
                        self._ip_ns_name_mapping[ip] = [name]
                    elif name not in self._ip_ns_name_mapping[ip]:
                        self._ip_ns_name_mapping[ip].append(name)

        return self._ip_ns_name_mapping

    def get_ns_name_for_ip(self, ip):
        '''Return the NS target name(s) that resolve to the given IP, either
        authoritatively or using glue.'''

        ip_name_mapping = self.get_ip_ns_name_mapping()
        try:
            return ip_name_mapping[ip], self.name
        except KeyError:
            pass

        if self.parent is None:
            return [], None
        return self.parent.get_ns_name_for_ip(ip)

    def _create_response_info_recursive(self, name, rdtype, name_to_info_mapping, rrset_to_cname_mapping):
        zone_obj = self.get_name(name).zone
        info_obj = AggregateResponseInfo(name, rdtype, self, zone_obj)
        for info in name_to_info_mapping[name]:
            if info in rrset_to_cname_mapping:
                cname_info = self._create_response_info_recursive(rrset_to_cname_mapping[info], rdtype, name_to_info_mapping, rrset_to_cname_mapping)
            else:
                cname_info = None
            info_obj.add_response_info(info, cname_info)
        return info_obj

    def _get_response_info(self, name, rdtype):
        query = self.queries[(name, rdtype)]
        name_to_info_mapping = {}
        rrset_to_cname_mapping = {}

        for rrset_info in query.answer_info:

            # only do qname, unless analysis type is recursive
            if not (rrset_info.rrset.name == name or self.analysis_type == ANALYSIS_TYPE_RECURSIVE):
                continue

            # if this is a CNAME record, create an info-to-target mapping
            if rrset_info.rrset.rdtype == dns.rdatatype.CNAME:
                rrset_to_cname_mapping[rrset_info] = rrset_info.rrset[0].target

            # map name to info and name_obj
            if rrset_info.rrset.name not in name_to_info_mapping:
                name_to_info_mapping[rrset_info.rrset.name] = []
            name_to_info_mapping[rrset_info.rrset.name].append(rrset_info)

        for neg_response_info in query.nxdomain_info + query.nodata_info:
            # only do qname, unless analysis type is recursive
            if not (neg_response_info.qname == name or self.analysis_type == ANALYSIS_TYPE_RECURSIVE):
                continue

            if neg_response_info.qname not in name_to_info_mapping:
                name_to_info_mapping[neg_response_info.qname] = []
            name_to_info_mapping[neg_response_info.qname].append(neg_response_info)

        for error in self.response_errors[query]:
            if name not in name_to_info_mapping:
                name_to_info_mapping[name] = []
            name_to_info_mapping[name].append(error)

        info_obj = AggregateResponseInfo(name, rdtype, self, self.zone)
        for info in name_to_info_mapping[name]:
            if info in rrset_to_cname_mapping:
                if self.analysis_type == ANALYSIS_TYPE_RECURSIVE:
                    cname_info = self._create_response_info_recursive(rrset_to_cname_mapping[info], rdtype, name_to_info_mapping, rrset_to_cname_mapping)
                else:
                    cname_obj = self.get_name(rrset_to_cname_mapping[info])
                    cname_info = cname_obj.get_response_info(rrset_to_cname_mapping[info], rdtype)
            else:
                cname_info = None
            info_obj.add_response_info(info, cname_info)

        return info_obj

    def get_response_info(self, name, rdtype):
        if not hasattr(self, '_response_info') or self._response_info is None:
            self._response_info = {}
        if (name, rdtype) not in self._response_info:
            self._response_info[(name, rdtype)] = self._get_response_info(name, rdtype)
        return self._response_info[(name, rdtype)]

    def serialize(self, d=None, meta_only=False, trace=None):
        if d is None:
            d = collections.OrderedDict()

        if trace is None:
            trace = []

        if self in trace:
            return

        name_str = self.name.canonicalize().to_text()
        if name_str in d:
            return

        # serialize dependencies first because their version of the analysis
        # might be the most complete (considering re-dos)
        self._serialize_dependencies(d, meta_only, trace)

        if self.parent is not None:
            self.parent.serialize(d, meta_only, trace + [self])
        if self.dlv_parent is not None:
            self.dlv_parent.serialize(d, meta_only, trace + [self])
        if self.nxdomain_ancestor is not None:
            self.nxdomain_ancestor.serialize(d, meta_only, trace + [self])

        clients_ipv4 = list(self.clients_ipv4)
        clients_ipv4.sort()
        clients_ipv6 = list(self.clients_ipv6)
        clients_ipv6.sort()

        d[name_str] = collections.OrderedDict()
        d[name_str]['type'] = analysis_types[self.analysis_type]
        d[name_str]['stub'] = self.stub
        d[name_str]['analysis_start'] = fmt.datetime_to_str(self.analysis_start)
        d[name_str]['analysis_end'] = fmt.datetime_to_str(self.analysis_end)
        if not self.stub:
            d[name_str]['clients_ipv4'] = clients_ipv4
            d[name_str]['clients_ipv6'] = clients_ipv6

            if self.parent is not None:
                d[name_str]['parent'] = self.parent_name().canonicalize().to_text()
            if self.dlv_parent is not None:
                d[name_str]['dlv_parent'] = self.dlv_parent_name().canonicalize().to_text()
            if self.nxdomain_ancestor is not None:
                d[name_str]['nxdomain_ancestor'] = self.nxdomain_ancestor_name().canonicalize().to_text()
            if self.referral_rdtype is not None:
                d[name_str]['referral_rdtype'] = dns.rdatatype.to_text(self.referral_rdtype)
            d[name_str]['explicit_delegation'] = self.explicit_delegation
            if self.nxdomain_name is not None:
                d[name_str]['nxdomain_name'] = self.nxdomain_name.to_text()
                d[name_str]['nxdomain_rdtype'] = dns.rdatatype.to_text(self.nxdomain_rdtype)
            if self.nxrrset_name is not None:
                d[name_str]['nxrrset_name'] = self.nxrrset_name.to_text()
                d[name_str]['nxrrset_rdtype'] = dns.rdatatype.to_text(self.nxrrset_rdtype)

        self._serialize_related(d[name_str], meta_only)

    def _serialize_related(self, d, meta_only):
        if self._auth_ns_ip_mapping:
            d['auth_ns_ip_mapping'] = collections.OrderedDict()
            ns_names = self._auth_ns_ip_mapping.keys()
            ns_names.sort()
            for name in ns_names:
                addrs = list(self._auth_ns_ip_mapping[name])
                addrs.sort()
                d['auth_ns_ip_mapping'][name.canonicalize().to_text()] = addrs

        if self.stub:
            return

        d['queries'] = []
        query_keys = self.queries.keys()
        query_keys.sort()
        for (qname, rdtype) in query_keys:
            for query in self.queries[(qname, rdtype)].queries.values():
                d['queries'].append(query.serialize(meta_only))

    def _serialize_dependencies(self, d, meta_only, trace):
        if self.stub:
            return

        for cname in self.cname_targets:
            for target, cname_obj in self.cname_targets[cname].items():
                if cname_obj is not None:
                    cname_obj.serialize(d, meta_only, trace=trace + [self])
        for signer, signer_obj in self.external_signers.items():
            if signer_obj is not None:
                signer_obj.serialize(d, meta_only, trace=trace + [self])
        for target, ns_obj in self.ns_dependencies.items():
            if ns_obj is not None:
                ns_obj.serialize(d, meta_only, trace=trace + [self])
        for target, mx_obj in self.mx_targets.items():
            if mx_obj is not None:
                mx_obj.serialize(d, meta_only, trace=trace + [self])

    @classmethod
    def deserialize(cls, name, d1, cache=None):
        if cache is None:
            cache = {}

        if name in cache:
            return cache[name]

        name_str = name.canonicalize().to_text()
        d = d1[name_str]

        # use a default analysis type to support previous version
        analysis_type = analysis_type_codes[d.get('type', 'authoritative')]
        stub = d['stub']

        if 'parent' in d:
            parent_name = dns.name.from_text(d['parent'])
            parent = cls.deserialize(parent_name, d1, cache=cache)
        else:
            parent = None

        if name != dns.name.root and 'dlv_parent' in d:
            dlv_parent_name = dns.name.from_text(d['dlv_parent'])
            dlv_parent = cls.deserialize(dlv_parent_name, d1, cache=cache)
        else:
            dlv_parent_name = None
            dlv_parent = None

        if 'nxdomain_ancestor' in d:
            nxdomain_ancestor_name = dns.name.from_text(d['nxdomain_ancestor'])
            nxdomain_ancestor = cls.deserialize(nxdomain_ancestor_name, d1, cache=cache)
        else:
            nxdomain_ancestor_name = None
            nxdomain_ancestor = None

        _logger.info('Loading %s' % fmt.humanize_name(name))

        cache[name] = a = cls(name, stub=stub, analysis_type=analysis_type)
        a.parent = parent
        if dlv_parent is not None:
            a.dlv_parent = dlv_parent
        if nxdomain_ancestor is not None:
            a.nxdomain_ancestor = nxdomain_ancestor
        a.analysis_start = fmt.str_to_datetime(d['analysis_start'])
        a.analysis_end = fmt.str_to_datetime(d['analysis_end'])

        if not a.stub:
            if 'referral_rdtype' in d:
                a.referral_rdtype = dns.rdatatype.from_text(d['referral_rdtype'])
            a.explicit_delegation = d['explicit_delegation']
            if 'nxdomain_name' in d:
                a.nxdomain_name = dns.name.from_text(d['nxdomain_name'])
                a.nxdomain_rdtype = dns.rdatatype.from_text(d['nxdomain_rdtype'])
            if 'nxrrset_name' in d:
                a.nxrrset_name = dns.name.from_text(d['nxrrset_name'])
                a.nxrrset_rdtype = dns.rdatatype.from_text(d['nxrrset_rdtype'])

        a._deserialize_related(d)
        a._deserialize_dependencies(d1, cache)
        return a

    def _deserialize_related(self, d):
        if 'auth_ns_ip_mapping' in d:
            for target in d['auth_ns_ip_mapping']:
                for addr in d['auth_ns_ip_mapping'][target]:
                    self.add_auth_ns_ip_mappings((dns.name.from_text(target), IPAddr(addr)))

        if self.stub:
            return

        bailiwick_map, default_bailiwick = self.get_bailiwick_mapping()

        query_map = {}
        #XXX backwards compatibility with previous version
        if isinstance(d['queries'], list):
            for query in d['queries']:
                key = (dns.name.from_text(query['qname']), dns.rdatatype.from_text(query['qtype']), dns.rdataclass.from_text(query['qclass']))
                if key not in query_map:
                    query_map[key] = []
                query_map[key].append(query)
        else:
            for query_str in d['queries']:
                vals = query_str.split('/')
                qname = dns.name.from_text('/'.join(vals[:-2]))
                rdtype = dns.rdatatype.from_text(vals[-1])
                rdclass = dns.rdataclass.from_text(vals[-2])
                key = (qname, rdtype, rdclass)
                query_map[key] = []
                for query in d['queries'][query_str]:
                    query_map[key].append(query)

        # import delegation NS queries first
        delegation_types = set([dns.rdatatype.NS])
        if self.referral_rdtype is not None:
            delegation_types.add(self.referral_rdtype)
        for rdtype in delegation_types:
            # if the query has already been imported, then
            # don't re-import
            if (self.name, rdtype) in self.queries:
                continue
            key = (self.name, rdtype, dns.rdataclass.IN)
            if key in query_map:
                _logger.debug('Importing %s/%s...' % (fmt.humanize_name(self.name), dns.rdatatype.to_text(rdtype)))
                for query in query_map[key]:
                    self.add_query(Q.DNSQuery.deserialize(query, bailiwick_map, default_bailiwick), True)
        # set the NS dependencies for the name
        if self.is_zone():
            self.set_ns_dependencies()

        for key in query_map:
            qname, rdtype, rdclass = key
            # if the query has already been imported, then
            # don't re-import
            if (qname, rdtype) in self.queries:
                continue
            if rdtype in delegation_types:
                continue
            if (qname, rdtype) == (self.nxdomain_name, self.nxdomain_rdtype):
                extra = ' (NXDOMAIN)'
            elif (qname, rdtype) == (self.nxrrset_name, self.nxrrset_rdtype):
                extra = ' (No data)'
            else:
                extra = ''
            _logger.debug('Importing %s/%s%s...' % (fmt.humanize_name(qname), dns.rdatatype.to_text(rdtype), extra))
            for query in query_map[key]:
                self.add_query(Q.DNSQuery.deserialize(query, bailiwick_map, default_bailiwick))

    def _deserialize_dependencies(self, d, cache):
        if self.stub:
            return

        for cname in self.cname_targets:
            for target in self.cname_targets[cname]:
                self.cname_targets[cname][target] = self.__class__.deserialize(target, d, cache=cache)
        for signer in self.external_signers:
            self.external_signers[signer] = self.__class__.deserialize(signer, d, cache=cache)

        # these two are optional
        for target in self.ns_dependencies:
            if target.canonicalize().to_text() in d:
                self.ns_dependencies[target] = self.__class__.deserialize(target, d, cache=cache)
        for target in self.mx_targets:
            if target.canonicalize().to_text() in d:
                self.mx_targets[target] = self.__class__.deserialize(target, d, cache=cache)

class ActiveDomainNameAnalysis(OnlineDomainNameAnalysis):
    def __init__(self, *args, **kwargs):
        super(ActiveDomainNameAnalysis, self).__init__(*args, **kwargs)
        self.complete = threading.Event()

class Analyst(object):
    analysis_model = ActiveDomainNameAnalysis
    diagnostic_query = Q.DiagnosticQuery
    tcp_diagnostic_query = Q.TCPDiagnosticQuery
    pmtu_diagnostic_query = Q.PMTUDiagnosticQuery
    truncation_diagnostic_query = Q.TruncationDiagnosticQuery
    edns_version_diagnostic_query = Q.EDNSVersionDiagnosticQuery
    edns_flag_diagnostic_query = Q.EDNSFlagDiagnosticQuery
    edns_opt_diagnostic_query = Q.EDNSOptDiagnosticQuery

    allow_loopback_query = False
    allow_private_query = False
    qname_only = True
    analysis_type = ANALYSIS_TYPE_AUTHORITATIVE

    clone_attrnames = ['dlv_domain', 'client_ipv4', 'client_ipv6', 'logger', 'ceiling', 'edns_diagnostics', 'follow_ns', 'explicit_delegations', 'explicit_only', 'analysis_cache', 'cache_level', 'analysis_cache_lock']

    def __init__(self, name, dlv_domain=None, client_ipv4=None, client_ipv6=None, logger=_logger, ceiling=None, edns_diagnostics=False,
             follow_ns=False, follow_mx=False, trace=None, explicit_delegations=None, extra_rdtypes=None, explicit_only=False, analysis_cache=None, cache_level=None, analysis_cache_lock=None):

        self.name = name
        self.dlv_domain = dlv_domain
        self.ceiling = self._detect_ceiling(ceiling)[0]

        if client_ipv4 is None and client_ipv6 is None:
            client_ipv4, client_ipv6 = get_client_addresses(logger=logger)
        if client_ipv4 is None and client_ipv6 is None:
            raise NetworkConnectivityException('No network interfaces available for analysis!')
        self.client_ipv4 = client_ipv4
        self.client_ipv6 = client_ipv6

        self.logger = logger

        self.edns_diagnostics = edns_diagnostics

        self.follow_ns = follow_ns
        self.follow_mx = follow_mx

        if trace is None:
            self.trace = []
        else:
            self.trace = trace

        assert not explicit_only or extra_rdtypes is not None or self._force_dnskey_query(name), 'If explicit_only is specified, then extra_rdtypes must be specified or force_dnskey must be true.'

        if explicit_delegations is None:
            self.explicit_delegations = {}
        else:
            self.explicit_delegations = explicit_delegations
        self.extra_rdtypes = extra_rdtypes
        self.explicit_only = explicit_only
        if analysis_cache is None:
            self.analysis_cache = {}
        else:
            self.analysis_cache = analysis_cache
        self.cache_level = cache_level
        if analysis_cache_lock is None:
            self.analysis_cache_lock = threading.Lock()
        else:
            self.analysis_cache_lock = analysis_cache_lock

        self._detect_cname_chain()

    def _detect_cname_chain(self):
        self._cname_chain = []

        if self.dlv_domain == self.name:
            return

        if len(self.name) < 3:
            return

        try:
            rdtype = self._rdtypes_to_query(self.name)[0]
        except IndexError:
            rdtype = dns.rdatatype.A

        try:
            ans = resolver.query_for_answer(self.name, rdtype, dns.rdataclass.IN, allow_noanswer=True)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return

        cname = self.name
        for i in range(Resolver.MAX_CNAME_REDIRECTION):
            try:
                cname = ans.response.find_rrset(ans.response.answer, cname, dns.rdataclass.IN, dns.rdatatype.CNAME)[0].target
                self._cname_chain.append(cname)
            except KeyError:
                return

    def _detect_ceiling(self, ceiling):
        if ceiling == dns.name.root or ceiling is None:
            return ceiling, None

        # if there is a ceiling, but the name is not a subdomain
        # of the ceiling, then use the name itself as a base
        if not self.name.is_subdomain(ceiling):
            ceiling = self.name

        try:
            ans = resolver.query_for_answer(ceiling, dns.rdatatype.NS, dns.rdataclass.IN)
            try:
                ans.response.find_rrset(ans.response.answer, ceiling, dns.rdataclass.IN, dns.rdatatype.NS)
                return ceiling, False
            except KeyError:
                pass
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException:
            parent_ceiling, fail = self._detect_ceiling(ceiling.parent())
            if fail:
                return parent_ceiling, True
            else:
                return ceiling, True
        return self._detect_ceiling(ceiling.parent())

    def _is_referral_of_type(self, rdtype):
        '''Return True if analysis of this name was invoked as a dependency (specified by
        rdtype) for another name; False otherwise.  Examples are CNAME, NS, MX.'''

        try:
            return self.trace[-1][1] == rdtype
        except IndexError:
            return False

    def _original_alias_of_cname(self):
        name = self.name
        for i in range(len(self.trace) - 1, -1, -1):
            if self.trace[i][1] != dns.rdatatype.CNAME:
                return name
            name = self.trace[i][0].name
        return name

    def _force_dnskey_query(self, name):
        return name == self.name and self._is_referral_of_type(dns.rdatatype.RRSIG)

    def _rdtypes_to_query(self, name):
        orig_name = self._original_alias_of_cname()

        rdtypes = []
        if self.explicit_only:
            if self.name == name:
                if self.extra_rdtypes is not None:
                    rdtypes.extend(self.extra_rdtypes)
            else:
                if name in self._cname_chain:
                    rdtypes.extend(self._rdtypes_to_query(self.name))
        else:
            rdtypes.extend(self._rdtypes_to_query_for_name(name))
            if self.name == name:
                if orig_name != name:
                    rdtypes.extend(self._rdtypes_to_query_for_name(orig_name))

                if self.extra_rdtypes is not None:
                    rdtypes.extend(self.extra_rdtypes)

            else:
                if name in self._cname_chain:
                    rdtypes.extend(self._rdtypes_to_query(self.name))

                if self._ask_tlsa_queries(self.name) and len(name) == len(self.name) - 2:
                    rdtypes.extend([dns.rdatatype.A, dns.rdatatype.AAAA])

        # remove duplicates
        rdtypes = list(collections.OrderedDict.fromkeys(rdtypes))

        return rdtypes

    def _rdtypes_to_query_for_name(self, name):
        rdtypes = []

        if self._ask_ptr_queries(name):
            rdtypes.append(dns.rdatatype.PTR)
        elif self._ask_naptr_queries(name):
            rdtypes.append(dns.rdatatype.NAPTR)
        elif self._ask_tlsa_queries(name):
            rdtypes.append(dns.rdatatype.TLSA)
        elif self._ask_srv_queries(name):
            rdtypes.append(dns.rdatatype.SRV)
        elif self._is_dkim(name):
            rdtypes.append(dns.rdatatype.TXT)
        elif name.is_subdomain(ARPA_NAME):
            pass
        elif PROTO_LABEL_RE.search(name[0]):
            pass
        elif self._is_sld_or_lower(name):
            rdtypes.extend([dns.rdatatype.A, dns.rdatatype.AAAA])

        return rdtypes

    def _ask_ptr_queries(self, name):
        '''Return True if PTR queries should be asked for this name, as guessed
        by the nature of the name, based on its length and its presence in the
        in-addr.arpa or ip6.arpa trees.'''

        # if this name is in the ip6.arpa tree and is the length of a full
        # reverse IPv6 address, then return True
        if name.is_subdomain(IP6_ARPA_NAME) and len(name) == 35:
            return True

        # if this name is in the in-addr.arpa tree and is the length of a full
        # reverse IPv4 address, then return True
        if name.is_subdomain(INADDR_ARPA_NAME) and len(name) == 7:
            return True

        return False

    def _ask_naptr_queries(self, name):
        '''Return True if NAPTR queries should be asked for this name, as guessed by
        the nature of the name, based on its presence in the e164.arpa tree.'''

        if name.is_subdomain(E164_ARPA_NAME) and name != E164_ARPA_NAME:
            return True

        return False

    def _ask_tlsa_queries(self, name):
        '''Return True if TLSA queries should be asked for this name, which is
        determined by examining the structure of the name for _<port>._<proto>
        format.'''

        if len(name) > 2 and DANE_PORT_RE.search(name[0]) is not None and PROTO_LABEL_RE.search(name[1]) is not None:
            return True

        return False

    def _ask_srv_queries(self, name):
        '''Return True if SRV queries should be asked for this name, which is
        determined by examining the structure of the name for common
        service-related names.'''

        if len(name) > 2 and SRV_PORT_RE.search(name[0]) is not None and PROTO_LABEL_RE.search(name[1]) is not None:
            return True

        return False

    def _is_dkim(self, name):
        '''Return True if the name is a DKIM name.'''

        return '_domainkey' in name

    def _is_sld_or_lower(self, name):
        '''Return True if the name is an SLD or lower.'''

        return len(name) >= 3

    def _ask_non_delegation_queries(self, name):
        '''Return True if non-delegation-related queries should be asked for
        name.'''

        if self.qname_only and not \
                (name == self.name or \
                name in self._cname_chain or \
                (self._ask_tlsa_queries(self.name) and len(name) == len(self.name) - 2)):
            return False
        if self.dlv_domain == self.name:
            return False
        return True

    def _filter_servers(self, servers):
        if self.client_ipv6 is None:
            servers = filter(lambda x: x.version != 6, servers)
        if self.client_ipv4 is None:
            servers = filter(lambda x: x.version != 4, servers)
        if not self.allow_loopback_query:
            servers = filter(lambda x: x.scope != IP_SCOPE_LOOPBACK, servers)
        if not self.allow_private_query:
            servers = filter(lambda x: x.scope not in (IP_SCOPE_UNIQUE_LOCAL, IP_SCOPE_RFC_1918, IP_SCOPE_LINK_LOCAL), servers)
        return servers

    def _get_name_for_analysis(self, name, stub=False, lock=True):
        with self.analysis_cache_lock:
            try:
                name_obj = self.analysis_cache[name]
            except KeyError:
                if lock:
                    name_obj = self.analysis_cache[name] = self.analysis_model(name, stub=stub, analysis_type=self.analysis_type)
                    return name_obj
                # if not locking, then return None
                else:
                    return None

        # if there is a complete event, then wait on it
        if hasattr(name_obj, 'complete'):
            name_obj.complete.wait()
        # loop and wait for analysis to be completed
        while name_obj.analysis_end is None:
            time.sleep(1)
            name_obj = self.analysis_cache[name]

        # check if this analysis needs to be re-done
        if self.name == name:
            redo_analysis = False
            # re-do analysis if force_dnskey is True and dnskey hasn't been queried
            if self._force_dnskey_query(self.name) and (self.name, dns.rdatatype.DNSKEY) not in name_obj.queries:
                redo_analysis = True

            # re-do analysis if there were no queries (previously an
            # "empty" non-terminal) but now it is the name in question
            if not name_obj.queries:
                redo_analysis = True

            # re-do analysis if this name is referenced by an alias
            # and previously the necessary queries weren't asked
            if self._is_referral_of_type(dns.rdatatype.CNAME):
                rdtypes_to_query = set(self._rdtypes_to_query(name))
                rdtypes_queried = set([r for n,r in name_obj.queries if n == name_obj.name])
                if rdtypes_to_query.difference(rdtypes_queried):
                    redo_analysis = True

            # if the previous analysis was a stub, but now we want the
            # whole analysis
            if name_obj.stub and not stub:
                redo_analysis = True

            if redo_analysis:
                with self.analysis_cache_lock:
                    if name_obj.uuid == self.analysis_cache[name].uuid:
                        del self.analysis_cache[name]
                return self._get_name_for_analysis(name, stub, lock)

        return name_obj

    def analyze_async(self, callback=None, exc_callback=None):
        def _analyze():
            try:
                result = self.analyze()
                if callback is not None:
                    callback(result)
            except:
                if exc_callback is not None:
                    exc_callback(sys.exc_info())
        t = threading.Thread(target=_analyze)
        t.start()
        return t

    def analyze(self):
        self._analyze_dlv()
        return self._analyze(self.name)

    def _analyze_dlv(self):
        if self.dlv_domain is not None and self.dlv_domain != self.name and self.dlv_domain not in self.analysis_cache:
            kwargs = dict([(n, getattr(self, n)) for n in self.clone_attrnames])
            kwargs['ceiling'] = self.dlv_domain
            a = self.__class__(self.dlv_domain, **kwargs)
            a.analyze()

    def _finalize_analysis_proper(self, name_obj):
        pass

    def _finalize_analysis_all(self, name_obj):
        pass

    def _cleanup_analysis_proper(self, name_obj):
        if hasattr(name_obj, 'complete'):
            name_obj.complete.set()

    def _cleanup_analysis_all(self, name_obj):
        if self.cache_level is not None and len(name_obj.name) > self.cache_level:
            del self.analysis_cache[name_obj.name]

    def _handle_explicit_delegations(self, name_obj):
        key = None
        if name_obj.name in self.explicit_delegations:
            key = name_obj.name
        elif WILDCARD_EXPLICIT_DELEGATION in self.explicit_delegations:
            key = WILDCARD_EXPLICIT_DELEGATION
        if key is not None:
            name_obj.add_auth_ns_ip_mappings(*self.explicit_delegations[key])
            name_obj.explicit_delegation = True

    def _analyze_stub(self, name):
        name_obj = self._get_name_for_analysis(name, stub=True)
        if name_obj.analysis_end is not None:
            return name_obj

        try:
            self.logger.info('Analyzing %s (stub)' % fmt.humanize_name(name))

            name_obj.analysis_start = datetime.datetime.now(fmt.utc).replace(microsecond=0)

            self._handle_explicit_delegations(name_obj)
            if not name_obj.explicit_delegation:
                try:
                    ans = resolver.query_for_answer(name, dns.rdatatype.NS, dns.rdataclass.IN)

                    # resolve every name in the NS RRset
                    query_tuples = []
                    for rr in ans.rrset:
                        query_tuples.extend([(rr.target, dns.rdatatype.A, dns.rdataclass.IN), (rr.target, dns.rdatatype.AAAA, dns.rdataclass.IN)])
                    answer_map = resolver.query_multiple_for_answer(*query_tuples)
                    for query_tuple in answer_map:
                        a = answer_map[query_tuple]
                        if isinstance(a, Resolver.DNSAnswer):
                            for a_rr in a.rrset:
                                name_obj.add_auth_ns_ip_mappings((query_tuple[0], IPAddr(a_rr.to_text())))
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    name_obj.parent = self._analyze_stub(name.parent()).zone
                except dns.exception.DNSException:
                    name_obj.parent = self._analyze_stub(name.parent()).zone

            name_obj.analysis_end = datetime.datetime.now(fmt.utc).replace(microsecond=0)

            self._finalize_analysis_proper(name_obj)
            self._finalize_analysis_all(name_obj)
        finally:
            self._cleanup_analysis_proper(name_obj)
            self._cleanup_analysis_all(name_obj)

        return name_obj

    def _analyze_ancestry(self, name):
        # only analyze the parent if the name is not root and if there is no
        # ceiling or the name is a subdomain of the ceiling
        if name == dns.name.root:
            parent_obj = None
        elif name in self.explicit_delegations:
            parent_obj = None
        elif self.ceiling is not None and self.ceiling.is_subdomain(name):
            parent_obj = self._analyze_stub(name.parent())
        else:
            parent_obj = self._analyze(name.parent())

        if parent_obj is not None:
            nxdomain_ancestor = parent_obj.nxdomain_ancestor
            if nxdomain_ancestor is None and \
                    parent_obj.referral_rdtype is not None and \
                    parent_obj.queries[(parent_obj.name, parent_obj.referral_rdtype)].is_nxdomain_all():
                nxdomain_ancestor = parent_obj

            # for zones other than the root assign parent_obj to the zone apex,
            # rather than the simply the domain formed by dropping its lower
            # leftmost label
            parent_obj = parent_obj.zone

        else:
            nxdomain_ancestor = None

        # retrieve the dlv
        if self.dlv_domain is not None and self.name != self.dlv_domain:
            dlv_parent_obj = self.analysis_cache[self.dlv_domain]
        else:
            dlv_parent_obj = None

        return parent_obj, dlv_parent_obj, nxdomain_ancestor

    def _analyze(self, name):
        '''Analyze a DNS name to learn about its health using introspective
        queries.'''

        # determine immediately if we need to do anything
        name_obj = self._get_name_for_analysis(name, lock=False)
        if name_obj is not None and name_obj.analysis_end is not None:
            return name_obj

        parent_obj, dlv_parent_obj, nxdomain_ancestor = \
                self._analyze_ancestry(name)

        # get or create the name
        name_obj = self._get_name_for_analysis(name)
        if name_obj.analysis_end is not None:
            return name_obj

        try:
            try:
                name_obj.parent = parent_obj
                name_obj.dlv_parent = dlv_parent_obj
                name_obj.nxdomain_ancestor = nxdomain_ancestor

                name_obj.analysis_start = datetime.datetime.now(fmt.utc).replace(microsecond=0)

                # perform the actual analysis on this name
                self._analyze_name(name_obj)

                # set analysis_end
                name_obj.analysis_end = datetime.datetime.now(fmt.utc).replace(microsecond=0)

                # remove dlv_parent if there are no DLV queries associated with it
                if name_obj.dlv_parent is not None and \
                        (name_obj.dlv_name, dns.rdatatype.DLV) not in name_obj.queries:
                    name_obj.dlv_parent = None

                # sanity check - if we weren't able to get responses from any
                # servers, check that we actually have connectivity
                self._check_connectivity(name_obj)

                self._finalize_analysis_proper(name_obj)
            finally:
                self._cleanup_analysis_proper(name_obj)

            # analyze dependencies
            self._analyze_dependencies(name_obj)

            self._finalize_analysis_all(name_obj)
        finally:
            self._cleanup_analysis_all(name_obj)

        return name_obj

    def _analyze_name(self, name_obj):
        self.logger.info('Analyzing %s' % fmt.humanize_name(name_obj.name))

        self._handle_explicit_delegations(name_obj)
        if not name_obj.explicit_delegation:
            # analyze delegation, and return if name doesn't exist, unless
            # explicit_only was specified
            yxdomain = self._analyze_delegation(name_obj)
            if not yxdomain and not self.explicit_only:
                return

        # set the NS dependencies for the name
        if name_obj.is_zone():
            name_obj.set_ns_dependencies()

        self._analyze_queries(name_obj)

    def _analyze_queries(self, name_obj):
        bailiwick = name_obj.zone.name

        if not name_obj.zone._all_servers_queried:
            servers = name_obj.zone.get_auth_or_designated_servers()
        else:
            servers = name_obj.zone.get_responsive_auth_or_designated_servers()
        servers = self._filter_servers(servers)
        exclude_no_answer = set()
        queries = {}

        # if there are responsive servers to query...
        if servers:

            # queries specific to zones for which non-delegation-related
            # queries are being issued
            if name_obj.is_zone() and self._ask_non_delegation_queries(name_obj.name) and not self.explicit_only:

                # EDNS diagnostic queries
                if self.edns_diagnostics:
                    self.logger.debug('Preparing EDNS diagnostic queries %s/%s...' % (fmt.humanize_name(name_obj.name), dns.rdatatype.to_text(dns.rdatatype.SOA)))
                    queries[(name_obj.name, -(dns.rdatatype.SOA+100))] = self.edns_version_diagnostic_query(name_obj.name, dns.rdatatype.SOA, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)
                    queries[(name_obj.name, -(dns.rdatatype.SOA+101))] = self.edns_opt_diagnostic_query(name_obj.name, dns.rdatatype.SOA, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)
                    queries[(name_obj.name, -(dns.rdatatype.SOA+102))] = self.edns_flag_diagnostic_query(name_obj.name, dns.rdatatype.SOA, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)

                # negative queries for all zones
                self._set_negative_queries(name_obj)
                if name_obj.nxdomain_name is not None:
                    self.logger.debug('Preparing query %s/%s (NXDOMAIN)...' % (fmt.humanize_name(name_obj.nxdomain_name), dns.rdatatype.to_text(name_obj.nxdomain_rdtype)))
                    queries[(name_obj.nxdomain_name, name_obj.nxdomain_rdtype)] = self.diagnostic_query(name_obj.nxdomain_name, name_obj.nxdomain_rdtype, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)
                if name_obj.nxrrset_name is not None:
                    self.logger.debug('Preparing query %s/%s (No data)...' % (fmt.humanize_name(name_obj.nxrrset_name), dns.rdatatype.to_text(name_obj.nxrrset_rdtype)))
                    queries[(name_obj.nxrrset_name, name_obj.nxrrset_rdtype)] = self.diagnostic_query(name_obj.nxrrset_name, name_obj.nxrrset_rdtype, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)

                # if the name is SLD or lower, then ask MX and TXT
                if self._is_sld_or_lower(name_obj.name):
                    self.logger.debug('Preparing query %s/MX...' % fmt.humanize_name(name_obj.name))
                    # note that we use a PMTU diagnostic query here, to simultaneously test PMTU
                    queries[(name_obj.name, dns.rdatatype.MX)] = self.pmtu_diagnostic_query(name_obj.name, dns.rdatatype.MX, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)
                    # we also do a query with small UDP payload to elicit and test a truncated response
                    queries[(name_obj.name, -dns.rdatatype.MX)] = self.truncation_diagnostic_query(name_obj.name, dns.rdatatype.MX, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)

                    self.logger.debug('Preparing query %s/TXT...' % fmt.humanize_name(name_obj.name))
                    queries[(name_obj.name, dns.rdatatype.TXT)] = self.diagnostic_query(name_obj.name, dns.rdatatype.TXT, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)

        # for zones and for (non-zone) names which have DNSKEYs referenced
        if name_obj.is_zone() or self._force_dnskey_query(name_obj.name):

            # if there are responsive servers to query...
            if servers:
                if self._ask_non_delegation_queries(name_obj.name) and not self.explicit_only:
                    self.logger.debug('Preparing query %s/SOA...' % fmt.humanize_name(name_obj.name))
                    queries[(name_obj.name, dns.rdatatype.SOA)] = self.diagnostic_query(name_obj.name, dns.rdatatype.SOA, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)

                    if name_obj.is_zone():
                        # for zones we also use a TCP diagnostic query here, to simultaneously test TCP connectivity
                        queries[(name_obj.name, -dns.rdatatype.SOA)] = self.tcp_diagnostic_query(name_obj.name, dns.rdatatype.SOA, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)
                    else:
                        # for non-zones we don't need to keey the (UDP) SOA query, if there is no positive response
                        exclude_no_answer.add((name_obj.name, dns.rdatatype.SOA))

                self.logger.debug('Preparing query %s/DNSKEY...' % fmt.humanize_name(name_obj.name))
                # note that we use a PMTU diagnostic query here, to simultaneously test PMTU
                queries[(name_obj.name, dns.rdatatype.DNSKEY)] = self.pmtu_diagnostic_query(name_obj.name, dns.rdatatype.DNSKEY, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)

                # we also do a query with small UDP payload to elicit and test a truncated response
                queries[(name_obj.name, -dns.rdatatype.DNSKEY)] = self.truncation_diagnostic_query(name_obj.name, dns.rdatatype.DNSKEY, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)

            # query for DS/DLV
            if name_obj.parent is not None:
                if not name_obj.parent._all_servers_queried:
                    parent_servers = name_obj.zone.parent.get_auth_or_designated_servers()
                else:
                    parent_servers = name_obj.zone.parent.get_responsive_auth_or_designated_servers()
                    if not parent_servers:
                        # while the parent servers might not be responsive for the parent name,
                        # they must be responsive for the current name, or else we wouldn't be here.
                        parent_servers = name_obj.zone.parent.get_auth_or_designated_servers()
                parent_servers = self._filter_servers(parent_servers)

                self.logger.debug('Preparing query %s/DS...' % fmt.humanize_name(name_obj.name))
                queries[(name_obj.name, dns.rdatatype.DS)] = self.diagnostic_query(name_obj.name, dns.rdatatype.DS, dns.rdataclass.IN, parent_servers, name_obj.parent_name(), self.client_ipv4, self.client_ipv6)

                if name_obj.dlv_parent is not None and self.dlv_domain != self.name:
                    dlv_servers = name_obj.dlv_parent.get_responsive_auth_or_designated_servers()
                    dlv_servers = self._filter_servers(dlv_servers)
                    dlv_name = name_obj.dlv_name
                    if dlv_servers:
                        self.logger.debug('Preparing query %s/DLV...' % fmt.humanize_name(dlv_name))
                        queries[(dlv_name, dns.rdatatype.DLV)] = self.diagnostic_query(dlv_name, dns.rdatatype.DLV, dns.rdataclass.IN, dlv_servers, name_obj.dlv_parent_name(), self.client_ipv4, self.client_ipv6)
                        exclude_no_answer.add((dlv_name, dns.rdatatype.DLV))

        # get rid of any queries already asked
        for name, rdtype in set(name_obj.queries).intersection(set(queries)):
            del queries[(name, rdtype)]

        # finally, query any additional rdtypes
        if servers and self._ask_non_delegation_queries(name_obj.name):
            all_queries = set(name_obj.queries).union(set(queries))
            for rdtype in self._rdtypes_to_query(name_obj.name):
                if (name_obj.name, rdtype) not in all_queries:
                    self.logger.debug('Preparing query %s/%s...' % (fmt.humanize_name(name_obj.name), dns.rdatatype.to_text(rdtype)))
                    queries[(name_obj.name, rdtype)] = self.diagnostic_query(name_obj.name, rdtype, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)

            # if no default queries were identified (e.g., empty non-terminal in
            # in-addr.arpa space), then add a backup.
            if not (queries or name_obj.queries):
                rdtype = dns.rdatatype.A
                self.logger.debug('Preparing query %s/%s...' % (fmt.humanize_name(name_obj.name), dns.rdatatype.to_text(rdtype)))
                queries[(name_obj.name, rdtype)] = self.diagnostic_query(name_obj.name, rdtype, dns.rdataclass.IN, servers, bailiwick, self.client_ipv4, self.client_ipv6)

        # actually execute the queries, then store the results
        self.logger.debug('Executing queries...')
        Q.ExecutableDNSQuery.execute_queries(*queries.values())
        for key, query in queries.items():
            if query.is_answer_any() or key not in exclude_no_answer:
                name_obj.add_query(query)

    def _analyze_delegation(self, name_obj):
        if name_obj.parent is None:
            parent_auth_servers = ROOT_NS_IPS
        elif name_obj.parent.stub:
            parent_auth_servers = name_obj.parent.get_auth_or_designated_servers()
        else:
            parent_auth_servers = name_obj.parent.get_responsive_auth_or_designated_servers()
            # even if no servers are responsive, use all designated servers if this
            # is the name in question, for completeness
            if not parent_auth_servers and name_obj.name == self.name:
                parent_auth_servers = name_obj.parent.get_auth_or_designated_servers()
        parent_auth_servers = set(self._filter_servers(parent_auth_servers))

        if not parent_auth_servers:
            return False

        servers_queried = collections.OrderedDict(((dns.rdatatype.NS, set()),))
        referral_queries = {}

        try:
            secondary_rdtype = self._rdtypes_to_query(name_obj.name)[0]
        except IndexError:
            secondary_rdtype = None
        else:
            if secondary_rdtype in (dns.rdatatype.DS, dns.rdatatype.DLV, dns.rdatatype.NS):
                secondary_rdtype = None
            else:
                servers_queried[secondary_rdtype] = set()

        # elicit a referral from parent servers by querying first for NS, then
        # a secondary type as a fallback
        for rdtype in servers_queried:
            servers_queried[rdtype].update(parent_auth_servers)

            name_obj.referral_rdtype = rdtype

            self.logger.debug('Querying %s/%s (referral)...' % (fmt.humanize_name(name_obj.name), dns.rdatatype.to_text(rdtype)))
            query = self.diagnostic_query(name_obj.name, rdtype, dns.rdataclass.IN, parent_auth_servers, name_obj.parent_name(), self.client_ipv4, self.client_ipv6)
            query.execute()
            referral_queries[rdtype] = query

            # if NXDOMAIN was received, then double-check with the secondary
            # type, as some servers (mostly load balancers) don't respond well
            # to NS queries
            if query.is_nxdomain_all():
                continue

            # otherwise, if we received at least one valid response, then break out
            if query.is_valid_complete_response_any():
                break

            # we only go a second time through the loop, querying the secondary
            # rdtype query if 1) there was NXDOMAIN or 2) there were no valid
            # responses.  In either case the secondary record type becomes the
            # referral rdtype.

        # if the name is not a delegation, or if we received no valid and
        # complete response, then move along
        if query.is_not_delegation_all() or not query.is_valid_complete_response_any():
            # We only keep the referral response if:
            #   1) there was an error getting a referral response;
            #   2) there was a discrepancy between NXDOMAIN and YXDOMAIN; or
            #   3) this is the name in question and the response was NXDOMAIN,
            #      in which case we use this to show the NXDOMAIN (empty answers
            #      will be asked later by better queries)
            # And in the case of a referral using the secondary rdtype, we only
            # keep the NS referral if there was a discrepancy between NXDOMAIN
            # and YXDOMAIN.

            is_nxdomain = query.is_nxdomain_all()
            is_valid = query.is_valid_complete_response_any()

             # (referral type is NS)
            if name_obj.referral_rdtype == dns.rdatatype.NS:
                # If there was a secondary type, the fact that only NS was queried
                # for indicates that there was no error and no NXDOMAIN response.
                # In this case, there is no need to save the referral.  Delete it.
                if secondary_rdtype is not None:
                    name_obj.referral_rdtype = None
                    del referral_queries[dns.rdatatype.NS]

                # If there was no secondary type, we need to evaluate the responses
                # to see if they're worth saving.  Save the referral if there
                # was an error or NXDOMAIN and there is no nxdomain_ancestor or
                # this is the name in question.
                else:
                    if not is_valid or (is_nxdomain and (name_obj.name == self.name or name_obj.nxdomain_ancestor is None)):
                        pass
                    else:
                        name_obj.referral_rdtype = None
                        del referral_queries[dns.rdatatype.NS]

             # (referral type is secondary type)
            else:
                # don't remove either record if there's an NXDOMAIN/YXDOMAIN mismatch
                if referral_queries[dns.rdatatype.NS].is_nxdomain_all() and \
                        is_valid and not is_nxdomain:
                    pass
                else:
                    # if no mismatch, then always delete the NS record
                    del referral_queries[dns.rdatatype.NS]
                    # Save the referral if there was an error or NXDOMAIN and
                    # there is no nxdomain_ancestor or this is the name in
                    # question.
                    if not is_valid or (is_nxdomain and (name_obj.name == self.name or name_obj.nxdomain_ancestor is None)):
                        pass
                    else:
                        name_obj.referral_rdtype = None
                        del referral_queries[secondary_rdtype]

            # add remaining queries
            for query in referral_queries.values():
                name_obj.add_query(query, True)

            # return a positive response only if not nxdomain
            return not is_nxdomain

        # add any queries made
        for query in referral_queries.values():
            name_obj.add_query(query, True)

        # now identify the authoritative NS RRset from all servers, resolve all
        # names referred to in the NS RRset(s), and query each corresponding
        # server, until all names have been queried
        names_resolved = set()
        names_not_resolved = name_obj.get_ns_names().difference(names_resolved)
        while names_not_resolved:
            # resolve every name in the NS RRset
            query_tuples = []
            for name in names_not_resolved:
                query_tuples.extend([(name, dns.rdatatype.A, dns.rdataclass.IN), (name, dns.rdatatype.AAAA, dns.rdataclass.IN)])
            answer_map = resolver.query_multiple_for_answer(*query_tuples)
            for query_tuple in answer_map:
                name = query_tuple[0]
                a = answer_map[query_tuple]
                if isinstance(a, Resolver.DNSAnswer):
                    for a_rr in a.rrset:
                        name_obj.add_auth_ns_ip_mappings((name, IPAddr(a_rr.to_text())))
                # negative responses
                elif isinstance(a, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
                    name_obj.add_auth_ns_ip_mappings((name, None))
                # error responses
                elif isinstance(a, (dns.exception.Timeout, dns.resolver.NoNameservers)):
                    pass
                names_resolved.add(name)

            queries = []
            auth_servers = name_obj.get_auth_or_designated_servers(no_cache=True)

            # NS query
            servers = auth_servers.difference(servers_queried[dns.rdatatype.NS])
            servers_queried[dns.rdatatype.NS].update(servers)
            servers = self._filter_servers(servers)
            if servers:
                self.logger.debug('Querying %s/NS (auth)...' % fmt.humanize_name(name_obj.name))
                queries.append(self.diagnostic_query(name_obj.name, dns.rdatatype.NS, dns.rdataclass.IN, servers, name_obj.name, self.client_ipv4, self.client_ipv6))

            # secondary query
            if secondary_rdtype is not None and self._ask_non_delegation_queries(name_obj.name):
                servers = auth_servers.difference(servers_queried[secondary_rdtype])
                servers_queried[secondary_rdtype].update(servers)
                servers = self._filter_servers(servers)
                if servers:
                    self.logger.debug('Querying %s/%s...' % (fmt.humanize_name(name_obj.name), dns.rdatatype.to_text(secondary_rdtype)))
                    queries.append(self.diagnostic_query(name_obj.name, secondary_rdtype, dns.rdataclass.IN, servers, name_obj.name, self.client_ipv4, self.client_ipv6))

            # actually execute the queries, then store the results
            Q.ExecutableDNSQuery.execute_queries(*queries)
            for query in queries:
                name_obj.add_query(query, True)

            names_not_resolved = name_obj.get_ns_names().difference(names_resolved)

        #TODO now go back and look at servers authoritative for both parent and
        #child that have authoritative referrals and re-classify them as
        #non-referrals (do this in deserialize (and dnsvizwww retrieve also)

        return True

    def _analyze_dependency(self, analyst, result_map, result_key, errors):
        try:
            result_map[result_key] = analyst.analyze()
        except:
            errors.append((result_key, sys.exc_info()))

    def _analyze_dependencies(self, name_obj):
        threads = []
        errors = []

        kwargs = dict([(n, getattr(self, n)) for n in self.clone_attrnames])
        for cname in name_obj.cname_targets:
            for target in name_obj.cname_targets[cname]:
                a = self.__class__(target, trace=self.trace + [(name_obj, dns.rdatatype.CNAME)], extra_rdtypes=self.extra_rdtypes, **kwargs)
                t = threading.Thread(target=self._analyze_dependency, args=(a, name_obj.cname_targets[cname], target, errors))
                t.start()
                threads.append(t)

        for signer in name_obj.external_signers:
            a = self.__class__(signer, trace=self.trace + [(name_obj, dns.rdatatype.RRSIG)], **kwargs)
            t = threading.Thread(target=self._analyze_dependency, args=(a, name_obj.external_signers, signer, errors))
            t.start()
            threads.append(t)

        if self.follow_ns:
            for ns in name_obj.ns_dependencies:
                a = self.__class__(ns, trace=self.trace + [(name_obj, dns.rdatatype.NS)], **kwargs)
                t = threading.Thread(target=self._analyze_dependency, args=(a, name_obj.ns_dependencies, ns, errors))
                t.start()
                threads.append(t)

        if self.follow_mx:
            for target in name_obj.mx_targets:
                a = self.__class__(target, trace=self.trace + [(name_obj, dns.rdatatype.MX)], extra_rdtypes=[dns.rdatatype.A, dns.rdatatype.AAAA], **kwargs)
                t = threading.Thread(target=self._analyze_dependency, args=(a, name_obj.mx_targets, target, errors))
                t.start()
                threads.append(t)

        for t in threads:
            t.join()
        if errors:
            # raise only the first exception, but log all the ones beyond
            for name, exc_info in errors[1:]:
                self.logger.error('Error analyzing %s' % name, exc_info=exc_info)
            raise errors[0][1][0], None, errors[0][1][2]

    def _set_negative_queries(self, name_obj):
        random_label = ''.join(random.sample('abcdefghijklmnopqrstuvwxyz1234567890', 10))
        try:
            name_obj.nxdomain_name = dns.name.from_text(random_label, name_obj.name)
            name_obj.nxdomain_rdtype = dns.rdatatype.A
        except dns.name.NameTooLong:
            pass

        name_obj.nxrrset_name = name_obj.name
        name_obj.nxrrset_rdtype = dns.rdatatype.CNAME

    def _check_connectivity(self, name_obj):
        if name_obj.get_auth_or_designated_servers(4) and self.client_ipv4 is not None and not name_obj.get_responsive_servers_udp(4):
            if not self._root_responsive(4):
                raise IPv4ConnectivityException('No IPv4 connectivity available!')
        if name_obj.get_auth_or_designated_servers(6) and self.client_ipv6 is not None and not name_obj.get_responsive_servers_udp(6):
            if not self._root_responsive(6):
                raise IPv6ConnectivityException('No IPv6 connectivity available!')

    def _root_responsive(self, proto):
        try:
            if proto == 4:
                _root_ipv4_connectivity_checker.query_for_answer(dns.name.root, dns.rdatatype.NS, dns.rdataclass.IN)
            elif proto == 6:
                _root_ipv6_connectivity_checker.query_for_answer(dns.name.root, dns.rdatatype.NS, dns.rdataclass.IN)
            return True
        except dns.exception.Timeout:
            pass
        return False

class PrivateAnalyst(Analyst):
    allow_loopback_query = True
    allow_private_query = True

class RecursiveAnalyst(Analyst):
    diagnostic_query = Q.RecursiveDiagnosticQuery
    tcp_diagnostic_query = Q.RecursiveTCPDiagnosticQuery
    pmtu_diagnostic_query = Q.RecursivePMTUDiagnosticQuery
    truncation_diagnostic_query = Q.RecursiveTruncationDiagnosticQuery
    edns_version_diagnostic_query = Q.RecursiveEDNSVersionDiagnosticQuery
    edns_flag_diagnostic_query = Q.RecursiveEDNSFlagDiagnosticQuery
    edns_opt_diagnostic_query = Q.RecursiveEDNSOptDiagnosticQuery

    analysis_type = ANALYSIS_TYPE_RECURSIVE

    def _detect_ceiling(self, ceiling):
        # if there is a ceiling, but the name is not a subdomain
        # of the ceiling, then use the name itself as a base
        if ceiling is not None and not self.name.is_subdomain(ceiling):
            ceiling = self.name

        return ceiling, None

    def _finalize_analysis_proper(self, name_obj):
        '''Since we initially queried the full set of queries before we knew
        which were appropriate for the name in question, we now identify all queries
        that were pertinent and remove all other.'''

        # if it's a stub, then no need to do anything
        if name_obj.stub:
            return

        # if there are not NS records, then it's not a zone, so clear auth NS
        # IP mapping
        if not name_obj.has_ns:
            name_obj._auth_ns_ip_mapping = {}

        queries = set()
        if name_obj.is_zone():
            queries.add((name_obj.name, dns.rdatatype.NS))
            if self._ask_non_delegation_queries(name_obj.name) and not self.explicit_only:
                queries.add((name_obj.nxdomain_name, name_obj.nxdomain_rdtype))
                queries.add((name_obj.nxrrset_name, name_obj.nxrrset_rdtype))
                if self._is_sld_or_lower(name_obj.name):
                    queries.add((name_obj.name, dns.rdatatype.MX))
                    queries.add((name_obj.name, dns.rdatatype.TXT))
        if name_obj.is_zone() or self._force_dnskey_query(name_obj.name):
            if self._ask_non_delegation_queries(name_obj.name) and not self.explicit_only:
                queries.add((name_obj.name, dns.rdatatype.SOA))
            queries.add((name_obj.name, dns.rdatatype.DNSKEY))

            if name_obj.parent is not None:
                queries.add((name_obj.name, dns.rdatatype.DS))
                if name_obj.dlv_parent is not None:
                    queries.add((name_obj.dlv_name, dns.rdatatype.DLV))

        if self._ask_non_delegation_queries(name_obj.name):
            for rdtype in self._rdtypes_to_query(name_obj.name):
                queries.add((name_obj.name, rdtype))

        if not queries:
            # for TLD and higher, add NS
            if len(name_obj.name) <= 2:
                rdtype = dns.rdatatype.NS
            # for SLD and lower, add A
            else:
                rdtype = dns.rdatatype.A
            queries.add((name_obj.name, rdtype))

        for name, rdtype in set(name_obj.queries).difference(queries):
            del name_obj.queries[(name, rdtype)]

        if (name_obj.nxdomain_name, name_obj.nxdomain_rdtype) not in queries:
            name_obj.nxdomain_name = None
            name_obj.nxdomain_rdtype = None
        if (name_obj.nxrrset_name, name_obj.nxrrset_rdtype) not in queries:
            name_obj.nxrrset_name = None
            name_obj.nxrrset_rdtype = None

    def _analyze_stub(self, name):
        name_obj = self._get_name_for_analysis(name, stub=True)
        if name_obj.analysis_end is not None:
            return name_obj

        try:
            self.logger.info('Analyzing %s (stub)' % fmt.humanize_name(name))

            name_obj.analysis_start = datetime.datetime.now(fmt.utc).replace(microsecond=0)

            self._handle_explicit_delegations(name_obj)
            servers = name_obj.zone.get_auth_or_designated_servers()
            servers = self._filter_servers(servers)
            resolver = Resolver.Resolver(list(servers), StandardRecursiveQueryCD)

            try:
                ans = resolver.query_for_answer(name, dns.rdatatype.NS, dns.rdataclass.IN)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                name_obj.parent = self._analyze_stub(name.parent()).zone
            except dns.exception.DNSException:
                pass

            name_obj.analysis_end = datetime.datetime.now(fmt.utc).replace(microsecond=0)

            self._finalize_analysis_proper(name_obj)
            self._finalize_analysis_all(name_obj)
        finally:
            self._cleanup_analysis_proper(name_obj)
            self._cleanup_analysis_all(name_obj)

        return name_obj

    def _analyze_ancestry(self, name, is_zone):
        # only analyze the parent if the name is not root and if there is no
        # ceiling or the name is a subdomain of the ceiling
        if name == dns.name.root:
            parent_obj = None
        elif self.ceiling is not None and self.ceiling.is_subdomain(name) and is_zone:
            parent_obj = self._analyze_stub(name.parent())
        else:
            parent_obj = self._analyze(name.parent())

        if parent_obj is not None:
            nxdomain_ancestor = parent_obj.nxdomain_ancestor
            if nxdomain_ancestor is None and not parent_obj.stub:
                rdtype = filter(lambda x: x[0] == parent_obj.name, parent_obj.queries.keys())[0][1]
                if parent_obj.queries[(parent_obj.name, rdtype)].is_nxdomain_all():
                    nxdomain_ancestor = parent_obj

            # for zones other than the root assign parent_obj to the zone apex,
            # rather than the simply the domain formed by dropping its lower
            # leftmost label
            parent_obj = parent_obj.zone

        else:
            nxdomain_ancestor = None

        # retrieve the dlv
        if self.dlv_domain is not None and self.name != self.dlv_domain:
            dlv_parent_obj = self.analysis_cache[self.dlv_domain]
        else:
            dlv_parent_obj = None

        return parent_obj, dlv_parent_obj, nxdomain_ancestor

    def _analyze(self, name):
        '''Analyze a DNS name to learn about its health using introspective
        queries.'''

        # determine immediately if we need to do anything
        name_obj = self._get_name_for_analysis(name, lock=False)
        if name_obj is not None and name_obj.analysis_end is not None:
            return name_obj

        # get or create the name
        name_obj = self._get_name_for_analysis(name)
        if name_obj.analysis_end is not None:
            return name_obj

        try:
            try:
                name_obj.analysis_start = datetime.datetime.now(fmt.utc).replace(microsecond=0)

                # perform the actual analysis on this name
                self._analyze_name(name_obj)

                # set analysis_end
                name_obj.analysis_end = datetime.datetime.now(fmt.utc).replace(microsecond=0)

                # if we got any type of valid response, then continue
                if name_obj.get_valid_servers():

                    # analyze ancestry
                    parent_obj, dlv_parent_obj, nxdomain_ancestor = \
                            self._analyze_ancestry(name, name_obj.has_ns)

                    name_obj.parent = parent_obj
                    name_obj.dlv_parent = dlv_parent_obj
                    name_obj.nxdomain_ancestor = nxdomain_ancestor

                else:
                    name_obj.parent = None
                    name_obj.dlv_parent = None
                    name_obj.nxdomain_ancestor = None

                self._finalize_analysis_proper(name_obj)
            finally:
                self._cleanup_analysis_proper(name_obj)

            # analyze dependencies
            self._analyze_dependencies(name_obj)

            self._finalize_analysis_all(name_obj)
        finally:
            self._cleanup_analysis_all(name_obj)

        return name_obj

    def _analyze_name(self, name_obj):
        self.logger.info('Analyzing %s' % fmt.humanize_name(name_obj.name))

        self._handle_explicit_delegations(name_obj)

        servers = name_obj.zone.get_auth_or_designated_servers()
        servers = self._filter_servers(servers)

        # make common query first to prime the cache

        # for root and TLD, use type NS
        if len(name_obj.name) <= 2:
            rdtype = dns.rdatatype.NS
        # for SLDs and below detect an appropriate type
        # and use A as a fallback.
        else:
            try:
                rdtype = self._rdtypes_to_query(name_obj.name)[0]
            except IndexError:
                rdtype = dns.rdatatype.A
            else:
                if rdtype in (dns.rdatatype.DS, dns.rdatatype.NS):
                    rdtype = dns.rdatatype.A

        self.logger.debug('Querying %s/%s...' % (fmt.humanize_name(name_obj.name), dns.rdatatype.to_text(rdtype)))
        query = self.diagnostic_query(name_obj.name, rdtype, dns.rdataclass.IN, servers, None, self.client_ipv4, self.client_ipv6)
        query.execute()
        name_obj.add_query(query, True)

        # if there were no valid responses, then exit out early
        if not query.is_valid_complete_response_any() and not self.explicit_only:
            return name_obj

        # if there was an NXDOMAIN for the first query, then don't ask the
        # others, unless explicit was called
        if query.is_nxdomain_all() and not self.explicit_only:
            return name_obj

        # now query most other queries
        self._analyze_queries(name_obj)

        if name_obj.name != dns.name.root:
            # ensure these weren't already queried for (e.g., as part of extra_rdtypes)
            if (name_obj.name, dns.rdatatype.DS) not in name_obj.queries:
                # make DS queries (these won't be included in the above mix
                # because there is no parent on the name_obj)
                self.logger.debug('Querying %s/%s...' % (fmt.humanize_name(name_obj.name), dns.rdatatype.to_text(dns.rdatatype.DS)))
                query = self.diagnostic_query(name_obj.name, dns.rdatatype.DS, dns.rdataclass.IN, servers, None, self.client_ipv4, self.client_ipv6)
                query.execute()
                name_obj.add_query(query)

        # for non-TLDs make NS queries after all others
        if len(name_obj.name) > 2:
            # ensure these weren't already queried for (e.g., as part of extra_rdtypes)
            if (name_obj.name, dns.rdatatype.NS) not in name_obj.queries:
                self.logger.debug('Querying %s/%s...' % (fmt.humanize_name(name_obj.name), dns.rdatatype.to_text(dns.rdatatype.NS)))
                query = self.diagnostic_query(name_obj.name, dns.rdatatype.NS, dns.rdataclass.IN, servers, None, self.client_ipv4, self.client_ipv6)
                query.execute()
                name_obj.add_query(query, True)

        return name_obj

class PrivateRecursiveAnalyst(RecursiveAnalyst):
    allow_loopback_query = True
    allow_private_query = True
