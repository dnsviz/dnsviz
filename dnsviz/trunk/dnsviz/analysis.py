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

import collections
import datetime
import errno
import logging
import random
import re
import socket
import sys
import threading
import time

import dns.flags, dns.name, dns.rdataclass, dns.rdatatype, dns.resolver

import crypto
import format as fmt
import query as Q
import resolver as Resolver
import response as Response
import status as Status
from util import tuple_to_dict

_logger = logging.getLogger(__name__)

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

class FoundYXDOMAIN(Exception):
    pass

ROOT_NS_IPS = set([
        '198.41.0.4', '2001:503:ba3e::2:30',   # A
        '192.228.79.201',                      # B
        '192.33.4.12',                         # C
        '199.7.91.13', '2001:500:2d::d',       # D
        '192.203.230.10',                      # E
        '192.5.5.241', '2001:500:2f::f',       # F
        '192.112.36.4',                        # G
        '128.63.2.53', '2001:500:1::803f:235', # H
        '192.36.148.17', '2001:7fe::53',       # I
        '192.58.128.30', '2001:503:c27::2:30', # J
        '193.0.14.129', '2001:7fd::1',         # K
        '199.7.83.42', '2001:500:3::42',       # L
        '202.12.27.33', '2001:dc3::35',        # M
])

ROOT_NS_IPS_6 = set(filter(lambda x: ':' in x, ROOT_NS_IPS))
ROOT_NS_IPS_4 = ROOT_NS_IPS.difference(ROOT_NS_IPS_6)

ARPA_NAME = dns.name.from_text('arpa')
IP6_ARPA_NAME = dns.name.from_text('ip6', ARPA_NAME)
INADDR_ARPA_NAME = dns.name.from_text('in-addr', ARPA_NAME)

LOOPBACK_IP_RE = re.compile(r'^(127\.|::1$)')
RFC_1918_RE = re.compile(r'^(0?10|172\.0?(1[6-9]|2[0-9]|3[0-1])|192\.168)\.')
LINK_LOCAL_RE = re.compile(r'^fe[89ab][0-9a-f]:', re.IGNORECASE)
UNIQ_LOCAL_RE = re.compile(r'^fd[0-9a-f]{2}:', re.IGNORECASE)

MAX_TTL = 100000000

def _get_client_address(server):
    if ':' in server:
        af = socket.AF_INET6
    else:
        af = socket.AF_INET
    s = socket.socket(af, socket.SOCK_DGRAM)
    try:
        s.connect((server, 53))
    except socket.error:
        return None
    return s.getsockname()[0]

def get_client_addresses(require_ipv4=False, require_ipv6=False, warn=True, logger=_logger):
    client_ipv4 = _get_client_address(list(ROOT_NS_IPS_4)[0])
    client_ipv6 = _get_client_address(list(ROOT_NS_IPS_6)[0])
    if client_ipv4 is None:
        if require_ipv4:
            raise NetworkConnectivityException('No IPv4 interfaces available for analysis!')
        elif warn:
            logger.warning('No IPv4 interfaces available for analysis!')
    if client_ipv6 is None:
        if require_ipv6:
            raise NetworkConnectivityException('No IPv6 interfaces available for analysis!')
        elif warn:
            logger.warning('No IPv6 interfaces available for analysis!')
    return client_ipv4, client_ipv6

# create a standard recurisve DNS query with checking disabled
class StandardRecursiveQueryCD(Q.StandardRecursiveQuery):
    flags = Q.StandardRecursiveQuery.flags | dns.flags.CD

_resolver = Resolver.Resolver.from_file('/etc/resolv.conf', StandardRecursiveQueryCD)
_root_ipv4_connectivity_checker = Resolver.Resolver(list(ROOT_NS_IPS_4), Q.SimpleDNSQuery, max_attempts=1, shuffle=True)
_root_ipv6_connectivity_checker = Resolver.Resolver(list(ROOT_NS_IPS_6), Q.SimpleDNSQuery, max_attempts=1, shuffle=True)

class DomainNameAnalysis(object):
    def __init__(self, name, stub=False):

        ##################################################
        # General attributes
        ##################################################

        # The name that is the focus of the analysis (serialized).
        self.name = name
        self.stub = stub

        # Analysis start and end (serialized).
        self.analysis_start = None
        self.analysis_end = None

        # The record type queried with the name when eliciting a referral.
        # (serialized).
        self.referral_rdtype = None
        self.explicit_delegation = False

        # The queries issued to and corresponding responses received from the
        # servers (serialized).
        self.queries = {}

        # A reference to the analysis of the parent authority (and that of the
        # DLV parent, if any).
        self.parent = None

        self._dlv_parent = None
        self._dlv_name = None

        # The clients used for queries (serialized - for convenience)
        self.clients_ipv4 = set() 
        self.clients_ipv6 = set()

        # Meta information associated with the domain name.  These are
        # set when responses are processed.
        self.has_soa = False
        self.has_ns = False
        self.cname_targets = {}
        self.dname_targets = {}
        self.ns_dependencies = {}
        self.mx_targets = {}
        self.ptr_targets = {}
        self.external_signers = {}

        # TTLs associated with individual record types and the minimum TTL of
        # dependencies
        self.ttl_mapping = {}

        self.status = None
        self.rrset_warnings = None
        self.rrset_errors = None
        self.rrsig_status = None
        self.rrsig_status_by_status = None
        self.wildcard_status = None
        self.wildcard_status_by_status = None
        self.dname_status = None
        self.nxdomain_status = None
        self.nxdomain_status_by_status = None
        self.nxdomain_servers_clients = None
        self.noanswer_servers_clients = None
        self.response_errors_rcode = None
        self.response_errors = None

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

        # Shortcuts to the values in the SOA record.
        self.serial = None
        self.rname = None
        self.mname = None

        self.dnssec_algorithms_in_dnskey = set()
        self.dnssec_algorithms_in_ds = set()
        self.dnssec_algorithms_in_dlv = set()
        self.dnssec_algorithms_digest_in_ds = set()
        self.dnssec_algorithms_digest_in_dlv = set()

        self.ds_status_by_ds = None
        self.ds_status_by_dnskey = None
        self.ds_status_by_status = None

        self.delegation_warnings = None
        self.delegation_errors = None
        self.delegation_status = None

        self.published_keys = None
        self.revoked_keys = None
        self.zsks = None
        self.ksks = None

    def __repr__(self):
        return u'<%s %s>' % (self.__class__.__name__, self.__unicode__())

    def __unicode__(self):
        return fmt.humanize_name(self.name, True)

    def __str__(self):
        return fmt.humanize_name(self.name)

    def parent_name(self):
        if self.parent is not None:
            return self.parent.name
        return None

    def dlv_parent_name(self):
        if self.dlv_parent is not None:
            return self.dlv_parent.name
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

    def _signed(self):
        return bool(self.dnssec_algorithms_in_dnskey or self.dnssec_algorithms_in_ds or self.dnssec_algorithms_in_dlv)
    signed = property(_signed)

    def single_client(self):
        return len(self.clients_ipv4) <= 1 and len(self.clients_ipv6) <= 1

    def get_name(self, name):
        #XXX this is a hack
        if name == self.name:
            return self
        elif name == self.parent_name():
            return self.parent
        elif name == self.dlv_parent_name():
            return self.dlv_parent
        elif name in self.external_signers:
            return self.external_signers[name]
        elif name in self.ns_dependencies and self.ns_dependencies[name] is not None:
            return self.ns_dependencies[name]
        else:
            for cname in self.cname_targets:
                ref = self.cname_targets[cname].get_name(name)
                if ref is not None:
                    return ref
            for dname in self.dname_targets:
                ref = self.dname_targets[dname].get_name(name)
                if ref is not None:
                    return ref
        return None

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

    def _handle_soa_response(self, rrset):
        '''Indicate that there exists an SOA record for the name which is the
        subject of this analysis, and save the relevant parts.'''

        self.has_soa = True
        if self.serial is None or rrset[0].serial > self.serial:
            self.serial = rrset[0].serial
            self.rname = rrset[0].rname
            self.mname = rrset[0].mname

    def _handle_mx_response(self, rrset):
        '''Save the targets from an MX RRset with the name which is the
        subject of this analysis.'''

        for mx in rrset:
            self.mx_targets[mx.exchange] = None

    def _handle_cname_response(self, rrset):
        '''Save the targets from a CNAME RRset with the name which is the
        subject of this analysis.'''

        self.cname_targets[rrset[0].target] = None

    def _handle_dname_response(self, rrset):
        '''Save the targets from a DNAME RRset with the name which is the
        subject of this analysis.'''

        self.dname_targets[rrset[0].target] = None

    def _handle_ptr_response(self, rrset):
        '''Save the targets from a PTR RRset with the name which is the
        subject of this analysis.'''

        self.ptr_targets[rrset[0].target] = None

    def _handle_ns_response(self, rrset, update_ns_names):
        '''Indicate that there exist NS records for the name which is the
        subject of this analysis, and, if authoritative, save the NS
        targets.'''

        self.has_ns = True
        if update_ns_names:
            for ns in rrset:
                self._ns_names_in_child.add(ns.target)

    def set_ns_dependencies(self):
        if self.parent is None:
            return
        for ns in self.get_ns_names_in_child().difference(self.get_ns_names_in_parent()):
            self.ns_dependencies[ns] = None

    def _handle_dnskey_response(self, rrset):
        for dnskey in rrset:
            self.dnssec_algorithms_in_dnskey.add(dnskey.algorithm)

    def _handle_ds_response(self, rrset):
        if rrset.rdtype == dns.rdatatype.DS:
            dnssec_algs = self.dnssec_algorithms_in_ds
            digest_algs = self.dnssec_algorithms_digest_in_ds
        else:
            dnssec_algs = self.dnssec_algorithms_in_dlv
            digest_algs = self.dnssec_algorithms_digest_in_dlv
        for ds in rrset:
            dnssec_algs.add(ds.algorithm)
            digest_algs.add((ds.algorithm, ds.digest_type))

    def _process_response(self, response, server, client, query):
        '''Process a DNS response from a query, setting and updating instance
        variables appropriately, and calling helper methods as necessary.'''

        if response.message is None:
            return

        is_authoritative = response.is_authoritative()

        # note server responsiveness and authoritativeness
        if response.udp_used():
            self._responsive_servers_clients_udp.add((server, client))
        if response.tcp_used():
            self._responsive_servers_clients_tcp.add((server, client))
        if is_authoritative:
            if query.rdtype not in (dns.rdatatype.DS, dns.rdatatype.DLV):
                self._auth_servers_clients.add((server, client))

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
            if query.qname in (self.name, self.dlv_name):
                if rrset.rdtype == dns.rdatatype.SOA:
                    self._handle_soa_response(rrset)
                elif rrset.rdtype == dns.rdatatype.MX:
                    self._handle_mx_response(rrset)
                elif rrset.rdtype == dns.rdatatype.CNAME:
                    self._handle_cname_response(rrset)
                elif rrset.rdtype == dns.rdatatype.PTR:
                    self._handle_ptr_response(rrset)
                elif rrset.rdtype == dns.rdatatype.NS:
                    self._handle_ns_response(rrset, True)
                elif rrset.rdtype == dns.rdatatype.DNSKEY:
                    self._handle_dnskey_response(rrset)
                elif rrset.rdtype in (dns.rdatatype.DS, dns.rdatatype.DLV):
                    self._handle_ds_response(rrset)

                # check whether it is signed and whether the signer matches
                try:
                    rrsig_rrset = response.message.find_rrset(response.message.answer, query.qname, query.rdclass, dns.rdatatype.RRSIG, rrset.rdtype)

                    for rrsig in rrsig_rrset:
                        if rrsig_rrset.covers == dns.rdatatype.DS and rrsig.signer == self.parent_name():
                            pass
                        elif rrsig_rrset.covers == dns.rdatatype.DLV and rrsig.signer == self.dlv_parent_name():
                            pass
                        elif rrsig.signer == self.zone.name:
                            pass
                        else:
                            self.external_signers[rrsig.signer] = None
                except KeyError:
                    pass

                self.ttl_mapping[rrset.rdtype] = min(self.ttl_mapping.get(rrset.rdtype, MAX_TTL), rrset.ttl)

        # look for SOA in authority section, in the case of negative responses
        try:
            soa_rrset = filter(lambda x: x.rdtype == dns.rdatatype.SOA, response.message.authority)[0]
            if soa_rrset.name == self.name:
                self.has_soa = True
        except IndexError:
            pass

        # if it fits the description of a referral, also grab the referral information
        if response.is_referral(query.qname):
            rrset = response.message.find_rrset(response.message.authority, self.name, dns.rdataclass.IN, dns.rdatatype.NS)
            self.ttl_mapping[-dns.rdatatype.NS] = min(self.ttl_mapping.get(-dns.rdatatype.NS, MAX_TTL), rrset.ttl)
            self._add_glue_ip_mapping(response)
            self._handle_ns_response(rrset, False)

        # if it is an authoritative answer that has authority information, then add it
        else:
            try:
                rrset = response.message.find_rrset(response.message.authority, query.qname, dns.rdataclass.IN, dns.rdatatype.NS)
                self._handle_ns_response(rrset, is_authoritative)
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

    def add_query(self, query):
        '''Process a DNS query and its responses, setting and updating instance
        variables appropriately, and calling helper methods as necessary.'''
        
        key = (query.qname, query.rdtype)
        if key not in self.queries:
            self.queries[key] = Q.MultiQuery(query.qname, query.rdtype, query.rdclass)
        self.queries[key].add_query(query)

        for server in query.responses:
            # note the fact that servers were queried
            self._all_servers_queried.add(server)

            for client in query.responses[server]:
                # note the fact that servers were queried from clients
                self._all_servers_clients_queried.add((server, client))
                if query.responses[server][client].tcp_first:
                    self._all_servers_clients_queried_tcp.add((server, client))
                if ':' in client:
                    self.clients_ipv6.add(client)
                else:
                    self.clients_ipv4.add(client)

                self._process_response(query.responses[server][client], server, client, query)

        dname_rrset_info = filter(lambda x: x.dname_info is not None or x.cname_info_from_dname, query.rrset_answer_info)
        for rrset_info in dname_rrset_info:
            if rrset_info.cname_info_from_dname:
                for cname_rrset_info in rrset_info.cname_info_from_dname:
                    self._handle_dname_response(cname_rrset_info.dname_info.rrset)
            elif rrset_info.dname_info is not None:
                self._handle_dname_response(rrset_info.dname_info.rrset)

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

    def get_responsive_servers_udp(self, proto=None):
        '''Return the set of servers for which some type of response was
        received from any client over UDP.'''

        responsive_servers = set([x[0] for x in self._responsive_servers_clients_udp])
        if proto == 4:
            return set(filter(lambda x: ':' not in x, responsive_servers))
        elif proto == 6:
            return set(filter(lambda x: ':' in x, responsive_servers))
        else:
            return responsive_servers

    def get_responsive_servers_tcp(self, proto=None):
        '''Return the set of servers for which some type of response was
        received from any client over TCP.'''

        responsive_servers = set([x[0] for x in self._responsive_servers_clients_tcp])
        if proto == 4:
            return set(filter(lambda x: ':' not in x, responsive_servers))
        elif proto == 6:
            return set(filter(lambda x: ':' in x, responsive_servers))
        else:
            return responsive_servers

    def get_auth_or_designated_servers(self, proto=None, no_cache=False):
        '''Return the set of servers that either answered authoritatively
        or were explicitly designated by NS and glue or authoritative IP.'''

        all_servers = set([x[0] for x in self._auth_servers_clients]).union(self.get_designated_servers(no_cache))
        if proto == 4:
            return set(filter(lambda x: ':' not in x, all_servers))
        elif proto == 6:
            return set(filter(lambda x: ':' in x, all_servers))
        else:
            return all_servers

    def get_responsive_auth_or_designated_servers(self, proto=None, no_cache=False):
        '''Return the set of servers that either answered authoritatively
        or were explicitly designated by NS and glue or authoritative IP and
        were responsive to queries.'''

        return self.get_auth_or_designated_servers(proto, no_cache).intersection(self.get_responsive_servers_udp(proto))

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

    def _index_dnskeys(self):
        self._dnskey_sets = []
        self._dnskeys = {}
        if (self.name, dns.rdatatype.DNSKEY) not in self.queries:
            return
        for dnskey_info in self.queries[(self.name, dns.rdatatype.DNSKEY)].rrset_answer_info:
            # there are CNAMEs that show up here...
            if dnskey_info.rrset.rdtype != dns.rdatatype.DNSKEY:
                continue
            dnskey_set = set()
            for dnskey_rdata in dnskey_info.rrset:
                if dnskey_rdata not in self._dnskeys:
                    self._dnskeys[dnskey_rdata] = Response.DNSKEYMeta(dnskey_info.rrset.name, dnskey_rdata, dnskey_info.rrset.ttl)
                self._dnskeys[dnskey_rdata].rrset_info.append(dnskey_info)
                self._dnskeys[dnskey_rdata].servers_clients.update(dnskey_info.servers_clients)
                dnskey_set.add(self._dnskeys[dnskey_rdata])

            self._dnskey_sets.append((dnskey_set, dnskey_info))

    def get_dnskey_sets(self):
        if not hasattr(self, '_dnskey_sets') or self._dnskey_sets is None:
            self._index_dnskeys()
        return self._dnskey_sets

    def get_dnskeys(self):
        if not hasattr(self, '_dnskeys') or self._dnskeys is None:
            self._index_dnskeys()
        return self._dnskeys.values()

    def potential_trusted_keys(self):
        active_ksks = self.ksks.difference(self.zsks).difference(self.revoked_keys)
        if active_ksks:
            return active_ksks
        return self.ksks.difference(self.revoked_keys)

    def populate_status(self, trusted_keys, supported_algs=None, supported_digest_algs=None, is_dlv=False):
        # status has already been populated
        if self.rrsig_status is not None:
            return

        # if we're a stub, there's nothing to evaluate
        if self.stub:
            return

        if supported_algs is not None:
            supported_algs.intersection_update(crypto._supported_algs)
        else:
            supported_algs = crypto._supported_algs
        if supported_digest_algs is not None:
            supported_digest_algs.intersection_update(crypto._supported_digest_algs)
        else:
            supported_digest_algs = crypto._supported_digest_algs

        if self.parent is not None:
            self.parent.populate_status(trusted_keys, supported_algs, supported_digest_algs)
        if self.dlv_parent is not None:
            self.dlv_parent.populate_status(trusted_keys, supported_algs, supported_digest_algs, is_dlv=True)
        _logger.debug('Assessing status of %s...' % (fmt.humanize_name(self.name)))
        self._populate_name_status()
        self._index_dnskeys()
        self._populate_rrsig_status(supported_algs)
        self._populate_nsec_status()
        if not is_dlv:
            self._populate_delegation_status(supported_algs, supported_digest_algs)
        if self.dlv_parent is not None:
            self._populate_ds_status(dns.rdatatype.DLV, supported_algs, supported_digest_algs)
        self._populate_dnskey_status(trusted_keys)

        for cname, cname_obj in self.cname_targets.items():
            cname_obj.populate_status(trusted_keys)
        for dname, dname_obj in self.dname_targets.items():
            dname_obj.populate_status(trusted_keys)
        for signer, signer_obj in self.external_signers.items():
            signer_obj.populate_status(trusted_keys)
        for target, ns_obj in self.ns_dependencies.items():
            if ns_obj is not None:
                ns_obj.populate_status(trusted_keys)

    def _populate_name_status(self):
        self.status = Status.NAME_STATUS_INDETERMINATE
        self.yxdomain = set()

        for (qname, rdtype), query in self.queries.items():
            for rrset_info in query.rrset_answer_info:
                self.yxdomain.add(rrset_info.rrset.name)
            for qname_sought in query.rrset_noanswer_info:
                try:
                    for soa_owner_name in query.rrset_noanswer_info[qname_sought]:
                        for (server,client) in query.rrset_noanswer_info[qname_sought][soa_owner_name]:
                            for response in query.rrset_noanswer_info[qname_sought][soa_owner_name][(server,client)]:
                                if qname_sought == qname or response.recursion_desired_and_available():
                                    self.yxdomain.add(qname_sought)
                                    raise FoundYXDOMAIN
                except FoundYXDOMAIN:
                    break

            # now check referrals (if name hasn't already been identified as YXDOMAIN)
            if self.name == qname and self.name not in self.yxdomain:
                if rdtype not in (self.referral_rdtype, dns.rdatatype.NS):
                    continue
                try:
                    for query1 in query.queries.values():
                        for server in query1.responses:
                            for client in query1.responses[server]:
                                if query1.responses[server][client].is_referral(self.name):
                                    self.yxdomain.add(self.name)
                                    raise FoundYXDOMAIN
                except FoundYXDOMAIN:
                    pass

        if self.name in self.yxdomain:
            self.status = Status.NAME_STATUS_YXDOMAIN

        for (qname, rdtype), query in self.queries.items():
            if rdtype == dns.rdatatype.DS:
                continue
            if self.name in query.nxdomain_info and self.status == Status.NAME_STATUS_INDETERMINATE:
                self.status = Status.NAME_STATUS_NXDOMAIN

    def _populate_rrsig_status(self, supported_algs):
        self.rrset_warnings = {}
        self.rrset_errors = {}
        self.rrsig_status = {}
        self.rrsig_status_by_status = {}
        self.dname_status = {}
        self.wildcard_status = {}
        self.wildcard_status_by_status = {}
        self.response_errors_rcode = {}
        self.response_errors = {}

        if self.is_zone():
            self.zsks = set()
            self.ksks = set()

        _logger.debug('Assessing RRSIG status of %s...' % (fmt.humanize_name(self.name)))
        for (qname, rdtype), query in self.queries.items():
            items_to_validate = []
            for rrset_info in query.rrset_answer_info:
                items_to_validate.append(rrset_info)
                if rrset_info.dname_info is not None:
                    items_to_validate.append(rrset_info.dname_info)
                for cname_rrset_info in rrset_info.cname_info_from_dname:
                    items_to_validate.append(cname_rrset_info.dname_info)
                    items_to_validate.append(cname_rrset_info)
            for nsec_set_info in query.nsec_set_info:
                items_to_validate += nsec_set_info.rrsets.values()

            for rrset_info in items_to_validate:
                self.rrset_warnings[rrset_info] = {}
                self.rrset_errors[rrset_info] = {}
                self.rrsig_status[rrset_info] = {}

                if rdtype == dns.rdatatype.DLV and qname == self.dlv_name:
                    dnssec_algorithms_in_dnskey = self.dlv_parent.dnssec_algorithms_in_dnskey
                    dnssec_algorithms_in_ds = set()
                    dnssec_algorithms_in_dlv = set()
                elif rdtype == dns.rdatatype.DS:
                    dnssec_algorithms_in_dnskey = self.parent.dnssec_algorithms_in_dnskey
                    dnssec_algorithms_in_ds = self.parent.dnssec_algorithms_in_ds
                    dnssec_algorithms_in_dlv = self.parent.dnssec_algorithms_in_dlv
                else:
                    dnssec_algorithms_in_dnskey = self.zone.dnssec_algorithms_in_dnskey
                    dnssec_algorithms_in_ds = self.zone.dnssec_algorithms_in_ds
                    dnssec_algorithms_in_dlv = self.zone.dnssec_algorithms_in_dlv

                # handle DNAMEs
                has_dname = set()
                if rrset_info.rrset.rdtype == dns.rdatatype.CNAME:
                    if rrset_info.dname_info is not None:
                        dname_info_list = [rrset_info.dname_info]
                        dname_status = Status.CNAMEFromDNAMEStatus(rrset_info, None)
                    elif rrset_info.cname_info_from_dname:
                        dname_info_list = [c.dname_info for c in rrset_info.cname_info_from_dname]
                        dname_status = Status.CNAMEFromDNAMEStatus(rrset_info.cname_info_from_dname[0], rrset_info)
                    else:
                        dname_info_list = []
                        dname_status = None

                    if dname_info_list:
                        for dname_info in dname_info_list:
                            for server, client in dname_info.servers_clients:
                                has_dname.update([(server,client,response) for response in dname_info.servers_clients[(server,client)]])

                        if rrset_info.rrset.name not in self.dname_status:
                            self.dname_status[rrset_info] = []
                        self.dname_status[rrset_info].append(dname_status)

                algs_signing_rrset = {}
                if dnssec_algorithms_in_dnskey or dnssec_algorithms_in_ds or dnssec_algorithms_in_dlv:
                    for server, client in rrset_info.servers_clients:
                        for response in rrset_info.servers_clients[(server, client)]:
                            if (server, client, response) not in has_dname:
                                algs_signing_rrset[(server, client, response)] = set()

                for rrsig in rrset_info.rrsig_info:
                    self.rrsig_status[rrset_info][rrsig] = {}

                    signer = self.get_name(rrsig.signer)

                    if signer.stub:
                        continue

                    for server, client in rrset_info.rrsig_info[rrsig].servers_clients:
                        for response in rrset_info.rrsig_info[rrsig].servers_clients[(server,client)]:
                            if (server,client,response) not in algs_signing_rrset:
                                continue
                            algs_signing_rrset[(server,client,response)].add(rrsig.algorithm)
                            if not dnssec_algorithms_in_dnskey.difference(algs_signing_rrset[(server,client,response)]) and \
                                    not dnssec_algorithms_in_ds.difference(algs_signing_rrset[(server,client,response)]) and \
                                    not dnssec_algorithms_in_dlv.difference(algs_signing_rrset[(server,client,response)]):
                                del algs_signing_rrset[(server,client,response)]

                    # define self-signature
                    self_sig = rdtype == dns.rdatatype.DNSKEY and rrsig.signer == rrset_info.rrset.name

                    #XXX we couldn't find the DNSKEY (currently, we're not checking for external signers?)
                    if signer is not None:
                        checked_keys = set()
                        for dnskey_set, dnskey_meta in signer.get_dnskey_sets():
                            validation_status_mapping = { True: set(), False: set(), None: set() }
                            for dnskey in dnskey_set:
                                # if we've already checked this key (i.e., in
                                # another DNSKEY RRset) then continue
                                if dnskey in checked_keys:
                                    continue
                                # if this is a RRSIG over DNSKEY RRset, then make sure we're validating
                                # with a DNSKEY that is actually in the set
                                if self_sig and dnskey.rdata not in rrset_info.rrset:
                                    continue
                                checked_keys.add(dnskey)
                                if not (dnskey.rdata.protocol == 3 and \
                                        rrsig.key_tag in (dnskey.key_tag, dnskey.key_tag_no_revoke) and \
                                        rrsig.algorithm == dnskey.rdata.algorithm):
                                    continue
                                rrsig_status = Status.RRSIGStatus(rrset_info, rrsig, dnskey, self.zone.name, fmt.datetime_to_timestamp(self.analysis_end), algorithm_unknown=rrsig.algorithm not in supported_algs)
                                validation_status_mapping[rrsig_status.signature_valid].add(rrsig_status)

                            # if we got results for multiple keys, then just select the one that validates
                            for status in True, False, None:
                                if validation_status_mapping[status]:
                                    for rrsig_status in validation_status_mapping[status]:
                                        self.rrsig_status[rrsig_status.rrset][rrsig_status.rrsig][rrsig_status.dnskey] = rrsig_status

                                        if self.is_zone() and rrset_info.rrset.name == self.name and \
                                                rrset_info.rrset.rdtype != dns.rdatatype.DS and \
                                                rrsig_status.dnskey is not None:
                                            if rrset_info.rrset.rdtype == dns.rdatatype.DNSKEY:
                                                self.ksks.add(rrsig_status.dnskey)
                                            else:
                                                self.zsks.add(rrsig_status.dnskey)

                                        key = rrsig_status.rrset, rrsig_status.rrsig
                                        if rrsig_status.validation_status not in self.rrsig_status_by_status:
                                            self.rrsig_status_by_status[rrsig_status.validation_status] = {}
                                        if key not in self.rrsig_status_by_status[rrsig_status.validation_status]:
                                            self.rrsig_status_by_status[rrsig_status.validation_status][key] = set()
                                        self.rrsig_status_by_status[rrsig_status.validation_status][key].add(rrsig_status)
                                    break

                    # no corresponding DNSKEY
                    if not self.rrsig_status[rrset_info][rrsig]:
                        rrsig_status = Status.RRSIGStatus(rrset_info, rrsig, None, self.zone.name, fmt.datetime_to_timestamp(self.analysis_end), algorithm_unknown=rrsig.algorithm not in supported_algs)
                        self.rrsig_status[rrsig_status.rrset][rrsig_status.rrsig][None] = rrsig_status
                        if rrsig_status.validation_status not in self.rrsig_status_by_status:
                            self.rrsig_status_by_status[rrsig_status.validation_status] = {}
                        self.rrsig_status_by_status[rrsig_status.validation_status][(rrsig_status.rrset, rrsig_status.rrsig)] = set([rrsig_status])

                # list errors for rrsets with which no RRSIGs were returned or not all algorithms were accounted for
                for server,client,response in algs_signing_rrset:
                    errors = self.rrset_errors[rrset_info]
                    # report an error if all RRSIGs are missing
                    if not algs_signing_rrset[(server,client,response)]:
                        if response.dnssec_requested():
                            if Status.RESPONSE_ERROR_MISSING_RRSIGS not in errors:
                                errors[Status.RESPONSE_ERROR_MISSING_RRSIGS] = set()
                            errors[Status.RESPONSE_ERROR_MISSING_RRSIGS].add((server,client))
                    else:
                        # report an error if RRSIGs for one or more algorithms are missing
                        if dnssec_algorithms_in_dnskey.difference(algs_signing_rrset[(server,client,response)]):
                            if Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DNSKEY not in errors:
                                errors[Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DNSKEY] = set()
                            errors[Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DNSKEY].add((server,client))
                        if dnssec_algorithms_in_ds.difference(algs_signing_rrset[(server,client,response)]):
                            if Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DS not in errors:
                                errors[Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DS] = set()
                            errors[Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DS].add((server,client))
                        if dnssec_algorithms_in_ds.difference(algs_signing_rrset[(server,client,response)]):
                            if Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DLV not in errors:
                                errors[Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DLV] = set()
                            errors[Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DLV].add((server,client))

                for wildcard_name in rrset_info.wildcard_info:
                    statuses = []
                    for server, client in rrset_info.wildcard_info[wildcard_name]:
                        for response in rrset_info.wildcard_info[wildcard_name][(server,client)]:
                            nsec_info_list = query.nsec_set_info_by_server[response]
                            status = None
                            for nsec_set_info in nsec_info_list:
                                if nsec_set_info.use_nsec3:
                                    status = Status.NSEC3StatusWildcard(rrset_info.rrset.name, wildcard_name, nsec_set_info)
                                else:
                                    status = Status.NSECStatusWildcard(rrset_info.rrset.name, wildcard_name, nsec_set_info)
                                if status.validation_status == Status.STATUS_VALID:
                                    break

                            # report that no NSEC(3) records were returned
                            if status is None:
                                # by definition, DNSSEC was requested (otherwise we
                                # wouldn't know this was a wildcard), so no need to
                                # check for DO bit in request
                                if Status.RESPONSE_ERROR_MISSING_NSEC_FOR_WILDCARD not in self.rrset_errors[rrset_info]:
                                    self.rrset_errors[rrset_info][Status.RESPONSE_ERROR_MISSING_NSEC_FOR_WILDCARD] = set()
                                self.rrset_errors[rrset_info][Status.RESPONSE_ERROR_MISSING_NSEC_FOR_WILDCARD].add((server,client))

                            # add status to list, if an equivalent one not already added
                            elif status not in statuses:
                                statuses.append(status)
                                validation_status = status.validation_status
                                if validation_status not in self.wildcard_status_by_status:
                                    self.wildcard_status_by_status[validation_status] = set()
                                self.wildcard_status_by_status[validation_status].add(status)

                    if statuses:
                        if rrset_info.rrset.name not in self.wildcard_status:
                            self.wildcard_status[rrset_info.rrset.name] = {}
                        if wildcard_name not in self.wildcard_status[rrset_info.rrset.name]:
                            self.wildcard_status[rrset_info.rrset.name][wildcard_name] = set(statuses)

                qname_obj = self.get_name(rrset_info.rrset.name)
                if rrset_info.rrset.rdtype == dns.rdatatype.DS:
                    qname_obj = qname_obj.parent
                for server,client in rrset_info.servers_clients:
                    for response in rrset_info.servers_clients[(server,client)]:
                        errors = self.rrset_errors[rrset_info]
                        warnings = self.rrset_warnings[rrset_info]
                        if response.message.edns < 0:
                            ##TODO be more specific about why EDNS isn't supported (e.g., timeout vs. SERVFAIL, etc.)
                            #if query.responses[server][client].effective_edns < 0:
                            #    pass
                            #else:
                            #    pass
                            if qname_obj is not None and qname_obj.signed:
                                if Status.RESPONSE_ERROR_NO_EDNS_SUPPORT not in errors:
                                    errors[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT] = set()
                                errors[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT].add((server,client))
                            #TODO determine if the following is a warning or not
                            #else:
                            #    if Status.RESPONSE_ERROR_NO_EDNS_SUPPORT not in warnings:
                            #        warnings[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT] = set()
                            #    warnings[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT].add((server,client))
                        elif not response.effective_edns_flags & dns.flags.DO:
                            if qname_obj is not None and qname_obj.signed:
                                if Status.RESPONSE_ERROR_NO_DO_SUPPORT not in errors:
                                    errors[Status.RESPONSE_ERROR_NO_DO_SUPPORT] = set()
                                errors[Status.RESPONSE_ERROR_NO_DO_SUPPORT].add((server,client))
                            #TODO determine if the following is a warning or not
                            #else:
                            #    if Status.RESPONSE_ERROR_NO_DO_SUPPORT not in warnings:
                            #        warnings[Status.RESPONSE_ERROR_NO_DO_SUPPORT] = set()
                            #    warnings[Status.RESPONSE_ERROR_NO_DO_SUPPORT].add((server,client))
                        if not response.is_authoritative() and \
                                not response.recursion_desired_and_available():
                            if Status.RESPONSE_ERROR_NOT_AUTHORITATIVE not in errors:
                                errors[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE] = set()
                            errors[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE].add((server,client))

            self.response_errors_rcode[(qname, rdtype)] = {}
            for rcode in query.error_rcode:
                self.response_errors_rcode[(qname, rdtype)][rcode] = query.error_rcode[rcode]
            self.response_errors[(qname, rdtype)] = {}
            for (error, errno1) in query.error:
                self.response_errors[(qname, rdtype)][(error, errno1)] = query.error[(error, errno1)]

        if self.is_zone():
            self.published_keys = set(self.get_dnskeys()).difference(self.zsks.union(self.ksks))
            self.revoked_keys = set(filter(lambda x: x.rdata.flags & fmt.DNSKEY_FLAGS['revoke'], self.get_dnskeys()))

    def _populate_delegation_status(self, supported_algs, supported_digest_algs):
        self.ds_status_by_ds = {}
        self.ds_status_by_dnskey = {}
        self.ds_status_by_status = {}
        self.delegation_errors = {}
        self.delegation_warnings = {}
        self.delegation_status = {}

        self._populate_ds_status(dns.rdatatype.DS, supported_algs, supported_digest_algs)
        if self.dlv_parent is not None:
            self._populate_ds_status(dns.rdatatype.DLV, supported_algs, supported_digest_algs)

    def _populate_ds_status(self, rdtype, supported_algs, supported_digest_algs):
        if rdtype not in (dns.rdatatype.DS, dns.rdatatype.DLV):
            raise ValueError('Type can only be DS or DLV.')
        if self.parent is None:
            return
        if rdtype == dns.rdatatype.DLV:
            name = self.dlv_name
            if name is None:
                raise ValueError('No DLV specified for DomainNameAnalysis object.')
        else:
            name = self.name

        _logger.debug('Assessing delegation status of %s...' % (fmt.humanize_name(self.name)))
        self.ds_status_by_ds[rdtype] = {}
        self.ds_status_by_dnskey[rdtype] = {}
        self.ds_status_by_status[rdtype] = {}
        self.delegation_warnings[rdtype] = {}
        self.delegation_errors[rdtype] = {}
        self.delegation_status[rdtype] = None

        try:
            ds_rrset_answer_info = self.queries[(name, rdtype)].rrset_answer_info
        except KeyError:
            # zones should have DS queries
            if self.is_zone():
                raise
            else:
                return

        secure_path = False

        if not self.get_responsive_auth_or_designated_servers():
            self.delegation_status[rdtype] = Status.DELEGATION_STATUS_LAME
            return

        # populate all the servers queried for DNSKEYs to determine
        # what problems there were with regard to DS records and if
        # there is at least one match
        dnskey_server_client_responses = set()
        for dnskey_query in self.queries[(self.name, dns.rdatatype.DNSKEY)].queries.values():
            for server in dnskey_query.responses:
                for client in dnskey_query.responses[server]:
                    response = dnskey_query.responses[server][client]
                    if response.is_valid_response() and response.is_complete_response():
                        dnskey_server_client_responses.add((server,client,response))

        for ds_rrset_info in ds_rrset_answer_info:
            # for each set of DS records provided by one or more servers,
            # identify the set of DNSSEC algorithms and the set of digest
            # algorithms per algorithm/key tag combination
            ds_algs = set()
            supported_ds_algs = set()
            digest_algs = {}
            for ds_rdata in ds_rrset_info.rrset:
                if (ds_rdata.algorithm, ds_rdata.key_tag) not in digest_algs:
                    digest_algs[(ds_rdata.algorithm, ds_rdata.key_tag)] = set()
                digest_algs[(ds_rdata.algorithm, ds_rdata.key_tag)].add(ds_rdata.digest_type)
                if ds_rdata.algorithm in supported_algs and ds_rdata.digest_type in supported_digest_algs:
                    supported_ds_algs.add(ds_rdata.algorithm)
                ds_algs.add(ds_rdata.algorithm)

            if supported_ds_algs:
                secure_path = True

            algs_signing_sep = {}
            algs_validating_sep = {}
            for server,client,response in dnskey_server_client_responses:
                algs_signing_sep[(server,client,response)] = set()
                algs_validating_sep[(server,client,response)] = set()

            for ds_rdata in ds_rrset_info.rrset:
                self.ds_status_by_ds[rdtype][ds_rdata] = {}

                for dnskey_info in self.queries[(self.name, dns.rdatatype.DNSKEY)].rrset_answer_info:
                    validation_status_mapping = { True: set(), False: set(), None: set() }
                    for dnskey_rdata in dnskey_info.rrset:
                        dnskey = self._dnskeys[dnskey_rdata]

                        if dnskey not in self.ds_status_by_dnskey[rdtype]:
                            self.ds_status_by_dnskey[rdtype][dnskey] = {}

                        # if the key tag doesn't match, then go any farther
                        if not (ds_rdata.key_tag in (dnskey.key_tag, dnskey.key_tag_no_revoke) and \
                                ds_rdata.algorithm == dnskey.rdata.algorithm):
                            continue

                        # check if the digest is a match
                        ds_status = Status.DSStatus(ds_rdata, ds_rrset_info, dnskey, digest_algorithm_unknown=ds_rdata.digest_type not in supported_digest_algs)
                        validation_status_mapping[ds_status.digest_valid].add(ds_status)

                        # ignore DS algorithm 1 if algorithm 2 exists
                        ignore_ds_alg = (ds_rdata.digest_type == 1) and (2 in digest_algs[(ds_rdata.algorithm, ds_rdata.key_tag)]) and (2 in supported_digest_algs)

                        for rrsig in dnskey_info.rrsig_info:
                            # move along if DNSKEY is not self-signing
                            if dnskey not in self.rrsig_status[dnskey_info][rrsig]:
                                continue
                            
                            # move along if key tag is not the same (i.e., revoke)
                            if dnskey.key_tag != rrsig.key_tag:
                                continue

                            for (server,client) in dnskey_info.rrsig_info[rrsig].servers_clients:
                                for response in dnskey_info.rrsig_info[rrsig].servers_clients[(server,client)]:
                                    if (server,client,response) in algs_signing_sep:
                                        # note that this algorithm is part of a self-signing DNSKEY
                                        algs_signing_sep[(server,client,response)].add(rrsig.algorithm)
                                        if not ds_algs.difference(algs_signing_sep[(server,client,response)]):
                                            del algs_signing_sep[(server,client,response)]

                                    if (server,client,response) in algs_validating_sep:
                                        # retrieve the status of the DNSKEY RRSIG
                                        rrsig_status = self.rrsig_status[dnskey_info][rrsig][dnskey]

                                        # if the DS digest and the RRSIG are both valid, and the digest algorithm
                                        # is not deprecated then mark it as a SEP
                                        if ds_status.validation_status == Status.DS_STATUS_VALID and \
                                                rrsig_status.validation_status == Status.RRSIG_STATUS_VALID and \
                                                not ignore_ds_alg:
                                            # note that this algorithm is part of a successful self-signing DNSKEY
                                            algs_validating_sep[(server,client,response)].add(rrsig.algorithm)
                                            if not ds_algs.difference(algs_validating_sep[(server,client,response)]):
                                                del algs_validating_sep[(server,client,response)]

                    # if we got results for multiple keys, then just select the one that validates
                    for status in True, False, None:
                        if validation_status_mapping[status]:
                            for ds_status in validation_status_mapping[status]:
                                self.ds_status_by_ds[rdtype][ds_status.ds][ds_status.dnskey] = ds_status
                                self.ds_status_by_dnskey[rdtype][ds_status.dnskey][ds_status.ds] = ds_status

                                if ds_status.validation_status not in self.ds_status_by_status[rdtype]:
                                    self.ds_status_by_status[ds_status.validation_status] = {}
                                key = rdtype, ds_status.ds
                                if key not in self.ds_status_by_status[ds_status.validation_status]:
                                    self.ds_status_by_status[ds_status.validation_status][key] = set()
                                self.ds_status_by_status[ds_status.validation_status][key].add(ds_status)
                            break

                # no corresponding DNSKEY
                if not self.ds_status_by_ds[rdtype][ds_rdata]:
                    ds_status = Status.DSStatus(ds_rdata, ds_rrset_info, None)
                    self.ds_status_by_ds[rdtype][ds_rdata][None] = ds_status
                    if None not in self.ds_status_by_dnskey[rdtype]:
                        self.ds_status_by_dnskey[rdtype][None] = {}
                    self.ds_status_by_dnskey[rdtype][None][ds_rdata] = ds_status
                    if ds_status.validation_status not in self.ds_status_by_status:
                        self.ds_status_by_status[ds_status.validation_status] = {}
                    self.ds_status_by_status[ds_status.validation_status][(rdtype, ds_rdata)] = set([ds_status])

            if not algs_validating_sep:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_SECURE
            else:
                for server,client,response in dnskey_server_client_responses:
                    if (server,client,response) not in algs_validating_sep or \
                            supported_ds_algs.intersection(algs_validating_sep[(server,client,response)]):
                        self.delegation_status[rdtype] = Status.DELEGATION_STATUS_SECURE
                    elif supported_ds_algs:
                        if Status.DELEGATION_ERROR_NO_SEP not in self.delegation_errors[rdtype]:
                            self.delegation_errors[rdtype][Status.DELEGATION_ERROR_NO_SEP] = set()
                        self.delegation_errors[rdtype][Status.DELEGATION_ERROR_NO_SEP].add((server,client))

            # report an error if one or more algorithms are incorrectly validated
            for (server,client,response) in algs_signing_sep:
                if Status.DELEGATION_ERROR_NO_SEP_FOR_SOME_ALGS not in self.delegation_errors[rdtype]:
                    self.delegation_errors[rdtype][Status.DELEGATION_ERROR_NO_SEP_FOR_SOME_ALGS] = set()
                self.delegation_errors[rdtype][Status.DELEGATION_ERROR_NO_SEP_FOR_SOME_ALGS].add((server,client))

        if self.delegation_status[rdtype] is None:
            if ds_rrset_answer_info:
                if secure_path:
                    self.delegation_status[rdtype] = Status.DELEGATION_STATUS_BOGUS
                else:
                    self.delegation_status[rdtype] = Status.DELEGATION_STATUS_INSECURE
            elif self.parent.signed:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_BOGUS
                for nsec_status in self.noanswer_status.get((self.name, dns.rdatatype.DS), []):
                    if nsec_status.validation_status == Status.NSEC_STATUS_VALID:
                        self.delegation_status[rdtype] = Status.DELEGATION_STATUS_INSECURE
                        break
            else:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_INSECURE

        if rdtype == dns.rdatatype.DS:
            if (name, rdtype) in self.nxdomain_servers_clients:
                self.delegation_errors[rdtype][Status.DELEGATION_ERROR_NO_NS_IN_PARENT] = self.nxdomain_servers_clients[(self.name, dns.rdatatype.DS)].copy()
                if self.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                    self.delegation_status[rdtype] = Status.DELEGATION_STATUS_INCOMPLETE

            #XXX this needs consideration for recursive
            if self.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                if not self.get_responsive_servers_udp() or not self._auth_servers_clients:
                    self.delegation_status[rdtype] = Status.DELEGATION_STATUS_LAME

    def _populate_nsec_status(self):
        self.nxdomain_status = {}
        self.nxdomain_servers_clients = {}
        self.nxdomain_warnings = {}
        self.nxdomain_errors = {}
        self.nxdomain_status_by_status = {}
        self.noanswer_status = {}
        self.noanswer_servers_clients = {}
        self.noanswer_warnings = {}
        self.noanswer_errors = {}
        self.noanswer_status_by_status = {}


        _logger.debug('Assessing negative responses status of %s...' % (fmt.humanize_name(self.name)))
        for (qname, rdtype), query in self.queries.items():
            for qname_sought in query.nxdomain_info:
                qname_obj = self.get_name(qname_sought)
                if rdtype == dns.rdatatype.DS:
                    qname_obj = qname_obj.parent
                statuses = []
                self.nxdomain_warnings[(qname_sought, rdtype)] = {}
                self.nxdomain_errors[(qname_sought, rdtype)] = {}
                self.nxdomain_servers_clients[(qname_sought, rdtype)] = {}
                for soa_owner_name, servers_clients in query.nxdomain_info[qname_sought].items():
                    self.nxdomain_servers_clients[(qname_sought, rdtype)].update(servers_clients)

                    if soa_owner_name is None:
                        if qname_sought == qname:
                            self.nxdomain_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_MISSING_SOA_FOR_NXDOMAIN] = servers_clients.copy()
                        else:
                            servers_affected = set()
                            for server_client in servers_clients:
                                for response in servers_clients[server_client]:
                                    if response.recursion_desired_and_available():
                                        servers_affected.add(server_client)
                            if servers_affected:
                                self.nxdomain_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_MISSING_SOA_FOR_NXDOMAIN] = servers_affected
                    elif not qname_sought.is_subdomain(soa_owner_name):
                        if qname_sought == qname:
                            if Status.RESPONSE_ERROR_BAD_SOA_FOR_NXDOMAIN not in self.nxdomain_errors[(qname_sought, rdtype)]:
                                self.nxdomain_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_BAD_SOA_FOR_NXDOMAIN] = set()
                            self.nxdomain_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_BAD_SOA_FOR_NXDOMAIN].update(servers_clients)
                        else:
                            servers_affected = set()
                            for server_client in servers_clients:
                                for response in servers_clients[server_client]:
                                    if response.recursion_desired_and_available():
                                        servers_affected.add(server_client)
                            if servers_affected:
                                if Status.RESPONSE_ERROR_BAD_SOA_FOR_NXDOMAIN not in self.nxdomain_errors[(qname_sought, rdtype)]:
                                    self.nxdomain_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_BAD_SOA_FOR_NXDOMAIN] = set()
                                self.nxdomain_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_BAD_SOA_FOR_NXDOMAIN].update(servers_affected)
                        soa_owner_name = None

                    if soa_owner_name is None:
                        if qname_obj is not None:
                            soa_owner_name = qname_obj.zone.name
                        elif self.name.is_subdomain(qname_sought) and qname_sought.is_subdomain(self.zone.name):
                            soa_owner_name = self.zone.name
                        #XXX this is a hack and may not be robust
                        else:
                            soa_owner_name = qname_sought.parent()

                    for server_client in servers_clients:
                        for response in servers_clients[server_client]:
                            if not (qname_sought == qname or response.recursion_desired_and_available()):
                                continue
                            nsec_info_list = query.nsec_set_info_by_server[response]
                            status = None
                            for nsec_set_info in nsec_info_list:
                                if nsec_set_info.use_nsec3:
                                    status = Status.NSEC3StatusNXDOMAIN(qname_sought, soa_owner_name, nsec_set_info)
                                else:
                                    status = Status.NSECStatusNXDOMAIN(qname_sought, soa_owner_name, nsec_set_info)
                                if status.validation_status == Status.STATUS_VALID:
                                    break

                            # report that no NSEC(3) records were returned
                            if status is None:
                                if qname_obj is not None and qname_obj.zone.signed and response.dnssec_requested() and \
                                        (qname_sought == qname or response.recursion_desired_and_available()):
                                    if Status.RESPONSE_ERROR_MISSING_NSEC_FOR_NXDOMAIN not in self.nxdomain_errors[(qname_sought, rdtype)]:
                                        self.nxdomain_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_MISSING_NSEC_FOR_NXDOMAIN] = set()
                                    self.nxdomain_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_MISSING_NSEC_FOR_NXDOMAIN].add(server_client)

                            elif status not in statuses:
                                statuses.append(status)
                                validation_status = status.validation_status
                                if validation_status not in self.nxdomain_status_by_status:
                                    self.nxdomain_status_by_status[validation_status] = set()
                                self.nxdomain_status_by_status[validation_status].add(status)

                if statuses:
                    self.nxdomain_status[(qname_sought, rdtype)] = set(statuses)

                if qname_sought in self.yxdomain and rdtype != dns.rdatatype.DS:
                    self.nxdomain_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_BAD_NXDOMAIN] = self.nxdomain_servers_clients[(qname_sought, rdtype)].copy()

                errors = self.nxdomain_errors[(qname_sought, rdtype)]
                warnings = self.nxdomain_warnings[(qname_sought, rdtype)]
                for server_client in self.nxdomain_servers_clients[(qname_sought, rdtype)]:
                    for response in self.nxdomain_servers_clients[(qname_sought, rdtype)][server_client]:
                        if response.message.edns < 0:
                            #TODO be more specific about why EDNS isn't supported (e.g., timeout vs. SERVFAIL, etc.)
                            #if query.responses[server][client].effective_edns < 0:
                            #    pass
                            #else:
                            #    pass
                            if qname_obj is not None and qname_obj.zone.signed:
                                if Status.RESPONSE_ERROR_NO_EDNS_SUPPORT not in errors:
                                    errors[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT] = set()
                                errors[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT].add(server_client)
                            #TODO determine if the following is a warning or not
                            #else:
                            #    if Status.RESPONSE_ERROR_NO_EDNS_SUPPORT not in warnings:
                            #        warnings[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT] = set()
                            #    warnings[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT].add(server_client)
                        elif not response.effective_edns_flags & dns.flags.DO:
                            if qname_obj is not None and qname_obj.zone.signed:
                                if Status.RESPONSE_ERROR_NO_DO_SUPPORT not in errors:
                                    errors[Status.RESPONSE_ERROR_NO_DO_SUPPORT] = set()
                                errors[Status.RESPONSE_ERROR_NO_DO_SUPPORT].add(server_client)
                            #TODO determine if the following is a warning or not
                            #else:
                            #    if Status.RESPONSE_ERROR_NO_DO_SUPPORT not in warnings:
                            #        warnings[Status.RESPONSE_ERROR_NO_DO_SUPPORT] = set()
                            #    warnings[Status.RESPONSE_ERROR_NO_DO_SUPPORT].add(server_client)
                        if not response.is_authoritative() and \
                                not response.recursion_desired_and_available():
                            if Status.RESPONSE_ERROR_NOT_AUTHORITATIVE not in errors:
                                errors[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE] = set()
                            errors[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE].add(server_client)

            # no answer
            for qname_sought in query.rrset_noanswer_info:
                qname_obj = self.get_name(qname_sought)
                if rdtype == dns.rdatatype.DS:
                    qname_obj = qname_obj.parent
                statuses = []
                self.noanswer_warnings[(qname_sought, rdtype)] = {}
                self.noanswer_errors[(qname_sought, rdtype)] = {}
                self.noanswer_servers_clients[(qname_sought, rdtype)] = {}
                for soa_owner_name, servers_clients in query.rrset_noanswer_info[qname_sought].items():
                    self.noanswer_servers_clients[(qname_sought, rdtype)].update(servers_clients)

                    if soa_owner_name is None:
                        # check for an upward referral
                        servers_missing_soa = set()
                        servers_upward_referral = set()
                        for server_client in servers_clients:
                            for response in servers_clients[server_client]:
                                if qname_sought == qname or response.recursion_desired_and_available():
                                    if qname_obj is not None and response.is_upward_referral(qname_obj.zone.name):
                                        servers_upward_referral.add(server_client)
                                    else:
                                        servers_missing_soa.add(server_client)
                        if servers_missing_soa:
                            self.noanswer_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_MISSING_SOA_FOR_NODATA] = servers_missing_soa
                        if servers_upward_referral:
                            self.noanswer_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_UPWARD_REFERRAL] = servers_upward_referral
                    elif not qname_sought.is_subdomain(soa_owner_name):
                        if qname_sought == qname:
                            if Status.RESPONSE_ERROR_BAD_SOA_FOR_NODATA not in self.noanswer_errors[(qname_sought, rdtype)]:
                                self.noanswer_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_BAD_SOA_FOR_NODATA] = set()
                            self.noanswer_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_BAD_SOA_FOR_NODATA].update(servers_clients)
                        else:
                            servers_affected = set()
                            for server_client in servers_clients:
                                for response in servers_clients[server_client]:
                                    if response.recursion_desired_and_available():
                                        servers_affected.add(server_client)
                            if servers_affected:
                                if Status.RESPONSE_ERROR_BAD_SOA_FOR_NODATA not in self.noanswer_errors[(qname_sought, rdtype)]:
                                    self.noanswer_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_BAD_SOA_FOR_NODATA] = set()
                                self.noanswer_errors[(qname_sought, rdtype)][Status.RESPONSE_ERROR_BAD_SOA_FOR_NODATA].update(servers_affected)
                        soa_owner_name = None

                    if soa_owner_name is None:
                        if qname_obj is not None:
                            soa_owner_name = qname_obj.zone.name
                        elif self.name.is_subdomain(qname_sought) and qname_sought.is_subdomain(self.zone.name):
                            soa_owner_name = self.zone.name
                        #XXX this is a hack and may not be robust
                        else:
                            soa_owner_name = qname_sought.parent()

                    for server_client in servers_clients:
                        for response in servers_clients[server_client]:
                            if not (qname_sought == qname or response.recursion_desired_and_available()):
                                continue
                            nsec_info_list = query.nsec_set_info_by_server[response]
                            status = None
                            for nsec_set_info in nsec_info_list:
                                if nsec_set_info.use_nsec3:
                                    status = Status.NSEC3StatusNoAnswer(qname_sought, query.rdtype, soa_owner_name, nsec_set_info.referral, nsec_set_info)
                                else:
                                    status = Status.NSECStatusNoAnswer(qname_sought, query.rdtype, soa_owner_name, nsec_set_info.referral, nsec_set_info)
                                    # possible empty non-terminal
                                    if status.validation_status != Status.STATUS_VALID:
                                        status = Status.NSECStatusEmptyNonTerminal(qname_sought, soa_owner_name, nsec_set_info)
                                if status.validation_status == Status.STATUS_VALID:
                                    break

                            if status is None:
                                if qname_obj is not None and qname_obj.zone.signed and response.dnssec_requested() and \
                                        (qname_sought == qname or response.recursion_desired_and_available()):
                                    if Status.RESPONSE_ERROR_MISSING_NSEC_FOR_NODATA not in self.noanswer_errors[(qname_sought,rdtype)]:
                                        self.noanswer_errors[(qname_sought,rdtype)][Status.RESPONSE_ERROR_MISSING_NSEC_FOR_NODATA] = set()
                                    self.noanswer_errors[(qname_sought,rdtype)][Status.RESPONSE_ERROR_MISSING_NSEC_FOR_NODATA].add(server_client)

                            elif status not in statuses:
                                statuses.append(status)
                                validation_status = status.validation_status
                                if validation_status not in self.noanswer_status_by_status:
                                    self.noanswer_status_by_status[validation_status] = set()
                                self.noanswer_status_by_status[validation_status].add((qname_sought, query.rdtype))

                if statuses:
                    if (qname_sought, rdtype) not in self.noanswer_status:
                        self.noanswer_status[(qname_sought, rdtype)] = set(statuses)

                errors = self.noanswer_errors[(qname_sought,rdtype)]
                warnings = self.noanswer_warnings[(qname_sought,rdtype)]
                for server_client in self.noanswer_servers_clients[(qname_sought, rdtype)]:
                    for response in self.noanswer_servers_clients[(qname_sought, rdtype)][server_client]:
                        if response.message.edns < 0:
                            #TODO be more specific about why EDNS isn't supported (e.g., timeout vs. SERVFAIL, etc.)
                            #if query.responses[server][client].effective_edns < 0:
                            #    pass
                            #else:
                            #    pass
                            if qname_obj is not None and qname_obj.zone.signed:
                                if Status.RESPONSE_ERROR_NO_EDNS_SUPPORT not in errors:
                                    errors[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT] = set()
                                errors[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT].add(server_client)
                            #TODO determine if the following is a warning or not
                            #else:
                            #    if Status.RESPONSE_ERROR_NO_EDNS_SUPPORT not in warnings:
                            #        warnings[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT] = set()
                            #    warnings[Status.RESPONSE_ERROR_NO_EDNS_SUPPORT].add(server_client)
                        elif not response.effective_edns_flags & dns.flags.DO:
                            if qname_obj is not None and qname_obj.zone.signed:
                                if Status.RESPONSE_ERROR_NO_DO_SUPPORT not in errors:
                                    errors[Status.RESPONSE_ERROR_NO_DO_SUPPORT] = set()
                                errors[Status.RESPONSE_ERROR_NO_DO_SUPPORT].add(server_client)
                            #TODO determine if the following is a warning or not
                            #else:
                            #    if Status.RESPONSE_ERROR_NO_DO_SUPPORT not in warnings:
                            #        warnings[Status.RESPONSE_ERROR_NO_DO_SUPPORT] = set()
                            #    warnings[Status.RESPONSE_ERROR_NO_DO_SUPPORT].add(server_client)
                        if not response.is_authoritative() and \
                                not response.recursion_desired_and_available():
                            if Status.RESPONSE_ERROR_NOT_AUTHORITATIVE not in errors:
                                errors[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE] = set()
                            errors[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE].add(server_client)

    def _populate_dnskey_status(self, trusted_keys):
        if (self.name, dns.rdatatype.DNSKEY) not in self.queries:
            return

        trusted_keys_rdata = set([k for z, k in trusted_keys if z == self.name])
        trusted_keys_existing = set()
        trusted_keys_not_self_signing = set()

        # buid a list of responsive servers
        servers_responsive = set()
        for query in self.queries[(self.name, dns.rdatatype.DNSKEY)].queries.values():
            servers_responsive.update([(server,client,query) for (server,client) in query.servers_with_valid_complete_response()])

        # any errors point to their own servers_clients value
        for dnskey in self.get_dnskeys():
            if dnskey.rdata in trusted_keys_rdata:
                trusted_keys_existing.add(dnskey)
                if dnskey not in self.ksks:
                    trusted_keys_not_self_signing.add(dnskey)
            if dnskey in self.revoked_keys and dnskey not in self.ksks:
                dnskey.errors[Status.DNSKEY_ERROR_REVOKED_NOT_SIGNING] = dnskey.servers_clients
            if not self.is_zone():
                dnskey.errors[Status.DNSKEY_ERROR_DNSKEY_NOT_AT_ZONE_APEX] = dnskey.servers_clients

            # if there were servers responsive for the query but that didn't return the dnskey
            servers_with_dnskey = set()
            for (server,client) in dnskey.servers_clients:
                for response in dnskey.servers_clients[(server,client)]:
                    servers_with_dnskey.add((server,client,response.query))
            servers_clients_without = servers_responsive.difference(servers_with_dnskey)
            if servers_clients_without:
                dnskey.errors[Status.DNSKEY_ERROR_DNSKEY_MISSING_FROM_SOME_SERVERS] = [(server,client) for (server,client,response) in servers_clients_without]

        if not trusted_keys_existing.difference(trusted_keys_not_self_signing):
            for dnskey in trusted_keys_not_self_signing:
                dnskey.errors[Status.DNSKEY_ERROR_TRUST_ANCHOR_NOT_SIGNING] = dnskey.servers_clients

    def serialize(self, d=None):
        if d is None:
            d = collections.OrderedDict()

        name_str = self.name.canonicalize().to_text()
        if name_str in d:
            return

        if self.parent is not None:
            self.parent.serialize(d)
        if self.dlv_parent is not None:
            self.dlv_parent.serialize(d)

        clients_ipv4 = list(self.clients_ipv4)
        clients_ipv4.sort()
        clients_ipv6 = list(self.clients_ipv6)
        clients_ipv6.sort()

        d[name_str] = collections.OrderedDict()
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
            if self.referral_rdtype is not None:
                d[name_str]['referral_rdtype'] = dns.rdatatype.to_text(self.referral_rdtype)
            d[name_str]['explicit_delegation'] = self.explicit_delegation
            if self.nxdomain_name is not None:
                d[name_str]['nxdomain_name'] = self.nxdomain_name.to_text()
                d[name_str]['nxdomain_rdtype'] = dns.rdatatype.to_text(self.nxdomain_rdtype)
            if self.nxrrset_name is not None:
                d[name_str]['nxrrset_name'] = self.nxrrset_name.to_text()
                d[name_str]['nxrrset_rdtype'] = dns.rdatatype.to_text(self.nxrrset_rdtype)

        self._serialize_related(d[name_str])
        self._serialize_dependencies(d)

    def _serialize_related(self, d):
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

        d['queries'] = collections.OrderedDict()
        query_keys = self.queries.keys()
        query_keys.sort()
        for (qname, rdtype) in query_keys:
            qname_type_str = '%s/%s/%s' % (qname.canonicalize().to_text(), dns.rdataclass.to_text(dns.rdataclass.IN), dns.rdatatype.to_text(rdtype))
            d['queries'][qname_type_str] = []
            for query in self.queries[(qname, rdtype)].queries.values():
                d['queries'][qname_type_str].append(query.serialize())

    def _serialize_dependencies(self, d):
        if self.stub:
            return

        for cname, cname_obj in self.cname_targets.items():
            cname_obj.serialize(d)
        for dname, dname_obj in self.dname_targets.items():
            dname_obj.serialize(d)
        for signer, signer_obj in self.external_signers.items():
            signer_obj.serialize(d)
        for target, ns_obj in self.ns_dependencies.items():
            if ns_obj is not None:
                ns_obj.serialize(d)

    def _serialize_rrset_info(self, rrset_info, consolidate_clients=False, show_servers=True, loglevel=logging.DEBUG):
        d = collections.OrderedDict()

        if loglevel <= logging.INFO or (self.rrset_warnings[rrset_info] and loglevel <= logging.WARNING) or (self.rrset_errors[rrset_info] and loglevel <= logging.ERROR):
            d['description'] = unicode(rrset_info)

        if loglevel <= logging.DEBUG:
            d['rrset'] = rrset_info.serialize(include_rrsig_info=False, show_servers=show_servers, consolidate_clients=consolidate_clients)

        if self.rrsig_status[rrset_info]:
            d['rrsig'] = []
            rrsigs = self.rrsig_status[rrset_info].keys()
            rrsigs.sort()
            for rrsig in rrsigs:
                dnskeys = self.rrsig_status[rrset_info][rrsig].keys()
                dnskeys.sort()
                for dnskey in dnskeys:
                    rrsig_status = self.rrsig_status[rrset_info][rrsig][dnskey]
                    rrsig_serialized = rrsig_status.serialize(consolidate_clients=consolidate_clients, loglevel=loglevel)
                    if rrsig_serialized:
                        d['rrsig'].append(rrsig_serialized)
            if not d['rrsig']:
                del d['rrsig']

        if rrset_info in self.dname_status:
            d['dname'] = []
            for dname_status in self.dname_status[rrset_info]:
                dname_serialized = dname_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
                if dname_serialized:
                    d['dname'].append(dname_serialized)
            if not d['dname']:
                del d['dname']

        if rrset_info.wildcard_info:
            d['wildcard_proof'] = collections.OrderedDict()
            wildcard_names = rrset_info.wildcard_info.keys()
            wildcard_names.sort()
            for wildcard_name in wildcard_names:
                wildcard_name_str = wildcard_name.canonicalize().to_text()
                d['wildcard_proof'][wildcard_name_str] = []
                if rrset_info.rrset.name in self.wildcard_status and wildcard_name in self.wildcard_status[rrset_info.rrset.name]:
                    for nsec_status in self.wildcard_status[rrset_info.rrset.name][wildcard_name]:
                        nsec_serialized = nsec_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
                        if nsec_serialized:
                            d['wildcard_proof'][wildcard_name_str].append(nsec_serialized)
                if not d['wildcard_proof'][wildcard_name_str]:
                    del d['wildcard_proof'][wildcard_name_str]
            if not d['wildcard_proof']:
                del d['wildcard_proof']

        if self.rrset_warnings[rrset_info] and loglevel <= logging.WARNING:
            d['warnings'] = collections.OrderedDict()
            warnings = self.rrset_warnings[rrset_info].keys()
            warnings.sort()
            for warning in warnings:
                servers = tuple_to_dict(self.rrset_warnings[rrset_info][warning])
                if consolidate_clients:
                    servers = list(servers)
                    servers.sort()
                d['warnings'][Status.response_error_mapping[warning]] = servers

        if self.rrset_errors[rrset_info] and loglevel <= logging.ERROR:
            d['errors'] = collections.OrderedDict()
            errors = self.rrset_errors[rrset_info].keys()
            errors.sort()
            for error in errors:
                servers = tuple_to_dict(self.rrset_errors[rrset_info][error])
                if consolidate_clients:
                    servers = list(servers)
                    servers.sort()
                d['errors'][Status.response_error_mapping[error]] = servers

        return d

    def serialize_status(self, d=None, is_dlv=False, loglevel=logging.DEBUG):
        if d is None:
            d = collections.OrderedDict()

        if self.stub:
            return d

        name_str = self.name.canonicalize().to_text()
        if name_str in d:
            return d

        if self.parent is not None:
            self.parent.serialize_status(d, loglevel=loglevel)
        if self.dlv_parent is not None:
            self.dlv_parent.serialize_status(d, is_dlv=True, loglevel=loglevel)

        consolidate_clients = self.single_client()

        d[name_str] = collections.OrderedDict()
        if loglevel <= logging.INFO or self.status not in (Status.NAME_STATUS_YXDOMAIN, Status.NAME_STATUS_NXDOMAIN):
            d[name_str]['status'] = Status.name_status_mapping[self.status]
        d[name_str]['answer'] = collections.OrderedDict()

        query_keys = self.queries.keys()
        query_keys.sort()
        for (qname, rdtype) in query_keys:
            query = self.queries[(qname, rdtype)]
            qname_type_str = '%s/%s/%s' % (qname.canonicalize().to_text(), dns.rdataclass.to_text(dns.rdataclass.IN), dns.rdatatype.to_text(rdtype))
            d[name_str]['answer'][qname_type_str] = []
            #TODO sort by CNAME dependencies, beginning with question
            for rrset_info in query.rrset_answer_info:
                # only look at qname
                if rrset_info.rrset.name == qname:
                    rrset_serialized = self._serialize_rrset_info(rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
                    if rrset_serialized:
                        d[name_str]['answer'][qname_type_str].append(rrset_serialized)
            if not d[name_str]['answer'][qname_type_str]:
                del d[name_str]['answer'][qname_type_str]
        if not d[name_str]['answer']:
            del d[name_str]['answer']

        if (self.name, dns.rdatatype.DNSKEY) in self.queries:
            d[name_str]['dnskeys'] = []
            for dnskey in self.get_dnskeys():
                dnskey_serialized = dnskey.serialize(consolidate_clients=consolidate_clients, loglevel=loglevel)
                if dnskey_serialized:
                    d[name_str]['dnskeys'].append(dnskey_serialized)
            if not d[name_str]['dnskeys']:
                del d[name_str]['dnskeys']

        if self.is_zone():
            if self.parent is not None and not is_dlv:
                d[name_str]['delegation'] = collections.OrderedDict()
                if (self.name, dns.rdatatype.DS) in self.queries:
                    if self.ds_status_by_ds[dns.rdatatype.DS]:
                        d[name_str]['delegation']['ds'] = []
                        dss = self.ds_status_by_ds[dns.rdatatype.DS].keys()
                        dss.sort()
                        for ds in dss:
                            dnskeys = self.ds_status_by_ds[dns.rdatatype.DS][ds].keys()
                            dnskeys.sort()
                            for dnskey in dnskeys:
                                ds_status = self.ds_status_by_ds[dns.rdatatype.DS][ds][dnskey]
                                ds_serialized = ds_status.serialize(consolidate_clients=consolidate_clients, loglevel=loglevel)
                                if ds_serialized:
                                    d[name_str]['delegation']['ds'].append(ds_serialized)
                        if not d[name_str]['delegation']['ds']:
                            del d[name_str]['delegation']['ds']

                    if self.noanswer_status.get((self.name, dns.rdatatype.DS), []):
                        d[name_str]['delegation']['insecurity_proof'] = []
                        for nsec_status in self.noanswer_status[(self.name, dns.rdatatype.DS)]:
                            nsec_serialized = nsec_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
                            if nsec_serialized:
                                d[name_str]['delegation']['insecurity_proof'].append(nsec_serialized)
                        if not d[name_str]['delegation']['insecurity_proof']:
                            del d[name_str]['delegation']['insecurity_proof']

                if loglevel <= logging.INFO or self.delegation_status[dns.rdatatype.DS] not in (Status.DELEGATION_STATUS_SECURE, Status.DELEGATION_STATUS_INSECURE):
                    d[name_str]['delegation']['status'] = Status.delegation_status_mapping[self.delegation_status[dns.rdatatype.DS]]

                if self.delegation_warnings[dns.rdatatype.DS] and loglevel <= logging.WARNING:
                    d[name_str]['delegation']['warnings'] = collections.OrderedDict()
                    warnings = self.delegation_warnings[dns.rdatatype.DS].keys()
                    warnings.sort()
                    for warning in warnings:
                        servers = tuple_to_dict(self.delegation_warnings[dns.rdatatype.DS][warning])
                        if consolidate_clients:
                            servers = list(servers)
                            servers.sort()
                        d[name_str]['delegation']['warnings'][Status.delegation_error_mapping[warning]] = servers

                if self.delegation_errors[dns.rdatatype.DS] and loglevel <= logging.ERROR:
                    d[name_str]['delegation']['errors'] = collections.OrderedDict()
                    errors = self.delegation_errors[dns.rdatatype.DS].keys()
                    errors.sort()
                    for error in errors:
                        servers = tuple_to_dict(self.delegation_errors[dns.rdatatype.DS][error])
                        if consolidate_clients:
                            servers = list(servers)
                            servers.sort()
                        d[name_str]['delegation']['errors'][Status.delegation_error_mapping[error]] = servers

                if not d[name_str]['delegation']:
                    del d[name_str]['delegation']

            if self.dlv_parent is not None:
                d[name_str]['dlv'] = collections.OrderedDict()
                if (self.dlv_name, dns.rdatatype.DLV) in self.queries:
                    if self.ds_status_by_ds[dns.rdatatype.DLV]:
                        d[name_str]['dlv']['ds'] = []
                        dss = self.ds_status_by_ds[dns.rdatatype.DLV].keys()
                        dss.sort()
                        for ds in dss:
                            dnskeys = self.ds_status_by_ds[dns.rdatatype.DLV][ds].keys()
                            dnskeys.sort()
                            for dnskey in dnskeys:
                                ds_status = self.ds_status_by_ds[dns.rdatatype.DLV][ds][dnskey]
                                ds_serialized = ds_status.serialize(consolidate_clients=consolidate_clients, loglevel=loglevel)
                                if ds_serialized:
                                    d[name_str]['dlv']['ds'].append(ds_serialized)
                        if not d[name_str]['dlv']['ds']:
                            del d[name_str]['dlv']['ds']

                    if self.noanswer_status.get((self.dlv_name, dns.rdatatype.DLV), []):
                        d[name_str]['dlv']['insecurity_proof'] = []
                        for nsec_status in self.noanswer_status[(self.name, dns.rdatatype.DLV)]:
                            nsec_serialized = nsec_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
                            if nsec_serialized:
                                d[name_str]['dlv']['insecurity_proof'].append(nsec_serialized)
                        if not d[name_str]['dlv']['insecurity_proof']:
                            del d[name_str]['dlv']['insecurity_proof']

                if loglevel <= logging.INFO or self.delegation_status[dns.rdatatype.DLV] not in (Status.DELEGATION_STATUS_SECURE, Status.DELEGATION_STATUS_INSECURE):
                    d[name_str]['dlv']['status'] = Status.delegation_status_mapping[self.delegation_status[dns.rdatatype.DLV]]

                if self.delegation_warnings[dns.rdatatype.DLV] and loglevel <= logging.WARNING:
                    d[name_str]['dlv']['warnings'] = collections.OrderedDict()
                    warnings = self.delegation_warnings[dns.rdatatype.DLV].keys()
                    warnings.sort()
                    for warning in warnings:
                        servers = tuple_to_dict(self.delegation_warnings[dns.rdatatype.DLV][warning])
                        if consolidate_clients:
                            servers = list(servers)
                            servers.sort()
                        d[name_str]['dlv']['warnings'][Status.delegation_error_mapping[warning]] = servers

                if self.delegation_errors[dns.rdatatype.DLV] and loglevel <= logging.ERROR:
                    d[name_str]['dlv']['errors'] = collections.OrderedDict()
                    errors = self.delegation_errors[dns.rdatatype.DLV].keys()
                    errors.sort()
                    for error in errors:
                        servers = tuple_to_dict(self.delegation_errors[dns.rdatatype.DLV][error])
                        if consolidate_clients:
                            servers = list(servers)
                            servers.sort()
                        d[name_str]['dlv']['errors'][Status.delegation_error_mapping[error]] = servers

                if not d[name_str]['dlv']:
                    del d[name_str]['dlv']

        if self.nxdomain_servers_clients:
            d[name_str]['nxdomain'] = collections.OrderedDict()
            query_keys = self.nxdomain_servers_clients.keys()
            query_keys.sort()
            for (qname, rdtype) in query_keys:
                qname_type_str = '%s/%s/%s' % (qname.canonicalize().to_text(), dns.rdataclass.to_text(dns.rdataclass.IN), dns.rdatatype.to_text(rdtype))
                d[name_str]['nxdomain'][qname_type_str] = collections.OrderedDict()
                if (qname, rdtype) in self.nxdomain_status:
                    d[name_str]['nxdomain'][qname_type_str]['proof'] = []
                    for nsec_status in self.nxdomain_status[(qname, rdtype)]:
                        nsec_serialized = nsec_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
                        if nsec_serialized:
                            d[name_str]['nxdomain'][qname_type_str]['proof'].append(nsec_serialized)
                    if not d[name_str]['nxdomain'][qname_type_str]['proof']:
                        del d[name_str]['nxdomain'][qname_type_str]['proof']

                if loglevel <= logging.DEBUG or \
                        (self.nxdomain_warnings[(qname, rdtype)] and loglevel <= logging.WARNING) or \
                        (self.nxdomain_errors[(qname, rdtype)] and loglevel <= logging.ERROR):
                    servers = tuple_to_dict(self.nxdomain_servers_clients[(qname, rdtype)])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    d[name_str]['nxdomain'][qname_type_str]['servers'] = servers

                if self.nxdomain_warnings[(qname, rdtype)] and loglevel <= logging.WARNING:
                    d[name_str]['nxdomain'][qname_type_str]['warnings'] = collections.OrderedDict()
                    warnings = self.nxdomain_warnings[(qname, rdtype)].keys()
                    warnings.sort()
                    for warning in warnings:
                        servers = tuple_to_dict(self.nxdomain_warnings[(qname, rdtype)][warning])
                        if consolidate_clients:
                            servers = list(servers)
                            servers.sort()
                        d[name_str]['nxdomain'][qname_type_str]['warnings'][Status.response_error_mapping[warning]] = servers

                if self.nxdomain_errors[(qname, rdtype)] and loglevel <= logging.ERROR:
                    d[name_str]['nxdomain'][qname_type_str]['errors'] = collections.OrderedDict()
                    errors = self.nxdomain_errors[(qname, rdtype)].keys()
                    errors.sort()
                    for error in errors:
                        servers = tuple_to_dict(self.nxdomain_errors[(qname, rdtype)][error])
                        if consolidate_clients:
                            servers = list(servers)
                            servers.sort()
                        d[name_str]['nxdomain'][qname_type_str]['errors'][Status.response_error_mapping[error]] = servers

                if not d[name_str]['nxdomain'][qname_type_str]:
                    del d[name_str]['nxdomain'][qname_type_str]
            if not d[name_str]['nxdomain']:
                del d[name_str]['nxdomain']

        if self.noanswer_servers_clients:
            d[name_str]['nodata'] = collections.OrderedDict()
            query_keys = self.noanswer_servers_clients.keys()
            query_keys.sort()
            for (qname, rdtype) in query_keys:
                qname_type_str = '%s/%s/%s' % (qname.canonicalize().to_text(), dns.rdataclass.to_text(dns.rdataclass.IN), dns.rdatatype.to_text(rdtype))
                d[name_str]['nodata'][qname_type_str] = collections.OrderedDict()
                if (qname, rdtype) in self.noanswer_status:
                    d[name_str]['nodata'][qname_type_str]['proof'] = []
                    for nsec_status in self.noanswer_status[(qname, rdtype)]:
                        nsec_serialized = nsec_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
                        if nsec_serialized:
                            d[name_str]['nodata'][qname_type_str]['proof'].append(nsec_serialized)
                    if not d[name_str]['nodata'][qname_type_str]['proof']:
                        del d[name_str]['nodata'][qname_type_str]['proof']

                if loglevel <= logging.DEBUG or \
                        (self.noanswer_warnings[(qname, rdtype)] and loglevel <= logging.WARNING) or \
                        (self.noanswer_errors[(qname, rdtype)] and loglevel <= logging.ERROR):
                    servers = tuple_to_dict(self.noanswer_servers_clients[(qname, rdtype)])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    d[name_str]['nodata'][qname_type_str]['servers'] = servers

                if self.noanswer_warnings[(qname, rdtype)] and loglevel <= logging.WARNING:
                    d[name_str]['nodata'][qname_type_str]['warnings'] = collections.OrderedDict()
                    warnings = self.noanswer_warnings[(qname, rdtype)].keys()
                    warnings.sort()
                    for warning in warnings:
                        servers = tuple_to_dict(self.noanswer_warnings[(qname,rdtype)][warning])
                        if consolidate_clients:
                            servers = list(servers)
                            servers.sort()
                        d[name_str]['nodata'][qname_type_str]['warnings'][Status.response_error_mapping[warning]] = servers

                if self.noanswer_errors[(qname, rdtype)] and loglevel <= logging.ERROR:
                    d[name_str]['nodata'][qname_type_str]['errors'] = collections.OrderedDict()
                    errors = self.noanswer_errors[(qname, rdtype)].keys()
                    errors.sort()
                    for error in errors:
                        servers = tuple_to_dict(self.noanswer_errors[(qname,rdtype)][error])
                        if consolidate_clients:
                            servers = list(servers)
                            servers.sort()
                        d[name_str]['nodata'][qname_type_str]['errors'][Status.response_error_mapping[error]] = servers

                if not d[name_str]['nodata'][qname_type_str]:
                    del d[name_str]['nodata'][qname_type_str]
            if not d[name_str]['nodata']:
                del d[name_str]['nodata']

        d[name_str]['response_errors'] = collections.OrderedDict()
        query_keys = self.response_errors_rcode.keys()
        query_keys.sort()
        for (qname, rdtype) in query_keys:
            qname_type_str = '%s/%s/%s' % (qname.canonicalize().to_text(), dns.rdataclass.to_text(dns.rdataclass.IN), dns.rdatatype.to_text(rdtype))
            d[name_str]['response_errors'][qname_type_str] = []

            rcodes = self.response_errors_rcode[(qname, rdtype)].keys()
            rcodes.sort()
            for rcode in rcodes:
                val = collections.OrderedDict()
                val['error'] = 'BAD_RCODE'
                val['description'] = dns.rcode.to_text(rcode)
                servers = tuple_to_dict(self.response_errors_rcode[(qname, rdtype)][rcode])
                if consolidate_clients:
                    servers = list(servers)
                    servers.sort()
                val['servers'] = servers
                d[name_str]['response_errors'][qname_type_str].append(val)

            errors_errno = self.response_errors[(qname, rdtype)].keys()
            errors_errno.sort()
            for error, errno1 in errors_errno:
                val = collections.OrderedDict()
                val['error'] = Q.response_errors[error]
                if errno1:
                    try:
                        val['description'] = errno.errorcode[errno1]
                    except KeyError:
                        #XXX find a good cross-platform way of handling this
                        pass
                servers = tuple_to_dict(self.response_errors[(qname, rdtype)][(error, errno1)])
                if consolidate_clients:
                    servers = list(servers)
                    servers.sort()
                val['servers'] = servers
                d[name_str]['response_errors'][qname_type_str].append(val)

            if not d[name_str]['response_errors'][qname_type_str]:
                del d[name_str]['response_errors'][qname_type_str]
        if not d[name_str]['response_errors']:
            del d[name_str]['response_errors']

        if not d[name_str]:
            del d[name_str]

        for cname, cname_obj in self.cname_targets.items():
            cname_obj.serialize_status(d, loglevel=loglevel)
        for dname, dname_obj in self.dname_targets.items():
            dname_obj.serialize_status(d, loglevel=loglevel)
        for signer, signer_obj in self.external_signers.items():
            signer_obj.serialize_status(d, loglevel=loglevel)
        for target, ns_obj in self.ns_dependencies.items():
            if ns_obj is not None:
                ns_obj.serialize_status(d, loglevel=loglevel)

        return d

    @classmethod
    def deserialize(cls, name, d1, cache=None):
        if cache is None:
            cache = {}

        if name in cache:
            return cache[name]

        name_str = name.canonicalize().to_text()
        d = d1[name_str]
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

        _logger.info('Loading %s' % fmt.humanize_name(name))

        cache[name] = a = cls(name, stub=stub)
        a.parent = parent
        if dlv_parent is not None:
            a.dlv_parent = dlv_parent
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
                    self.add_auth_ns_ip_mappings((dns.name.from_text(target), addr))

        if self.stub:
            return

        # import delegation NS queries first
        delegation_types = set([dns.rdatatype.NS])
        if self.referral_rdtype is not None:
            delegation_types.add(self.referral_rdtype)
        for rdtype in delegation_types:
            query_str = '%s/%s/%s' % (self.name.canonicalize().to_text(), dns.rdataclass.to_text(dns.rdataclass.IN), dns.rdatatype.to_text(rdtype))
            if query_str in d['queries']:
                _logger.debug('Importing %s/%s...' % (fmt.humanize_name(self.name), dns.rdatatype.to_text(rdtype)))
                for query in d['queries'][query_str]:
                    self.add_query(Q.DNSQuery.deserialize(query))
        # set the NS dependencies for the name
        if self.is_zone():
            self.set_ns_dependencies()

        for query_str in d['queries']:
            qname, rdclass, rdtype = query_str.split('/')
            qname = dns.name.from_text(qname)
            rdtype = dns.rdatatype.from_text(rdtype)
            if rdtype in delegation_types:
                continue
            if (qname, rdtype) == (self.nxdomain_name, self.nxdomain_rdtype):
                extra = ' (NXDOMAIN)'
            elif (qname, rdtype) == (self.nxrrset_name, self.nxrrset_rdtype):
                extra = ' (No data)'
            else:
                extra = ''
            _logger.debug('Importing %s/%s%s...' % (fmt.humanize_name(qname), dns.rdatatype.to_text(rdtype), extra))
            for query in d['queries'][query_str]:
                self.add_query(Q.DNSQuery.deserialize(query))

    def _deserialize_dependencies(self, d, cache):
        if self.stub:
            return

        for cname in self.cname_targets:
            self.cname_targets[cname] = self.__class__.deserialize(cname, d, cache=cache)
        for dname in self.dname_targets:
            self.dname_targets[dname] = self.__class__.deserialize(dname, d, cache=cache)
        for signer in self.external_signers:
            self.external_signers[signer] = self.__class__.deserialize(signer, d, cache=cache)
        for target in self.ns_dependencies:
            if target.canonicalize().to_text() in d:
                self.ns_dependencies[target] = self.__class__.deserialize(target, d, cache=cache)

class ActiveDomainNameAnalysis(DomainNameAnalysis):
    def __init__(self, *args, **kwargs):
        super(ActiveDomainNameAnalysis, self).__init__(*args, **kwargs)
        self.complete = threading.Event()

class Analyst(object):
    analysis_model = ActiveDomainNameAnalysis
    diagnostic_query = Q.DiagnosticQuery
    tcp_diagnostic_query = Q.TCPDiagnosticQuery
    pmtu_diagnostic_query = Q.PMTUDiagnosticQuery
    truncation_diagnostic_query = Q.TruncationDiagnosticQuery
    allow_loopback_query = False
    allow_private_query = False
    qname_only = True

    clone_attrnames = ['dlv_domain', 'client_ipv4', 'client_ipv6', 'logger', 'ceiling', 'follow_ns', 'explicit_delegations', 'analysis_cache', 'analysis_cache_lock']

    def __init__(self, name, dlv_domain=None, client_ipv4=None, client_ipv6=None, logger=_logger, ceiling=None, force_dnskey=False,
             follow_ns=False, trace=None, explicit_delegations=None, analysis_cache=None, analysis_cache_lock=None):

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

        self.force_dnskey = force_dnskey
        self.follow_ns = follow_ns

        if trace is None:
            self.trace = []
        else:
            self.trace = trace
        if explicit_delegations is None:
            self.explicit_delegations = {}
        else:
            self.explicit_delegations = explicit_delegations
        if analysis_cache is None:
            self.analysis_cache = {}
        else:
            self.analysis_cache = analysis_cache
        if analysis_cache_lock is None:
            self.analysis_cache_lock = threading.Lock()
        else:
            self.analysis_cache_lock = analysis_cache_lock

    def _detect_ceiling(self, ceiling):
        if ceiling == dns.name.root or ceiling is None:
            return ceiling, None

        # if there is a celing, but the name is not a subdomain
        # of the celing, then use the name itself as a base
        if not self.name.is_subdomain(ceiling):
            ceiling = self.name

        try:
            ans = _resolver.query(ceiling, dns.rdatatype.NS, dns.rdataclass.IN)
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
            name = self.trace[i][0]
        return name

    def _ask_ptr_queries(self, name):
        '''Return True if PTR queries should be asked for this name, as guessed by
        the nature of the name (particularly whether or not it is in the arpa tree)
        and the nature of the name (if any) that invoked the query as a dependency.'''

        orig_name = self._original_alias_of_cname()
        if orig_name.is_subdomain(IP6_ARPA_NAME):
            if name.is_subdomain(IP6_ARPA_NAME) and len(name) == 35:
                return True
            elif self.name == name:
                return True
        elif orig_name.is_subdomain(INADDR_ARPA_NAME):
            if name.is_subdomain(INADDR_ARPA_NAME) and len(name) == 7:
                return True
            elif self.name == name:
                return True
        return False

    def _ask_other_queries(self, name):
        '''Return True if queries other than A, PTR, NS, and SOA (e.g., MX,
        AAAA, TXT) should be asked, based on the nature of the name.'''

        if name.is_subdomain(IP6_ARPA_NAME) or name.is_subdomain(INADDR_ARPA_NAME):
            return False
        if len(name) < 3:
            return False
        if self.qname_only and name != self.name:
            return False
        if self.dlv_domain == self.name:
            return False
        return True

    def _is_dkim(self, name):
        '''Return True if the name is a DKIM name.'''

        return '_domainkey' in name

    def _filter_servers(self, servers):
        if self.client_ipv6 is None:
            servers = filter(lambda x: ':' not in x, servers)
        elif self.client_ipv4 is None:
            servers = filter(lambda x: ':' in x, servers)
        if not self.allow_loopback_query:
            servers = filter(lambda x: not LOOPBACK_IP_RE.match(x), servers)
        if not self.allow_private_query:
            servers = filter(lambda x: not RFC_1918_RE.match(x) and not LINK_LOCAL_RE.match(x) and not UNIQ_LOCAL_RE.match(x), servers)
        return servers

    def _get_name_for_analysis(self, name, stub=False, lock=True):
        with self.analysis_cache_lock:
            try:
                name_obj = self.analysis_cache[name]
            except KeyError:
                if lock:
                    name_obj = self.analysis_cache[name] = self.analysis_model(name, stub=stub)
                    return name_obj
                # if not locking, then return None
                else:
                    return None

        # if there is a complete event, then wait on it
        if hasattr(name_obj, 'complete'):
            name_obj.complete.wait()
        # otherwise, loop and wait for analysis to be completed
        else:
            while name_obj.analysis_end is None:
                time.sleep(1)
                name_obj = self.analysis_cache[name]
        #TODO re-do analyses if force_dnskey is True and dnskey hasn't been queried
        #TODO re-do anaysis if not stub requested but cache is stub?
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
            a = self.__class__(self.dlv_domain, force_dnskey=False, **kwargs)
            a.analyze()

    def _finalize_analysis_proper(self, name_obj):
        if hasattr(name_obj, 'complete'):
            name_obj.complete.set()

    def _finalize_analysis_all(self, name_obj):
        pass

    def _analyze_stub(self, name):
        name_obj = self._get_name_for_analysis(name, stub=True)
        if name_obj.analysis_end is not None:
            return name_obj

        try:
            self.logger.info('Analyzing %s (stub)' % fmt.humanize_name(name))

            name_obj.analysis_start = datetime.datetime.now(fmt.utc).replace(microsecond=0)
            try:
                ans = _resolver.query(name, dns.rdatatype.NS, dns.rdataclass.IN)
                
                # resolve every name in the NS RRset
                query_tuples = []
                for rr in ans.rrset:
                    query_tuples.extend([(rr.target, dns.rdatatype.A, dns.rdataclass.IN), (rr.target, dns.rdatatype.AAAA, dns.rdataclass.IN)])
                answer_map = _resolver.query_multiple(*query_tuples)
                for query_tuple in answer_map:
                    a = answer_map[query_tuple]
                    if isinstance(a, Resolver.DNSAnswer):
                        for a_rr in a.rrset:
                            name_obj.add_auth_ns_ip_mappings((query_tuple[0], a_rr.to_text()))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                name_obj.parent = self._analyze_stub(name.parent()).zone
            except dns.exception.DNSException:
                name_obj.parent = self._analyze_stub(name.parent()).zone

            name_obj.analysis_end = datetime.datetime.now(fmt.utc).replace(microsecond=0)

        finally:
            self._finalize_analysis_proper(name_obj)
            self._finalize_analysis_all(name_obj)

        return name_obj

    def _analyze(self, name):
        '''Analyze a DNS name to learn about its health using introspective
        queries.'''

        # determine immediately if we need to do anything
        name_obj = self._get_name_for_analysis(name, lock=False)
        if name_obj is not None and name_obj.analysis_end is not None:
            return name_obj

        # only analyze the parent if the name is not root and if there is no
        # ceiling or the name is a subdomain of the ceiling
        if name == dns.name.root:
            parent_obj = None
        elif name in self.explicit_delegations:
            parent_obj = None
        elif name == self.ceiling:
            parent_obj = self._analyze_stub(name.parent())
        else:
            parent_obj = self._analyze(name.parent())

        if parent_obj is not None:
            # for zones other than the root assign parent_obj to the zone apex,
            # rather than the simply the domain formed by dropping its lower
            # leftmost label
            parent_obj = parent_obj.zone

        # retrieve the dlv
        if self.dlv_domain is not None and self.name != self.dlv_domain:
            dlv_parent_obj = self.analysis_cache[self.dlv_domain]
        else:
            dlv_parent_obj = None
        
        # get or create the name
        name_obj = self._get_name_for_analysis(name)
        if name_obj.analysis_end is not None:
            return name_obj

        try:
            try:
                name_obj.parent = parent_obj
                name_obj.dlv_parent = dlv_parent_obj

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

            finally:
                self._finalize_analysis_proper(name_obj)

            # analyze dependencies
            self._analyze_dependencies(name_obj)

        finally:
            self._finalize_analysis_all(name_obj)

        return name_obj

    def _analyze_name(self, name_obj):
        self.logger.info('Analyzing %s' % fmt.humanize_name(name_obj.name))

        # analyze delegation, and return if name doesn't exist
        yxdomain = self._analyze_delegation(name_obj)
        if not yxdomain:
            return

        # set the NS dependencies for the name
        if name_obj.is_zone():
            name_obj.set_ns_dependencies()

        if not name_obj.zone._all_servers_queried:
            servers = name_obj.zone.get_auth_or_designated_servers()
        else:
            servers = name_obj.zone.get_responsive_auth_or_designated_servers()
        servers = self._filter_servers(servers)
        exclude_no_answer = set()
        queries = {}

        if servers:
            if self._ask_other_queries(name_obj.name):
                # A query might already have been performed during delegation
                # analysis
                if (name_obj.name, dns.rdatatype.A) not in name_obj.queries:
                    self.logger.debug('Preparing query %s/A...' % fmt.humanize_name(name_obj.name))
                    queries[(name_obj.name, dns.rdatatype.A)] = self.diagnostic_query(name_obj.name, dns.rdatatype.A, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)
                self.logger.debug('Preparing query %s/AAAA...' % fmt.humanize_name(name_obj.name))
                queries[(name_obj.name, dns.rdatatype.AAAA)] = self.diagnostic_query(name_obj.name, dns.rdatatype.AAAA, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)
                if name_obj.is_zone():
                    # A query might already have been performed during
                    # delegation analysis
                    if (name_obj.name, dns.rdatatype.NS) not in name_obj.queries:
                        self.logger.debug('Preparing query %s/NS...' % fmt.humanize_name(name_obj.name))
                        queries[(name_obj.name, dns.rdatatype.NS)] = self.diagnostic_query(name_obj.name, dns.rdatatype.NS, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)
                    self.logger.debug('Preparing query %s/MX...' % fmt.humanize_name(name_obj.name))
                    # note that we use a PMTU diagnostic query here, to simultaneously test PMTU
                    queries[(name_obj.name, dns.rdatatype.MX)] = self.pmtu_diagnostic_query(name_obj.name, dns.rdatatype.MX, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)
                    # we also do a query with small UDP payload to elicit and test a truncated response
                    queries[(name_obj.name, -dns.rdatatype.MX)] = self.truncation_diagnostic_query(name_obj.name, dns.rdatatype.MX, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)
                if name_obj.is_zone() or self._is_dkim(name_obj.name):
                    self.logger.debug('Preparing query %s/TXT...' % fmt.humanize_name(name_obj.name))
                    queries[(name_obj.name, dns.rdatatype.TXT)] = self.diagnostic_query(name_obj.name, dns.rdatatype.TXT, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)

        if name_obj.is_zone() or \
                (self.force_dnskey and self.name == name_obj.name):

            if servers:
                if (not self.qname_only) or self.name == name_obj.name:
                    if self.dlv_domain != self.name:
                        self.logger.debug('Preparing query %s/SOA...' % fmt.humanize_name(name_obj.name))
                        # note that we use TCP diagnostic query here, to simultaneously test TCP connectivity
                        # (the query falls back to UDP in case there are issues)
                        queries[(name_obj.name, dns.rdatatype.SOA)] = self.tcp_diagnostic_query(name_obj.name, dns.rdatatype.SOA, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)

                self.logger.debug('Preparing query %s/DNSKEY...' % fmt.humanize_name(name_obj.name))
                # note that we use a PMTU diagnostic query here, to simultaneously test PMTU
                queries[(name_obj.name, dns.rdatatype.DNSKEY)] = self.pmtu_diagnostic_query(name_obj.name, dns.rdatatype.DNSKEY, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)
                # we also do a query with small UDP payload to elicit and test a truncated response
                queries[(name_obj.name, -dns.rdatatype.DNSKEY)] = self.truncation_diagnostic_query(name_obj.name, dns.rdatatype.DNSKEY, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)

            if name_obj.parent is not None:
                if not name_obj.parent._all_servers_queried:
                    parent_servers = name_obj.zone.parent.get_auth_or_designated_servers()
                else:
                    parent_servers = name_obj.zone.parent.get_responsive_auth_or_designated_servers()
                parent_servers = self._filter_servers(parent_servers)

                self.logger.debug('Preparing query %s/DS...' % fmt.humanize_name(name_obj.name))
                queries[(name_obj.name, dns.rdatatype.DS)] = self.diagnostic_query(name_obj.name, dns.rdatatype.DS, dns.rdataclass.IN, parent_servers, self.client_ipv4, self.client_ipv6)

                if name_obj.dlv_parent is not None and self.dlv_domain != self.name:
                    dlv_servers = name_obj.dlv_parent.get_responsive_auth_or_designated_servers()
                    dlv_servers = self._filter_servers(dlv_servers)
                    dlv_name = name_obj.dlv_name
                    if dlv_servers:
                        self.logger.debug('Preparing query %s/DLV...' % fmt.humanize_name(dlv_name))
                        queries[(dlv_name, dns.rdatatype.DLV)] = self.diagnostic_query(dlv_name, dns.rdatatype.DLV, dns.rdataclass.IN, dlv_servers, self.client_ipv4, self.client_ipv6)
                        exclude_no_answer.add((dlv_name, dns.rdatatype.DLV))

        if servers and self.dlv_domain != self.name:
            if name_obj.is_zone() and \
                    ((not self.qname_only) or name_obj.name == self.name):
                self._set_negative_queries(name_obj)
                if name_obj.nxdomain_name is not None:
                    self.logger.debug('Preparing query %s/%s (NXDOMAIN)...' % (fmt.humanize_name(name_obj.nxdomain_name), dns.rdatatype.to_text(name_obj.nxdomain_rdtype)))
                    queries[(name_obj.nxdomain_name, name_obj.nxdomain_rdtype)] = self.diagnostic_query(name_obj.nxdomain_name, name_obj.nxdomain_rdtype, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)
                if name_obj.nxrrset_name is not None:
                    self.logger.debug('Preparing query %s/%s (No data)...' % (fmt.humanize_name(name_obj.nxrrset_name), dns.rdatatype.to_text(name_obj.nxrrset_rdtype)))
                    queries[(name_obj.nxrrset_name, name_obj.nxrrset_rdtype)] = self.diagnostic_query(name_obj.nxrrset_name, name_obj.nxrrset_rdtype, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)

            if self._ask_ptr_queries(name_obj.name):
                self.logger.debug('Preparing query %s/PTR...' % fmt.humanize_name(name_obj.name))
                queries[(name_obj.name, dns.rdatatype.PTR)] = self.diagnostic_query(name_obj.name, dns.rdatatype.PTR, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6)

        # actually execute the queries, then store the results
        self.logger.debug('Executing queries...')
        Q.ExecutableDNSQuery.execute_queries(*queries.values())
        for key, query in queries.items():
            if query.rrset_answer_info or key not in exclude_no_answer:
                name_obj.add_query(query)

    def _analyze_delegation(self, name_obj):
        if name_obj.name in self.explicit_delegations:
            name_obj.add_auth_ns_ip_mappings(*self.explicit_delegations[name_obj.name])
            name_obj.explicit_delegation = True
            return True
        elif name_obj.parent is None:
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

        servers_queried = { dns.rdatatype.NS: set(), dns.rdatatype.A: set() }
        referral_queries = {}

        # elicit a referral from parent servers by querying first for NS, then for A as a fallback
        for rdtype in (dns.rdatatype.NS, dns.rdatatype.A):
            if rdtype in servers_queried:
                servers_queried[rdtype].update(parent_auth_servers)

            name_obj.referral_rdtype = rdtype

            self.logger.debug('Querying %s/%s (referral)...' % (fmt.humanize_name(name_obj.name), dns.rdatatype.to_text(rdtype)))
            query = self.diagnostic_query(name_obj.name, rdtype, dns.rdataclass.IN, parent_auth_servers, self.client_ipv4, self.client_ipv6)
            query.execute()
            referral_queries[rdtype] = query

            # if NXDOMAIN was received, then double-check with A, as some servers
            # (mostly load balancers) don't respond well to NS queries
            if query.is_nxdomain_all():
                continue

            # otherwise, if we received at least one valid response, then break out
            if query.is_valid_complete_response_any():
                break

            if name_obj.name.is_subdomain(ARPA_NAME):
                break

            # we only go a second time through the loop with an A query if the name
            # is not under .arpa and if 1) there was NXDOMAIN or 2) there were
            # no valid responses  In either case the A record becomes the
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
            # And in the case of a referral type of A, we only keep the NS
            # referral if there was a discrepancy between NXDOMAIN and YXDOMAIN.

            is_nxdomain = query.is_nxdomain_all()
            is_valid = query.is_valid_complete_response_any()

             # (referral type is A)
            if name_obj.referral_rdtype == dns.rdatatype.NS:
                # if rdtype is NS and the name is not under .arpa, then there
                # was no error, and no NXDOMAIN, so there is no need to save
                # the referral.  Delete it.
                if not name_obj.name.is_subdomain(ARPA_NAME):
                    name_obj.referral_rdtype = None
                    del referral_queries[dns.rdatatype.NS]

                # if the name was under .arpa, we only performed one referral query
                # (NS).  save the referral if there was an error or if NXDOMAIN
                # and the name matches this name.  Return positive response only
                # if not NXDOMAIN
                else:
                    if not is_valid or (name_obj.name == self.name and is_nxdomain):
                        pass
                    else:
                        name_obj.referral_rdtype = None
                        del referral_queries[dns.rdatatype.NS]

             # (referral type is A)
            else:
                # don't remove either record if there's not an NXDOMAIN/YXDOMAIN mismatch
                if referral_queries[dns.rdatatype.NS].is_nxdomain_all() and \
                        is_valid and not is_nxdomain:
                    pass
                else:
                    # if no mismatch, then always delete the NS record
                    del referral_queries[dns.rdatatype.NS]
                    # also, delete the A record query if the name doesn't match or is not NXDOMAIN
                    if not is_valid or (name_obj.name == self.name and is_nxdomain):
                        pass
                    else:
                        name_obj.referral_rdtype = None
                        del referral_queries[dns.rdatatype.A]

            # add remaining queries
            for query in referral_queries.values():
                name_obj.add_query(query)

            # return a positive response only if not nxdomain
            return not is_nxdomain

        # add any queries made
        for query in referral_queries.values():
            name_obj.add_query(query)

        names_resolved = set()
        names_not_resolved = name_obj.get_ns_names().difference(names_resolved)
        while names_not_resolved:
            # resolve every name in the NS RRset
            query_tuples = []
            for name in names_not_resolved:
                query_tuples.extend([(name, dns.rdatatype.A, dns.rdataclass.IN), (name, dns.rdatatype.AAAA, dns.rdataclass.IN)])
            answer_map = _resolver.query_multiple(*query_tuples)
            for query_tuple in answer_map:
                name = query_tuple[0]
                a = answer_map[query_tuple]
                if isinstance(a, Resolver.DNSAnswer):
                    for a_rr in a.rrset:
                        name_obj.add_auth_ns_ip_mappings((name, a_rr.to_text()))
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
                queries.append(self.diagnostic_query(name_obj.name, dns.rdatatype.NS, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6))

            # A query
            if self._ask_other_queries(name_obj.name):
                servers = auth_servers.difference(servers_queried[dns.rdatatype.A])
                servers_queried[dns.rdatatype.A].update(servers)
                servers = self._filter_servers(servers)
                if servers:
                    self.logger.debug('Querying %s/A...' % fmt.humanize_name(name_obj.name))
                    queries.append(self.diagnostic_query(name_obj.name, dns.rdatatype.A, dns.rdataclass.IN, servers, self.client_ipv4, self.client_ipv6))

            # actually execute the queries, then store the results
            Q.ExecutableDNSQuery.execute_queries(*queries)
            for query in queries:
                name_obj.add_query(query)

            names_not_resolved = name_obj.get_ns_names().difference(names_resolved)

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
            a = self.__class__(cname, force_dnskey=False, trace=self.trace + [(name_obj.name, dns.rdatatype.CNAME)], **kwargs)
            t = threading.Thread(target=self._analyze_dependency, args=(a, name_obj.cname_targets, cname, errors))
            t.start()
            threads.append(t)

        for dname in name_obj.dname_targets:
            a = self.__class__(dname, force_dnskey=False, trace=self.trace + [(name_obj.name, dns.rdatatype.DNAME)], **kwargs)
            t = threading.Thread(target=self._analyze_dependency, args=(a, name_obj.dname_targets, dname, errors))
            t.start()
            threads.append(t)

        for signer in name_obj.external_signers:
            a = self.__class__(signer, force_dnskey=True, trace=self.trace + [(name_obj.name, dns.rdatatype.RRSIG)], **kwargs)
            t = threading.Thread(target=self._analyze_dependency, args=(a, name_obj.external_signers, signer, errors))
            t.start()
            threads.append(t)

        if self.follow_ns:
            for ns in name_obj.ns_dependencies:
                a = self.__class__(ns, force_dnskey=False, trace=self.trace + [(name_obj.name, dns.rdatatype.NS)], **kwargs)
                t = threading.Thread(target=self._analyze_dependency, args=(a, name_obj.ns_dependencies, ns, errors))
                t.start()
                threads.append(t)

        #TODO MX targets?

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
                _root_ipv4_connectivity_checker.query(dns.name.root, dns.rdatatype.NS, dns.rdataclass.IN)
            elif proto == 6:
                _root_ipv6_connectivity_checker.query(dns.name.root, dns.rdatatype.NS, dns.rdataclass.IN)
            return True
        except dns.exception.Timeout:
            pass
        return False
