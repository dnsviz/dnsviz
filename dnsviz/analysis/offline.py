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

import collections
import errno
import logging

import dns.flags, dns.rdataclass, dns.rdatatype

from dnsviz import crypto 
import dnsviz.format as fmt
import dnsviz.query as Q
from dnsviz.response import DNSKEYMeta
import dnsviz.status as Status
from dnsviz.util import tuple_to_dict

from online import OnlineDomainNameAnalysis

_logger = logging.getLogger(__name__)

class FoundYXDOMAIN(Exception):
    pass

class OfflineDomainNameAnalysis(OnlineDomainNameAnalysis):
    RDTYPES_ALL = 0
    RDTYPES_ALL_SAME_NAME = 1
    RDTYPES_NS_TARGET = 2
    RDTYPES_SECURE_DELEGATION = 3
    RDTYPES_DELEGATION = 4

    QUERY_CLASS = Q.MultiQueryAggregateDNSResponse

    def __init__(self, name, stub=False):
        super(OfflineDomainNameAnalysis, self).__init__(name, stub=stub)

        self.status = None
        self.yxdomain = None
        self.yxrrset = None
        self.rrset_warnings = None
        self.rrset_errors = None
        self.rrsig_status = None
        self.wildcard_status = None
        self.dname_status = None
        self.nxdomain_status = None
        self.nxdomain_warnings = None
        self.nxdomain_errors = None
        self.nodata_status = None
        self.nodata_warnings = None
        self.nodata_errors = None

        self.ds_status_by_ds = None
        self.ds_status_by_dnskey = None

        self.delegation_warnings = None
        self.delegation_errors = None
        self.delegation_status = None

        self.published_keys = None
        self.revoked_keys = None
        self.zsks = None
        self.ksks = None

    def _index_dnskeys(self):
        self._dnskey_sets = []
        self._dnskeys = {}
        if (self.name, dns.rdatatype.DNSKEY) not in self.queries:
            return
        for dnskey_info in self.queries[(self.name, dns.rdatatype.DNSKEY)].answer_info:
            # there are CNAMEs that show up here...
            if not (dnskey_info.rrset.name == self.name and dnskey_info.rrset.rdtype == dns.rdatatype.DNSKEY):
                continue
            dnskey_set = set()
            for dnskey_rdata in dnskey_info.rrset:
                if dnskey_rdata not in self._dnskeys:
                    self._dnskeys[dnskey_rdata] = DNSKEYMeta(dnskey_info.rrset.name, dnskey_rdata, dnskey_info.rrset.ttl)
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

    def _rdtypes_for_analysis_level(self, level):
        rdtypes = set([self.referral_rdtype, dns.rdatatype.NS])
        if level == self.RDTYPES_DELEGATION:
            return rdtypes
        rdtypes.update([dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.DLV])
        if level == self.RDTYPES_SECURE_DELEGATION:
            return rdtypes
        rdtypes.update([dns.rdatatype.A, dns.rdatatype.AAAA])
        if level == self.RDTYPES_NS_TARGET:
            return rdtypes
        return None

    def _server_responsive_with_condition(self, server, client, request_test, response_test):
        for query in self.queries.values():
            for query1 in query.queries.values():
                if request_test(query1):
                    try:
                        if client is None:
                            clients = query1.responses[server].keys()
                        else:
                            clients = (client,)
                    except KeyError:
                        continue

                    for c in clients:
                        try:
                            response = query1.responses[server][client]
                        except KeyError:
                            continue
                        if response_test(response):
                            return True
        return False

    def server_responsive_with_edns_flag(self, server, client, f):
        return self._server_responsive_with_condition(server, client,
                lambda x: x.edns >= 0 and x.edns_flags & f,
                lambda x: ((x.effective_tcp and x.tcp_responsive) or \
                        (not x.effective_tcp and x.udp_responsive)) and \
                        x.effective_edns >= 0 and x.effective_edns_flags & f)

    def server_responsive_valid_with_edns_flag(self, server, client, f):
        return self._server_responsive_with_condition(server, client,
                lambda x: x.edns >= 0 and x.edns_flags & f,
                lambda x: x.is_valid_response() and \
                        x.effective_edns >= 0 and x.effective_edns_flags & f)

    def server_responsive_with_do(self, server, client):
        return self.server_responsive_with_edns_flag(server, client, dns.flags.DO)

    def server_responsive_valid_with_do(self, server, client):
        return self.server_responsive_valid_with_edns_flag(server, client, dns.flags.DO)

    def server_responsive_with_edns(self, server, client):
        return self._server_responsive_with_condition(server, client,
                lambda x: x.edns >= 0,
                lambda x: ((x.effective_tcp and x.tcp_responsive) or \
                        (not x.effective_tcp and x.udp_responsive)) and \
                        x.effective_edns >= 0)

    def server_responsive_valid_with_edns(self, server, client):
        return self._server_responsive_with_condition(server, client,
                lambda x: x.edns >= 0,
                lambda x: x.is_valid_response() and \
                        x.effective_edns >= 0)

    def populate_status(self, trusted_keys, supported_algs=None, supported_digest_algs=None, is_dlv=False, level=RDTYPES_ALL, trace=None, follow_mx=True):
        if trace is None:
            trace = []

        # avoid loops
        if self in trace:
            self._populate_name_status(level)
            return

        # if status has already been populated, then don't reevaluate
        if self.rrsig_status is not None:
            return

        # if we're a stub, there's nothing to evaluate
        if self.stub:
            return

        # identify supported algorithms as intersection of explicitly supported
        # and software supported
        if supported_algs is not None:
            supported_algs.intersection_update(crypto._supported_algs)
        else:
            supported_algs = crypto._supported_algs
        if supported_digest_algs is not None:
            supported_digest_algs.intersection_update(crypto._supported_digest_algs)
        else:
            supported_digest_algs = crypto._supported_digest_algs

        # populate status of dependencies
        if level <= self.RDTYPES_NS_TARGET:
            for cname in self.cname_targets:
                for target, cname_obj in self.cname_targets[cname].items():
                    cname_obj.populate_status(trusted_keys, level=max(self.RDTYPES_ALL_SAME_NAME, level), trace=trace + [self])
            if follow_mx:
                for target, mx_obj in self.mx_targets.items():
                    if mx_obj is not None:
                        mx_obj.populate_status(trusted_keys, level=max(self.RDTYPES_ALL_SAME_NAME, level), trace=trace + [self], follow_mx=False)
        if level <= self.RDTYPES_SECURE_DELEGATION:
            for signer, signer_obj in self.external_signers.items():
                signer_obj.populate_status(trusted_keys, level=self.RDTYPES_SECURE_DELEGATION, trace=trace + [self])
            for target, ns_obj in self.ns_dependencies.items():
                if ns_obj is not None:
                    ns_obj.populate_status(trusted_keys, level=self.RDTYPES_NS_TARGET, trace=trace + [self])

        # populate status of ancestry
        if self.parent is not None:
            self.parent.populate_status(trusted_keys, supported_algs, supported_digest_algs, level=self.RDTYPES_SECURE_DELEGATION, trace=trace + [self])
        if self.dlv_parent is not None:
            self.dlv_parent.populate_status(trusted_keys, supported_algs, supported_digest_algs, is_dlv=True, level=self.RDTYPES_SECURE_DELEGATION, trace=trace + [self])

        _logger.debug('Assessing status of %s...' % (fmt.humanize_name(self.name)))
        self._populate_name_status(level)
        if level <= self.RDTYPES_SECURE_DELEGATION:
            self._index_dnskeys()
        self._populate_rrsig_status_all(supported_algs, level)
        self._populate_nsec_status(supported_algs, level)
        self._finalize_key_roles()
        if level <= self.RDTYPES_SECURE_DELEGATION:
            if not is_dlv:
                self._populate_delegation_status(supported_algs, supported_digest_algs)
            if self.dlv_parent is not None:
                self._populate_ds_status(dns.rdatatype.DLV, supported_algs, supported_digest_algs)
            self._populate_dnskey_status(trusted_keys)

    def _populate_name_status(self, level, trace=None):
        # using trace allows _populate_name_status to be called independent of
        # populate_status
        if trace is None:
            trace = []

        # avoid loops
        if self in trace:
            return

        self.status = Status.NAME_STATUS_INDETERMINATE
        self.yxdomain = set()
        self.yxrrset = set()

        bailiwick_map, default_bailiwick = self.get_bailiwick_mapping()
        
        required_rdtypes = self._rdtypes_for_analysis_level(level)
        for (qname, rdtype), query in self.queries.items():

            if level > self.RDTYPES_ALL and qname not in (self.name, self.dlv_name):
                continue

            if required_rdtypes is not None and rdtype not in required_rdtypes:
                continue

            qname_obj = self.get_name(qname)
            if rdtype == dns.rdatatype.DS:
                qname_obj = qname_obj.parent
            elif rdtype == dns.rdatatype.DLV:
                qname_obj = qname_obj.dlv_parent

            for rrset_info in query.answer_info:
                self.yxdomain.add(rrset_info.rrset.name)
                self.yxrrset.add((rrset_info.rrset.name, rrset_info.rrset.rdtype))
                if rrset_info.dname_info is not None:
                    self.yxrrset.add((rrset_info.dname_info.rrset.name, rrset_info.dname_info.rrset.rdtype))
                for cname_rrset_info in rrset_info.cname_info_from_dname:
                    self.yxrrset.add((cname_rrset_info.dname_info.rrset.name, cname_rrset_info.dname_info.rrset.rdtype))
                    self.yxrrset.add((cname_rrset_info.rrset.name, cname_rrset_info.rrset.rdtype))
            for neg_response_info in query.nodata_info:
                try:
                    for (server,client) in neg_response_info.servers_clients:
                        for response in neg_response_info.servers_clients[(server,client)]:
                            if not response.is_upward_referral(qname_obj.zone.name):
                                if neg_response_info.qname == qname or response.recursion_desired_and_available():
                                    self.yxdomain.add(neg_response_info.qname)
                                    raise FoundYXDOMAIN
                except FoundYXDOMAIN:
                    break

            if level <= self.RDTYPES_DELEGATION:
                # now check referrals (if name hasn't already been identified as YXDOMAIN)
                if self.name == qname and self.name not in self.yxdomain:
                    if rdtype not in (self.referral_rdtype, dns.rdatatype.NS):
                        continue
                    try:
                        for query1 in query.queries.values():
                            for server in query1.responses:
                                bailiwick = bailiwick_map.get(server, default_bailiwick)
                                for client in query1.responses[server]:
                                    if query1.responses[server][client].is_referral(self.name, rdtype, bailiwick, proper=True):
                                        self.yxdomain.add(self.name)
                                        raise FoundYXDOMAIN
                    except FoundYXDOMAIN:
                        pass

        if level <= self.RDTYPES_NS_TARGET:
            # now add the values of CNAMEs
            for cname in self.cname_targets:
                if level > self.RDTYPES_ALL and cname not in (self.name, self.dlv_name):
                    continue
                for target, cname_obj in self.cname_targets[cname].items():
                    if cname_obj is self:
                        continue
                    if cname_obj.yxrrset is None:
                        cname_obj._populate_name_status(self.RDTYPES_ALL, trace=trace + [self])
                    for name, rdtype in cname_obj.yxrrset:
                        if name == target:
                            self.yxrrset.add((cname,rdtype))

        if self.name in self.yxdomain:
            self.status = Status.NAME_STATUS_NOERROR

        if self.status == Status.NAME_STATUS_INDETERMINATE:
            for (qname, rdtype), query in self.queries.items():
                if rdtype == dns.rdatatype.DS:
                    continue
                if filter(lambda x: x.qname == qname, query.nxdomain_info):
                    self.status = Status.NAME_STATUS_NXDOMAIN
                    break

    def _populate_response_errors(self, qname_obj, response, server, client, warnings, errors):
        # if the initial request used EDNS
        if response.query.edns >= 0:
            error_code = None
            #TODO check for general intermittent errors (i.e., not just for EDNS/DO)
            #TODO mark a slow response as well (over a certain threshold)

            # if the response didn't use EDNS
            if response.message.edns < 0:
                # if the effective request didn't use EDNS either
                if response.effective_edns < 0:
                    # find out if this really appears to be an EDNS issue, by
                    # seeing if any other queries to this server with EDNS were
                    # actually successful 
                    if response.responsive_cause_index is not None:
                        if response.history[response.responsive_cause_index].cause == Q.RETRY_CAUSE_NETWORK_ERROR:
                            if qname_obj is not None and qname_obj.zone.server_responsive_with_edns(server,client):
                                error_code = Status.RESPONSE_ERROR_INTERMITTENT_NETWORK_ERROR
                            else:
                                error_code = Status.RESPONSE_ERROR_NETWORK_ERROR_WITH_EDNS
                        elif response.history[response.responsive_cause_index].cause == Q.RETRY_CAUSE_FORMERR:
                            if qname_obj is not None and qname_obj.zone.server_responsive_valid_with_edns(server,client):
                                error_code = Status.RESPONSE_ERROR_INTERMITTENT_FORMERR
                            else:
                                error_code = Status.RESPONSE_ERROR_FORMERR_WITH_EDNS
                        elif response.history[response.responsive_cause_index].cause == Q.RETRY_CAUSE_TIMEOUT:
                            if qname_obj is not None and qname_obj.zone.server_responsive_with_edns(server,client):
                                error_code = Status.RESPONSE_ERROR_INTERMITTENT_TIMEOUT
                            else:
                                error_code = Status.RESPONSE_ERROR_TIMEOUT_WITH_EDNS
                        elif response.history[response.responsive_cause_index].cause == Q.RETRY_CAUSE_OTHER:
                            if qname_obj is not None and qname_obj.zone.server_responsive_valid_with_edns(server,client):
                                error_code = Status.RESPONSE_ERROR_INTERMITTENT_ERROR
                            else:
                                error_code = Status.RESPONSE_ERROR_ERROR_WITH_EDNS
                        elif response.history[response.responsive_cause_index].cause == Q.RETRY_CAUSE_RCODE:
                            if qname_obj is not None and qname_obj.zone.server_responsive_valid_with_edns(server,client):
                                error_code = Status.RESPONSE_ERROR_INTERMITTENT_BAD_RCODE
                            else:
                                error_code = Status.RESPONSE_ERROR_BAD_RCODE_WITH_EDNS

                # if the ultimate request used EDNS, then it was simply ignored
                # by the server
                else:
                    error_code = Status.RESPONSE_ERROR_EDNS_IGNORED

                #TODO handle this better
                if error_code is None:
                    raise Exception('Unknown EDNS-related error')

            # the response did use EDNS
            else:

                # check for EDNS version mismatch
                if response.effective_edns != response.message.edns:
                    if Status.RESPONSE_ERROR_UNSUPPORTED_EDNS_VERSION not in warnings:
                        warnings[Status.RESPONSE_ERROR_UNSUPPORTED_EDNS_VERSION] = set()
                    warnings[Status.RESPONSE_UNSUPPORTED_EDNS_VERSION].add((server,client))

                # check for PMTU issues
                #TODO need bounding here
                if response.effective_edns_max_udp_payload != response.query.edns_max_udp_payload and response.msg_size > 512:
                    if Status.RESPONSE_ERROR_PMTU_EXCEEDED not in warnings:
                        warnings[Status.RESPONSE_ERROR_PMTU_EXCEEDED] = set()
                    warnings[Status.RESPONSE_ERROR_PMTU_EXCEEDED].add((server,client))

                if response.query.edns_flags != response.effective_edns_flags:
                    for i in range(15, -1, -1):
                        f = 1 << i
                        # the response used EDNS with the given flag, but the flag
                        # wasn't (ultimately) requested
                        if ((response.query.edns_flags & f) != (response.effective_edns_flags & f)):
                            # find out if this really appears to be a flag issue,
                            # by seeing if any other queries to this server with
                            # the DO bit were also unsuccessful 
                            if response.responsive_cause_index is not None:
                                if response.history[response.responsive_cause_index].cause == Q.RETRY_CAUSE_NETWORK_ERROR:
                                    if qname_obj is not None and qname_obj.zone.server_responsive_with_edns_flag(server,client,f):
                                        error_code = Status.RESPONSE_ERROR_INTERMITTENT_NETWORK_ERROR
                                    else:
                                        error_code = Status.RESPONSE_ERROR_NETWORK_ERROR_WITH_EDNS_FLAG
                                elif response.history[response.responsive_cause_index].cause == Q.RETRY_CAUSE_FORMERR:
                                    if qname_obj is not None and qname_obj.zone.server_responsive_valid_with_edns_flag(server,client,f):
                                        error_code = Status.RESPONSE_ERROR_INTERMITTENT_FORMERR
                                    else:
                                        error_code = Status.RESPONSE_ERROR_FORMERR_WITH_EDNS_FLAG
                                elif response.history[response.responsive_cause_index].cause == Q.RETRY_CAUSE_TIMEOUT:
                                    if qname_obj is not None and qname_obj.zone.server_responsive_with_edns_flag(server,client,f):
                                        error_code = Status.RESPONSE_ERROR_INTERMITTENT_TIMEOUT
                                    else:
                                        error_code = Status.RESPONSE_ERROR_TIMEOUT_WITH_EDNS_FLAG
                                elif response.history[response.responsive_cause_index].cause == Q.RETRY_CAUSE_OTHER:
                                    if qname_obj is not None and qname_obj.zone.server_responsive_valid_with_edns_flag(server,client,f):
                                        error_code = Status.RESPONSE_ERROR_INTERMITTENT_ERROR
                                    else:
                                        error_code = Status.RESPONSE_ERROR_ERROR_WITH_EDNS_FLAG
                                elif response.history[response.responsive_cause_index].cause == Q.RETRY_CAUSE_RCODE:
                                    if qname_obj is not None and qname_obj.zone.server_responsive_valid_with_edns_flag(server,client,f):
                                        error_code = Status.RESPONSE_ERROR_INTERMITTENT_BAD_RCODE
                                    else:
                                        error_code = Status.RESPONSE_ERROR_BAD_RCODE_WITH_EDNS_FLAG

                            #TODO handle this better
                            if error_code is None:
                                raise Exception('Unknown EDNS-flag-related error')

                        if error_code is not None:
                            break

            if error_code is not None:
                # warn on intermittent errors
                if error_code in (Status.RESPONSE_ERROR_INTERMITTENT_NETWORK_ERROR, Status.RESPONSE_ERROR_INTERMITTENT_FORMERR,
                        Status.RESPONSE_ERROR_INTERMITTENT_TIMEOUT, Status.RESPONSE_ERROR_INTERMITTENT_ERROR,
                        Status.RESPONSE_ERROR_INTERMITTENT_BAD_RCODE):
                    group = warnings
                # if the error really matters (e.g., due to DNSSEC), note an error
                elif qname_obj is not None and qname_obj.zone.signed:
                    group = errors
                # otherwise, warn
                else:
                    group = warnings

                if error_code not in group:
                    group[error_code] = set()
                group[error_code].add((server,client))

        if not response.is_authoritative() and \
                not response.recursion_desired_and_available():
            if Status.RESPONSE_ERROR_NOT_AUTHORITATIVE not in errors:
                errors[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE] = set()
            errors[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE].add((server,client))

    def _populate_wildcard_status(self, qname, rdtype, query, rrset_info, qname_obj, supported_algs):
        for wildcard_name in rrset_info.wildcard_info:
            if qname_obj is None:
                zone_name = wildcard_info.parent()
            else:
                zone_name = qname_obj.zone.name

            servers_missing_nsec = set()
            for server, client in rrset_info.wildcard_info[wildcard_name].servers_clients:
                for response in rrset_info.wildcard_info[wildcard_name].servers_clients[(server,client)]:
                    servers_missing_nsec.add((server,client,response))

            self.wildcard_status[rrset_info.wildcard_info[wildcard_name]] = {}
            status_by_response = {}

            for nsec_set_info in rrset_info.wildcard_info[wildcard_name].nsec_set_info:
                if nsec_set_info.use_nsec3:
                    status = Status.NSEC3StatusWildcard(rrset_info.rrset.name, wildcard_name, rdtype, zone_name, nsec_set_info)
                else:
                    status = Status.NSECStatusWildcard(rrset_info.rrset.name, wildcard_name, rdtype, zone_name, nsec_set_info)

                for nsec_rrset_info in nsec_set_info.rrsets.values():
                    self._populate_rrsig_status(qname, rdtype, query, nsec_rrset_info, qname_obj, supported_algs)

                if status.validation_status == Status.NSEC_STATUS_VALID:
                    self.wildcard_status[rrset_info.wildcard_info[wildcard_name]][nsec_set_info] = status

                for server, client in nsec_set_info.servers_clients:
                    for response in nsec_set_info.servers_clients[(server,client)]:
                        if (server,client,response) in servers_missing_nsec:
                            servers_missing_nsec.remove((server,client,response))
                        if status.validation_status == Status.NSEC_STATUS_VALID:
                            if (server,client,response) in status_by_response:
                                del status_by_response[(server,client,response)]
                        else:
                            status_by_response[(server,client,response)] = status

            for (server,client,response), status in status_by_response.items():
                self.wildcard_status[rrset_info.wildcard_info[wildcard_name]][status.nsec_set_info] = status

            for server, client, response in servers_missing_nsec:
                # by definition, DNSSEC was requested (otherwise we
                # wouldn't know this was a wildcard), so no need to
                # check for DO bit in request
                if Status.RESPONSE_ERROR_MISSING_NSEC_FOR_WILDCARD not in self.rrset_errors[rrset_info]:
                    self.rrset_errors[rrset_info][Status.RESPONSE_ERROR_MISSING_NSEC_FOR_WILDCARD] = set()
                self.rrset_errors[rrset_info][Status.RESPONSE_ERROR_MISSING_NSEC_FOR_WILDCARD].add((server,client))

    def _populate_rrsig_status(self, qname, rdtype, query, rrset_info, qname_obj, supported_algs):
        self.rrset_warnings[rrset_info] = {}
        self.rrset_errors[rrset_info] = {}
        self.rrsig_status[rrset_info] = {}

        qname_obj = self.get_name(qname)
        if qname_obj is None:
            zone_name = None
        else:
            if rdtype == dns.rdatatype.DS:
                qname_obj = qname_obj.parent
            elif rdtype == dns.rdatatype.DLV:
                qname_obj = qname_obj.dlv_parent
            zone_name = qname_obj.zone.name

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

            #XXX
            if signer is not None:

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
                        rrsig_status = Status.RRSIGStatus(rrset_info, rrsig, dnskey, zone_name, fmt.datetime_to_timestamp(self.analysis_end), algorithm_unknown=rrsig.algorithm not in supported_algs)
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
                            break

            # no corresponding DNSKEY
            if not self.rrsig_status[rrset_info][rrsig]:
                rrsig_status = Status.RRSIGStatus(rrset_info, rrsig, None, self.zone.name, fmt.datetime_to_timestamp(self.analysis_end), algorithm_unknown=rrsig.algorithm not in supported_algs)
                self.rrsig_status[rrsig_status.rrset][rrsig_status.rrsig][None] = rrsig_status

        # list errors for rrsets with which no RRSIGs were returned or not all algorithms were accounted for
        for server,client,response in algs_signing_rrset:
            errors = self.rrset_errors[rrset_info]
            # report an error if all RRSIGs are missing
            if not algs_signing_rrset[(server,client,response)]:
                if response.dnssec_requested():
                    if Status.RESPONSE_ERROR_MISSING_RRSIGS not in errors:
                        errors[Status.RESPONSE_ERROR_MISSING_RRSIGS] = set()
                    errors[Status.RESPONSE_ERROR_MISSING_RRSIGS].add((server,client))
                elif qname_obj is not None and qname_obj.zone.server_responsive_with_do(server,client):
                    if Status.RESPONSE_ERROR_UNABLE_TO_RETRIEVE_DNSSEC_RECORDS not in errors:
                        errors[Status.RESPONSE_ERROR_UNABLE_TO_RETRIEVE_DNSSEC_RECORDS] = set()
                    errors[Status.RESPONSE_ERROR_UNABLE_TO_RETRIEVE_DNSSEC_RECORDS].add((server,client))
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
                if dnssec_algorithms_in_dlv.difference(algs_signing_rrset[(server,client,response)]):
                    if Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DLV not in errors:
                        errors[Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DLV] = set()
                    errors[Status.RESPONSE_ERROR_MISSING_ALGS_FROM_DLV].add((server,client))

        self._populate_wildcard_status(qname, rdtype, query, rrset_info, qname_obj, supported_algs)

        for server,client in rrset_info.servers_clients:
            for response in rrset_info.servers_clients[(server,client)]:
                self._populate_response_errors(qname_obj, response, server, client, self.rrset_warnings[rrset_info], self.rrset_errors[rrset_info])

    def _populate_rrsig_status_all(self, supported_algs, level):
        self.rrset_warnings = {}
        self.rrset_errors = {}
        self.rrsig_status = {}
        self.dname_status = {}
        self.wildcard_status = {}

        if self.is_zone():
            self.zsks = set()
            self.ksks = set()

        _logger.debug('Assessing RRSIG status of %s...' % (fmt.humanize_name(self.name)))
        required_rdtypes = self._rdtypes_for_analysis_level(level)
        for (qname, rdtype), query in self.queries.items():

            if level > self.RDTYPES_ALL and qname not in (self.name, self.dlv_name):
                continue

            if required_rdtypes is not None and rdtype not in required_rdtypes:
                continue

            items_to_validate = []
            for rrset_info in query.answer_info:
                items_to_validate.append(rrset_info)
                if rrset_info.dname_info is not None:
                    items_to_validate.append(rrset_info.dname_info)
                for cname_rrset_info in rrset_info.cname_info_from_dname:
                    items_to_validate.append(cname_rrset_info.dname_info)
                    items_to_validate.append(cname_rrset_info)

            for rrset_info in items_to_validate:
                qname_obj = self.get_name(rrset_info.rrset.name)
                if rdtype == dns.rdatatype.DS:
                    qname_obj = qname_obj.parent

                self._populate_rrsig_status(rrset_info.rrset.name, rdtype, query, rrset_info, qname_obj, supported_algs)

    def _finalize_key_roles(self):
        if self.is_zone():
            self.published_keys = set(self.get_dnskeys()).difference(self.zsks.union(self.ksks))
            self.revoked_keys = set(filter(lambda x: x.rdata.flags & fmt.DNSKEY_FLAGS['revoke'], self.get_dnskeys()))

    def _populate_delegation_status(self, supported_algs, supported_digest_algs):
        self.ds_status_by_ds = {}
        self.ds_status_by_dnskey = {}
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
        self.delegation_warnings[rdtype] = {}
        self.delegation_errors[rdtype] = {}
        self.delegation_status[rdtype] = None

        try:
            ds_rrset_answer_info = self.queries[(name, rdtype)].answer_info
        except KeyError:
            # zones should have DS queries
            if self.is_zone():
                raise
            else:
                return

        secure_path = False

        bailiwick_map, default_bailiwick = self.get_bailiwick_mapping()

        if (self.name, dns.rdatatype.DNSKEY) in self.queries:
            dnskey_multiquery = self.queries[(self.name, dns.rdatatype.DNSKEY)]
        else:
            dnskey_multiquery = self.QUERY_CLASS(self.name, dns.rdatatype.DNSKEY, dns.rdataclass.IN)

        # populate all the servers queried for DNSKEYs to determine
        # what problems there were with regard to DS records and if
        # there is at least one match
        dnskey_server_client_responses = set()
        for dnskey_query in dnskey_multiquery.queries.values():
            for server in dnskey_query.responses:
                bailiwick = bailiwick_map.get(server, default_bailiwick)
                for client in dnskey_query.responses[server]:
                    response = dnskey_query.responses[server][client]
                    if response.is_valid_response() and response.is_complete_response() and not response.is_referral(self.name, dns.rdatatype.DNSKEY, bailiwick):
                        dnskey_server_client_responses.add((server,client,response))

        for ds_rrset_info in ds_rrset_answer_info:
            # there are CNAMEs that show up here...
            if not (ds_rrset_info.rrset.name == name and ds_rrset_info.rrset.rdtype == rdtype):
                continue

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

                for dnskey_info in dnskey_multiquery.answer_info:
                    # there are CNAMEs that show up here...
                    if not (dnskey_info.rrset.name == self.name and dnskey_info.rrset.rdtype == dns.rdatatype.DNSKEY):
                        continue

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
                            break

                # no corresponding DNSKEY
                if not self.ds_status_by_ds[rdtype][ds_rdata]:
                    ds_status = Status.DSStatus(ds_rdata, ds_rrset_info, None)
                    self.ds_status_by_ds[rdtype][ds_rdata][None] = ds_status
                    if None not in self.ds_status_by_dnskey[rdtype]:
                        self.ds_status_by_dnskey[rdtype][None] = {}
                    self.ds_status_by_dnskey[rdtype][None][ds_rdata] = ds_status

            if dnskey_server_client_responses:
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

            else:
                self.delegation_errors[rdtype][Status.DELEGATION_ERROR_NO_SEP] = set()
                self.delegation_errors[rdtype][Status.DELEGATION_ERROR_NO_SEP_FOR_SOME_ALGS] = set()

        if self.delegation_status[rdtype] is None:
            if ds_rrset_answer_info:
                if secure_path:
                    self.delegation_status[rdtype] = Status.DELEGATION_STATUS_BOGUS
                else:
                    self.delegation_status[rdtype] = Status.DELEGATION_STATUS_INSECURE
            elif self.parent.signed:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_BOGUS
                for nsec_status_list in [self.nxdomain_status[n] for n in self.nxdomain_status if n.qname == name and n.rdtype == dns.rdatatype.DS] + \
                        [self.nodata_status[n] for n in self.nodata_status if n.qname == name and n.rdtype == dns.rdatatype.DS]:
                    for nsec_status in nsec_status_list:
                        if nsec_status.validation_status == Status.NSEC_STATUS_VALID:
                            self.delegation_status[rdtype] = Status.DELEGATION_STATUS_INSECURE
                            break
            else:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_INSECURE

        #XXX the remaining checks need consideration for recursive

        # if no servers (designated or stealth authoritative) respond or none
        # respond authoritatively, then make the delegation as lame
        if not self.get_responsive_auth_or_designated_servers():
            self.delegation_errors[rdtype][Status.DELEGATION_ERROR_NO_RESPONSIVE_SERVERS] = set()
            if self.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_LAME
        elif not self.get_valid_auth_or_designated_servers():
            self.delegation_errors[rdtype][Status.DELEGATION_ERROR_NO_VALID_RCODE_RESPONSE] = set()
            if self.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_LAME
        elif not self._auth_servers_clients:
            self.delegation_errors[rdtype][Status.DELEGATION_ERROR_NO_AUTHORITATIVE_RESPONSE] = set()
            if self.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_LAME

        if rdtype == dns.rdatatype.DS:
            try:
                ds_nxdomain_info = filter(lambda x: x.qname == name and x.rdtype == dns.rdatatype.DS, self.queries[(name, rdtype)].nxdomain_info)[0]
            except IndexError:
                pass
            else:
                self.delegation_errors[rdtype][Status.DELEGATION_ERROR_NO_NS_IN_PARENT] = ds_nxdomain_info.servers_clients.copy()
                if self.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                    self.delegation_status[rdtype] = Status.DELEGATION_STATUS_INCOMPLETE

    def _populate_negative_response_status(self, query, neg_response_info, \
            bad_soa_error, missing_soa_error, upward_referral_error, missing_nsec_error, \
            nsec_status_cls, nsec3_status_cls, warnings, errors, supported_algs):

        qname_obj = self.get_name(neg_response_info.qname)
        if query.rdtype == dns.rdatatype.DS:
            qname_obj = qname_obj.parent

        soa_owner_name_for_servers = {}
        servers_without_soa = set()
        servers_missing_nsec = set()
        for server, client in neg_response_info.servers_clients:
            for response in neg_response_info.servers_clients[(server, client)]:
                servers_without_soa.add((server, client, response))
                servers_missing_nsec.add((server, client, response))

                self._populate_response_errors(qname_obj, response, server, client, warnings, errors)

        for soa_rrset_info in neg_response_info.soa_rrset_info:
            soa_owner_name = soa_rrset_info.rrset.name

            for server, client in soa_rrset_info.servers_clients:
                for response in soa_rrset_info.servers_clients[(server, client)]:
                    servers_without_soa.remove((server, client, response))
                    soa_owner_name_for_servers[(server,client,response)] = soa_owner_name

            if soa_owner_name != qname_obj.zone.name:
                if neg_response_info.qname == query.qname:
                    if bad_soa_error not in errors:
                        errors[bad_soa_error] = set()
                    errors[bad_soa_error].update(soa_rrset_info.servers_clients)
                else:
                    for server,client in soa_rrset_info.servers_clients:
                        for response in soa_rrset_info.servers_clients[(server,client)]:
                            if response.recursion_desired_and_available():
                                if bad_soa_error not in errors:
                                    errors[bad_soa_error] = set()
                                errors[bad_soa_error].add((server,client))

            self._populate_rrsig_status(soa_owner_name, dns.rdatatype.SOA, query, soa_rrset_info, self.get_name(soa_owner_name), supported_algs)

        servers_missing_soa = set()
        servers_upward_referral = set()
        for server,client,response in servers_without_soa:
            if neg_response_info.qname == query.qname or response.recursion_desired_and_available():
                # check for an upward referral
                if upward_referral_error is not None and response.is_upward_referral(qname_obj.zone.name):
                    servers_upward_referral.add((server,client))
                else:
                    servers_missing_soa.add((server,client))
        if servers_missing_soa:
            errors[missing_soa_error] = servers_missing_soa
        if servers_upward_referral:
            errors[upward_referral_error] = servers_upward_referral

            if Status.RESPONSE_ERROR_NOT_AUTHORITATIVE in errors:
                errors[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE].difference_update(errors[upward_referral_error])
                if not errors[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE]:
                    del errors[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE]
            if Status.RESPONSE_ERROR_NOT_AUTHORITATIVE in warnings:
                warnings[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE].difference_update(errors[upward_referral_error])
                if not warnings[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE]:
                    del warnings[Status.RESPONSE_ERROR_NOT_AUTHORITATIVE]

        statuses = []
        status_by_response = {}
        for nsec_set_info in neg_response_info.nsec_set_info:
            if nsec_set_info.use_nsec3:
                status = nsec3_status_cls(neg_response_info.qname, query.rdtype, \
                        soa_owner_name_for_servers.get((server,client,response), qname_obj.zone.name), nsec_set_info)
            else:
                status = nsec_status_cls(neg_response_info.qname, query.rdtype, \
                        soa_owner_name_for_servers.get((server,client,response), qname_obj.zone.name), nsec_set_info)

            for nsec_rrset_info in nsec_set_info.rrsets.values():
                self._populate_rrsig_status(neg_response_info.qname, query.rdtype, query, nsec_rrset_info, qname_obj, supported_algs)

            if status.validation_status == Status.NSEC_STATUS_VALID:
                statuses.append(status)

            for server, client in nsec_set_info.servers_clients:
                for response in nsec_set_info.servers_clients[(server,client)]:
                    if (server,client,response) in servers_missing_nsec:
                        servers_missing_nsec.remove((server,client,response))
                    if status.validation_status == Status.NSEC_STATUS_VALID:
                        if (server,client,response) in status_by_response:
                            del status_by_response[(server,client,response)]
                    elif neg_response_info.qname == query.qname or response.recursion_desired_and_available():
                        status_by_response[(server,client,response)] = status

        for (server,client,response), status in status_by_response.items():
            statuses.append(status)

        for server, client, response in servers_missing_nsec:
            # report that no NSEC(3) records were returned
            if qname_obj.zone.signed and (neg_response_info.qname == query.qname or response.recursion_desired_and_available()):
                if response.dnssec_requested():
                    if missing_nsec_error not in errors:
                        errors[missing_nsec_error] = set()
                    errors[missing_nsec_error].add((server,client))
                elif qname_obj.zone.server_responsive_with_do(server,client):
                    if Status.RESPONSE_ERROR_UNABLE_TO_RETRIEVE_DNSSEC_RECORDS not in errors:
                        errors[Status.RESPONSE_ERROR_UNABLE_TO_RETRIEVE_DNSSEC_RECORDS] = set()
                    errors[Status.RESPONSE_ERROR_UNABLE_TO_RETRIEVE_DNSSEC_RECORDS].add((server,client))

        return statuses

    def _populate_nsec_status(self, supported_algs, level):
        self.nxdomain_status = {}
        self.nxdomain_warnings = {}
        self.nxdomain_errors = {}
        self.nodata_status = {}
        self.nodata_warnings = {}
        self.nodata_errors = {}

        _logger.debug('Assessing negative responses status of %s...' % (fmt.humanize_name(self.name)))
        required_rdtypes = self._rdtypes_for_analysis_level(level)
        for (qname, rdtype), query in self.queries.items():
            if level > self.RDTYPES_ALL and qname not in (self.name, self.dlv_name):
                continue

            if required_rdtypes is not None and rdtype not in required_rdtypes:
                continue

            for neg_response_info in query.nxdomain_info:
                self.nxdomain_warnings[neg_response_info] = {}
                self.nxdomain_errors[neg_response_info] = {}
                self.nxdomain_status[neg_response_info] = \
                        self._populate_negative_response_status(query, neg_response_info, \
                                Status.RESPONSE_ERROR_BAD_SOA_FOR_NXDOMAIN, Status.RESPONSE_ERROR_MISSING_SOA_FOR_NXDOMAIN, None, \
                                Status.RESPONSE_ERROR_MISSING_NSEC_FOR_NXDOMAIN, Status.NSECStatusNXDOMAIN, Status.NSEC3StatusNXDOMAIN, \
                                self.nxdomain_warnings[neg_response_info], self.nxdomain_errors[neg_response_info], \
                                supported_algs)

                if neg_response_info.qname in self.yxdomain and rdtype not in (dns.rdatatype.DS, dns.rdatatype.DLV):
                    self.nxdomain_warnings[neg_response_info][Status.RESPONSE_ERROR_BAD_NXDOMAIN] = neg_response_info.servers_clients.copy()

            for neg_response_info in query.nodata_info:
                self.nodata_warnings[neg_response_info] = {}
                self.nodata_errors[neg_response_info] = {}
                self.nodata_status[neg_response_info] = \
                        self._populate_negative_response_status(query, neg_response_info, \
                                Status.RESPONSE_ERROR_BAD_SOA_FOR_NODATA, Status.RESPONSE_ERROR_MISSING_SOA_FOR_NODATA, Status.RESPONSE_ERROR_UPWARD_REFERRAL, \
                                Status.RESPONSE_ERROR_MISSING_NSEC_FOR_NODATA, Status.NSECStatusNoAnswer, Status.NSEC3StatusNoAnswer, \
                                self.nodata_warnings[neg_response_info], self.nodata_errors[neg_response_info], \
                                supported_algs)

    def _populate_dnskey_status(self, trusted_keys):
        if (self.name, dns.rdatatype.DNSKEY) not in self.queries:
            return

        trusted_keys_rdata = set([k for z, k in trusted_keys if z == self.name])
        trusted_keys_existing = set()
        trusted_keys_not_self_signing = set()

        # buid a list of responsive servers
        bailiwick_map, default_bailiwick = self.get_bailiwick_mapping()
        servers_responsive = set()
        for query in self.queries[(self.name, dns.rdatatype.DNSKEY)].queries.values():
            servers_responsive.update([(server,client,query) for (server,client) in query.servers_with_valid_complete_response(bailiwick_map, default_bailiwick)])

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
                for nsec_status in self.wildcard_status[rrset_info.wildcard_info[wildcard_name]].values():
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

    def _serialize_negative_response_info(self, neg_response_info, neg_status, warnings, errors, consolidate_clients=False, loglevel=logging.DEBUG):
        d = collections.OrderedDict()

        d['proof'] = []
        for nsec_status in neg_status[neg_response_info]:
            nsec_serialized = nsec_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
            if nsec_serialized:
                d['proof'].append(nsec_serialized)
        if not d['proof']:
            del d['proof']

        d['soa'] = []
        for soa_rrset_info in neg_response_info.soa_rrset_info:
            rrset_serialized = self._serialize_rrset_info(soa_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
            if rrset_serialized:
                d['soa'].append(rrset_serialized)
        if not d['soa']:
            del d['soa']

        if loglevel <= logging.DEBUG or \
                (warnings[neg_response_info] and loglevel <= logging.WARNING) or \
                (errors[neg_response_info] and loglevel <= logging.ERROR):
            servers = tuple_to_dict(neg_response_info.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

        if warnings[neg_response_info] and loglevel <= logging.WARNING:
            d['warnings'] = collections.OrderedDict()
            items = warnings[neg_response_info].keys()
            items.sort()
            for item in items:
                servers = tuple_to_dict(warnings[neg_response_info][item])
                if consolidate_clients:
                    servers = list(servers)
                    servers.sort()
                d['warnings'][Status.response_error_mapping[item]] = servers

        if errors[neg_response_info] and loglevel <= logging.ERROR:
            d['errors'] = collections.OrderedDict()
            items = errors[neg_response_info].keys()
            items.sort()
            for item in items:
                servers = tuple_to_dict(errors[neg_response_info][item])
                if consolidate_clients:
                    servers = list(servers)
                    servers.sort()
                d['errors'][Status.response_error_mapping[item]] = servers

        return d

    def _serialize_response_error_info(self, error_info, consolidate_clients=False, loglevel=logging.DEBUG):
        d = collections.OrderedDict()

        d['error'] = Q.response_errors[error_info.code]

        if error_info.code == Q.RESPONSE_ERROR_INVALID_RCODE:
            d['description'] = dns.rcode.to_text(error_info.arg)
        elif error_info.arg is not None:
            try:
                d['description'] = errno.errorcode[error_info.arg]
            except KeyError:
                #XXX find a good cross-platform way of handling this
                pass

        servers = tuple_to_dict(error_info.servers_clients)
        if consolidate_clients:
            servers = list(servers)
            servers.sort()
        d['servers'] = servers

        return d

    def _serialize_query_status(self, query, consolidate_clients=False, loglevel=logging.DEBUG):
        d = collections.OrderedDict()
        d['answer'] = []
        d['nxdomain'] = []
        d['nodata'] = []
        d['error'] = []

        #TODO sort by CNAME dependencies, beginning with question
        for rrset_info in query.answer_info:
            # only look at qname
            #TODO fix this check for recursive
            if rrset_info.rrset.name == query.qname:
                rrset_serialized = self._serialize_rrset_info(rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
                if rrset_serialized:
                    d['answer'].append(rrset_serialized)

        for neg_response_info in query.nxdomain_info:
            # only look at qname
            #TODO fix this check for recursive
            if neg_response_info.qname == query.qname:
                neg_response_serialized = self._serialize_negative_response_info(neg_response_info, self.nxdomain_status, self.nxdomain_warnings, self.nxdomain_errors, consolidate_clients=consolidate_clients, loglevel=loglevel)
                if neg_response_serialized:
                    d['nxdomain'].append(neg_response_serialized)

        for neg_response_info in query.nodata_info:
            # only look at qname
            #TODO fix this check for recursive
            if neg_response_info.qname == query.qname:
                neg_response_serialized = self._serialize_negative_response_info(neg_response_info, self.nodata_status, self.nodata_warnings, self.nodata_errors, consolidate_clients=consolidate_clients, loglevel=loglevel)
                if neg_response_serialized:
                    d['nodata'].append(neg_response_serialized)

        for error_info in query.error_info:
            error_serialized = self._serialize_response_error_info(error_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
            if error_serialized:
                d['error'].append(error_serialized)

        if not d['answer']: del d['answer']
        if not d['nxdomain']: del d['nxdomain']
        if not d['nodata']: del d['nodata']
        if not d['error']: del d['error']

        return d

    def _serialize_dnskey_status(self, consolidate_clients=False, loglevel=logging.DEBUG):
        d = []

        for dnskey in self.get_dnskeys():
            dnskey_serialized = dnskey.serialize(consolidate_clients=consolidate_clients, loglevel=loglevel)
            if dnskey_serialized:
                d.append(dnskey_serialized)

        return d

    def _serialize_delegation_status(self, rdtype, consolidate_clients=False, loglevel=logging.DEBUG):
        d = collections.OrderedDict()

        dss = self.ds_status_by_ds[rdtype].keys()
        d['ds'] = []
        dss.sort()
        for ds in dss:
            dnskeys = self.ds_status_by_ds[rdtype][ds].keys()
            dnskeys.sort()
            for dnskey in dnskeys:
                ds_status = self.ds_status_by_ds[rdtype][ds][dnskey]
                ds_serialized = ds_status.serialize(consolidate_clients=consolidate_clients, loglevel=loglevel)
                if ds_serialized:
                    d['ds'].append(ds_serialized)
        if not d['ds']:
            del d['ds']

        try:
            neg_response_info = filter(lambda x: x.qname == self.name and x.rdtype == rdtype, self.nodata_status)[0]
            status = self.nodata_status
        except IndexError:
            try:
                neg_response_info = filter(lambda x: x.qname == self.name and x.rdtype == rdtype, self.nxdomain_status)[0]
                status = self.nxdomain_status
            except IndexError:
                neg_response_info = None

        if neg_response_info is not None:
            d['insecurity_proof'] = []
            for nsec_status in status[neg_response_info]:
                nsec_serialized = nsec_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel)
                if nsec_serialized:
                    d['insecurity_proof'].append(nsec_serialized)
            if not d['insecurity_proof']:
                del d['insecurity_proof']

        if loglevel <= logging.INFO or self.delegation_status[rdtype] not in (Status.DELEGATION_STATUS_SECURE, Status.DELEGATION_STATUS_INSECURE):
            d['status'] = Status.delegation_status_mapping[self.delegation_status[rdtype]]

        if self.delegation_warnings[rdtype] and loglevel <= logging.WARNING:
            d['warnings'] = collections.OrderedDict()
            warnings = self.delegation_warnings[rdtype].keys()
            warnings.sort()
            for warning in warnings:
                servers = tuple_to_dict(self.delegation_warnings[rdtype][warning])
                if consolidate_clients:
                    servers = list(servers)
                    servers.sort()
                d['warnings'][Status.delegation_error_mapping[warning]] = servers

        if self.delegation_errors[rdtype] and loglevel <= logging.ERROR:
            d['errors'] = collections.OrderedDict()
            errors = self.delegation_errors[rdtype].keys()
            errors.sort()
            for error in errors:
                servers = tuple_to_dict(self.delegation_errors[rdtype][error])
                if consolidate_clients:
                    servers = list(servers)
                    servers.sort()
                d['errors'][Status.delegation_error_mapping[error]] = servers

        return d

    def serialize_status(self, d=None, is_dlv=False, loglevel=logging.DEBUG, level=RDTYPES_ALL, trace=None, follow_mx=True):
        if d is None:
            d = collections.OrderedDict()

        if trace is None:
            trace = []

        # avoid loops
        if self in trace:
            return d

        # if we're a stub, there's no status to serialize
        if self.stub:
            return d

        name_str = self.name.canonicalize().to_text()
        if name_str in d:
            return d

        # serialize status of dependencies first because their version of the
        # analysis might be the most complete (considering re-dos)
        if level <= self.RDTYPES_NS_TARGET:
            for cname in self.cname_targets:
                for target, cname_obj in self.cname_targets[cname].items():
                    cname_obj.serialize_status(d, loglevel=loglevel, level=max(self.RDTYPES_ALL_SAME_NAME, level), trace=trace + [self])
            if follow_mx:
                for target, mx_obj in self.mx_targets.items():
                    if mx_obj is not None:
                        mx_obj.serialize_status(d, loglevel=loglevel, level=max(self.RDTYPES_ALL_SAME_NAME, level), trace=trace + [self], follow_mx=False)
        if level <= self.RDTYPES_SECURE_DELEGATION:
            for signer, signer_obj in self.external_signers.items():
                signer_obj.serialize_status(d, loglevel=loglevel, level=self.RDTYPES_SECURE_DELEGATION, trace=trace + [self])
            for target, ns_obj in self.ns_dependencies.items():
                if ns_obj is not None:
                    ns_obj.serialize_status(d, loglevel=loglevel, level=self.RDTYPES_NS_TARGET, trace=trace + [self])

        # serialize status of ancestry
        if level <= self.RDTYPES_SECURE_DELEGATION:
            if self.parent is not None:
                self.parent.serialize_status(d, loglevel=loglevel, level=self.RDTYPES_SECURE_DELEGATION, trace=trace + [self])
            if self.dlv_parent is not None:
                self.dlv_parent.serialize_status(d, is_dlv=True, loglevel=loglevel, level=self.RDTYPES_SECURE_DELEGATION, trace=trace + [self])

        consolidate_clients = self.single_client()

        d[name_str] = collections.OrderedDict()
        if loglevel <= logging.INFO or self.status not in (Status.NAME_STATUS_NOERROR, Status.NAME_STATUS_NXDOMAIN):
            d[name_str]['status'] = Status.name_status_mapping[self.status]

        d[name_str]['queries'] = collections.OrderedDict()
        query_keys = self.queries.keys()
        query_keys.sort()
        required_rdtypes = self._rdtypes_for_analysis_level(level)
        for (qname, rdtype) in query_keys:

            if level > self.RDTYPES_ALL and qname not in (self.name, self.dlv_name):
                continue

            if required_rdtypes is not None and rdtype not in required_rdtypes:
                continue

            query_serialized = self._serialize_query_status(self.queries[(qname, rdtype)], consolidate_clients=consolidate_clients, loglevel=loglevel)
            if query_serialized:
                qname_type_str = '%s/%s/%s' % (qname.canonicalize().to_text(), dns.rdataclass.to_text(dns.rdataclass.IN), dns.rdatatype.to_text(rdtype))
                d[name_str]['queries'][qname_type_str] = query_serialized

        if not d[name_str]['queries']:
            del d[name_str]['queries']

        if level <= self.RDTYPES_SECURE_DELEGATION and (self.name, dns.rdatatype.DNSKEY) in self.queries:
            dnskey_serialized = self._serialize_dnskey_status(consolidate_clients=consolidate_clients, loglevel=loglevel)
            if dnskey_serialized:
                d[name_str]['dnskey'] = dnskey_serialized

        if self.is_zone():
            if self.parent is not None and not is_dlv:
                delegation_serialized = self._serialize_delegation_status(dns.rdatatype.DS, consolidate_clients=consolidate_clients, loglevel=loglevel)
                if delegation_serialized:
                    d[name_str]['delegation'] = delegation_serialized

            if self.dlv_parent is not None:
                if (self.dlv_name, dns.rdatatype.DLV) in self.queries:
                    delegation_serialized = self._serialize_delegation_status(dns.rdatatype.DLV, consolidate_clients=consolidate_clients, loglevel=loglevel)
                    if delegation_serialized:
                        d[name_str]['dlv'] = delegation_serialized

        if not d[name_str]:
            del d[name_str]

        return d
