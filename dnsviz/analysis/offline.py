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

import copy
import errno
import logging

# minimal support for python2.6
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

import dns.flags, dns.rcode, dns.rdataclass, dns.rdatatype

from dnsviz import crypto
import dnsviz.format as fmt
from dnsviz.ipaddr import *
import dnsviz.query as Q
from dnsviz import response as Response
from dnsviz.util import tuple_to_dict
lb2s = fmt.latin1_binary_to_string

from . import errors as Errors
from .online import OnlineDomainNameAnalysis, \
        ANALYSIS_TYPE_AUTHORITATIVE, ANALYSIS_TYPE_RECURSIVE, ANALYSIS_TYPE_CACHE
from . import status as Status

DNS_PROCESSED_VERSION = '1.0'

#XXX (this needs to be updated if new specification ever updates
# RFC 6891)
EDNS_DEFINED_FLAGS = dns.flags.DO

DNSSEC_KEY_LENGTHS_BY_ALGORITHM = {
        12: 512, 13: 512, 14: 768, 15: 256, 16: 456,
}
DNSSEC_KEY_LENGTH_ERRORS = {
        12: Errors.DNSKEYBadLengthGOST, 13: Errors.DNSKEYBadLengthECDSA256,
        14: Errors.DNSKEYBadLengthECDSA384, 15: Errors.DNSKEYBadLengthEd25519,
        16: Errors.DNSKEYBadLengthEd448,
}

_logger = logging.getLogger(__name__)

class FoundYXDOMAIN(Exception):
    pass

class CNAMELoopDetected(Exception):
    pass

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

class OfflineDomainNameAnalysis(OnlineDomainNameAnalysis):
    RDTYPES_ALL = 0
    RDTYPES_ALL_SAME_NAME = 1
    RDTYPES_NS_TARGET = 2
    RDTYPES_SECURE_DELEGATION = 3
    RDTYPES_DELEGATION = 4

    QUERY_CLASS = Q.TTLDistinguishingMultiQueryAggregateDNSResponse

    def __init__(self, *args, **kwargs):

        self._strict_cookies = kwargs.pop('strict_cookies', False)
        self._allow_private = kwargs.pop('allow_private', False)

        super(OfflineDomainNameAnalysis, self).__init__(*args, **kwargs)

        if self.analysis_type != ANALYSIS_TYPE_AUTHORITATIVE:
            self._query_cls = Q.MultiQueryAggregateDNSResponse

        # Shortcuts to the values in the SOA record.
        self.serial = None
        self.rname = None
        self.mname = None

        self.dnssec_algorithms_in_dnskey = set()
        self.dnssec_algorithms_in_ds = set()
        self.dnssec_algorithms_in_dlv = set()
        self.dnssec_algorithms_digest_in_ds = set()
        self.dnssec_algorithms_digest_in_dlv = set()

        self.status = None
        self.yxdomain = None
        self.yxrrset = None
        self.yxrrset_proper = None
        self.nxrrset = None
        self.rrset_warnings = None
        self.rrset_errors = None
        self.rrsig_status = None
        self.response_component_status = None
        self.wildcard_status = None
        self.dname_status = None
        self.nxdomain_status = None
        self.nxdomain_warnings = None
        self.nxdomain_errors = None
        self.nodata_status = None
        self.nodata_warnings = None
        self.nodata_errors = None
        self.response_errors = None
        self.response_warnings = None

        self.ds_status_by_ds = None
        self.ds_status_by_dnskey = None

        self.zone_errors = None
        self.zone_warnings = None
        self.zone_status = None

        self.delegation_warnings = None
        self.delegation_errors = None
        self.delegation_status = None

        self.published_keys = None
        self.revoked_keys = None
        self.zsks = None
        self.ksks = None
        self.dnskey_with_ds = None

        self._dnskey_sets = None
        self._dnskeys = None

    def _signed(self):
        return bool(self.dnssec_algorithms_in_dnskey or self.dnssec_algorithms_in_ds or self.dnssec_algorithms_in_dlv)
    signed = property(_signed)

    def _handle_soa_response(self, rrset):
        '''Indicate that there exists an SOA record for the name which is the
        subject of this analysis, and save the relevant parts.'''

        self.has_soa = True
        if self.serial is None or rrset[0].serial > self.serial:
            self.serial = rrset[0].serial
            self.rname = rrset[0].rname
            self.mname = rrset[0].mname

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

    def _process_response_answer_rrset(self, rrset, query, response):
        super(OfflineDomainNameAnalysis, self)._process_response_answer_rrset(rrset, query, response)
        if query.qname in (self.name, self.dlv_name):
            if rrset.rdtype == dns.rdatatype.SOA:
                self._handle_soa_response(rrset)
            elif rrset.rdtype == dns.rdatatype.DNSKEY:
                self._handle_dnskey_response(rrset)
            elif rrset.rdtype in (dns.rdatatype.DS, dns.rdatatype.DLV):
                self._handle_ds_response(rrset)

    def _index_dnskeys(self):
        if self._dnskey_sets is not None:
            return

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
        return list(self._dnskeys.values())

    def potential_trusted_keys(self):
        active_ksks = self.ksks.difference(self.zsks).difference(self.revoked_keys)
        if active_ksks:
            return active_ksks
        return self.ksks.difference(self.revoked_keys)

    def _create_response_info_recursive(self, name, rdtype, name_to_info_mapping, rrset_to_cname_mapping, trace=None):
        zone_obj = self.get_name(name).zone
        info_obj = AggregateResponseInfo(name, rdtype, self, zone_obj)

        if trace is None:
            trace = [name]

        for info in name_to_info_mapping[name]:
            if info in rrset_to_cname_mapping:
                target = info.rrset[0].target
                if target not in trace:
                    cname_info = self._create_response_info_recursive(rrset_to_cname_mapping[info], rdtype, name_to_info_mapping, rrset_to_cname_mapping, trace=trace + [target])
                else:
                    cname_info = None
            else:
                cname_info = None
            info_obj.add_response_info(info, cname_info)
        return info_obj

    def _get_response_info(self, name, rdtype):
        #XXX there are reasons for this (e.g., NXDOMAIN, after which no further
        # queries are made), but it would be good to have a sanity check, so
        # we don't simply produce an incomplete output.
        # see also: dnsviz.viz.dnssec.graph_rrset_auth()
        if (name, rdtype) not in self.queries:
            return None

        query = self.queries[(name, rdtype)]
        name_to_info_mapping = {}
        rrset_to_cname_mapping = {}

        name_to_info_mapping[name] = []

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

            # make sure this query was made to a server designated as
            # authoritative
            z_obj = self.zone
            if self.is_zone() and neg_response_info.rdtype == dns.rdatatype.DS:
                z_obj = self.zone.parent
            if not set([s for (s,c) in neg_response_info.servers_clients]).intersection(z_obj.get_auth_or_designated_servers()):
                continue

            if neg_response_info.qname not in name_to_info_mapping:
                name_to_info_mapping[neg_response_info.qname] = []
            name_to_info_mapping[neg_response_info.qname].append(neg_response_info)

        for error in self.response_errors[query]:
            name_to_info_mapping[name].append(error)

        for warning in self.response_warnings[query]:
            name_to_info_mapping[name].append(warning)

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
            self._response_info[(name, rdtype)] = None
            self._response_info[(name, rdtype)] = self._get_response_info(name, rdtype)
        return self._response_info[(name, rdtype)]

    def _serialize_nsec_set_simple(self, nsec_set_info, neg_status, response_info):
        nsec_tup = []
        if neg_status[nsec_set_info]:
            for nsec_status in neg_status[nsec_set_info]:
                # assign the "overall" status of the NSEC proof, based on both
                # the correctness of the NSEC proof as well as the
                # authentication status of the collective records comprising
                # the proof.
                #
                # if the proof is not valid, then use the validity status of
                # the proof as the overall status.
                if nsec_status.validation_status != Status.NSEC_STATUS_VALID:
                    status = Status.nsec_status_mapping[nsec_status.validation_status]
                # else (the NSEC proof is valid)
                else:
                    # if there is a component status, then set the overall
                    # status to the authentication status of collective records
                    # comprising the proof (the proof is only as good as it is
                    # authenticated).
                    if self.response_component_status is not None:
                        status = Status.rrset_status_mapping[self.response_component_status[nsec_status.nsec_set_info]]
                    # otherwise, set the overall status to insecure
                    else:
                        status = Status.rrset_status_mapping[Status.RRSET_STATUS_INSECURE]

                warnings = [w.terse_description for w in nsec_status.warnings]
                errors = [e.terse_description for e in nsec_status.errors]

                children = []
                for nsec_rrset_info in nsec_status.nsec_set_info.rrsets.values():
                    children.append(self._serialize_response_component_simple(nsec_rrset_info.rrset.rdtype, response_info, nsec_rrset_info, True))

                nsec_tup.append(('PROOF', status, [], [], [(Status.nsec_status_mapping[nsec_status.validation_status], warnings, errors, '')], children))

        return nsec_tup

    def _serialize_rrsig_simple(self, name_obj, rrset_info):
        rrsig_tup = []
        if name_obj.rrsig_status[rrset_info]:
            rrsigs = list(name_obj.rrsig_status[rrset_info].keys())
            rrsigs.sort()
            for rrsig in rrsigs:
                dnskeys = list(name_obj.rrsig_status[rrset_info][rrsig].keys())
                dnskeys.sort()
                for dnskey in dnskeys:
                    rrsig_status = name_obj.rrsig_status[rrset_info][rrsig][dnskey]

                    # assign the "overall" status of the RRSIG, based on both
                    # the validity of the RRSIG as well as the authentication
                    # status of the DNSKEY with which it is validated
                    #
                    # if the RRSIG is not valid, then use the RRSIG status as
                    # the overall status
                    if rrsig_status.validation_status != Status.RRSIG_STATUS_VALID:
                        status = Status.rrsig_status_mapping[rrsig_status.validation_status]
                    # else (the status of the RRSIG is valid)
                    else:
                        # if there is a component status, then set the overall
                        # status to that of the status of the DNSKEY (an RRSIG
                        # is only as authentic as the DNSKEY that signs it)
                        if self.response_component_status is not None:
                            status = Status.rrset_status_mapping[self.response_component_status[dnskey]]
                        # otherwise, set the overall status to insecure
                        else:
                            status = Status.rrset_status_mapping[Status.RRSET_STATUS_INSECURE]

                    warnings = [w.terse_description for w in rrsig_status.warnings]
                    errors = [e.terse_description for e in rrsig_status.errors]
                    rrsig_tup.append(('RRSIG', status, [], [], [(Status.rrsig_status_mapping[rrsig_status.validation_status], warnings, errors, '%s/%s/%s (%s - %s)' % \
                            (fmt.humanize_name(rrsig.signer), rrsig.algorithm, rrsig.key_tag, fmt.timestamp_to_str(rrsig.inception)[:10], fmt.timestamp_to_str(rrsig.expiration)[:10]))], []))
        return rrsig_tup

    def _serialize_response_component_simple(self, rdtype, response_info, info, show_neg_response, dname_status=None):
        rdata = []
        if isinstance(info, Errors.DomainNameAnalysisError):
            query = response_info.name_obj.queries[(response_info.qname, response_info.rdtype)]
            if info in response_info.name_obj.response_warnings[query]:
                status = 'WARNING'
            else:
                status = 'ERROR'
        else:
            if self.response_component_status is not None:
                status = Status.rrset_status_mapping[self.response_component_status[info]]
            else:
                status = Status.rrset_status_mapping[Status.RRSET_STATUS_INSECURE]

        rdata_tup = []
        children = []
        if isinstance(info, Response.RRsetInfo):
            if info.rrset.rdtype == dns.rdatatype.CNAME:
                rdata_tup.append((None, [], [], 'CNAME %s' % (lb2s(info.rrset[0].target.to_text()))))
            elif rdtype == dns.rdatatype.DNSKEY:
                for d in info.rrset:
                    dnskey_meta = response_info.name_obj._dnskeys[d]
                    warnings = [w.terse_description for w in dnskey_meta.warnings]
                    errors = [e.terse_description for e in dnskey_meta.errors]
                    rdata_tup.append(('VALID', warnings, errors, '%d/%d/%d' % (d.algorithm, dnskey_meta.key_tag, d.flags)))
            elif rdtype == dns.rdatatype.DS:
                dss = list(response_info.name_obj.ds_status_by_ds[dns.rdatatype.DS].keys())
                dss.sort()
                for ds in dss:
                    # only show the DS if in the RRset in question
                    if ds not in info.rrset:
                        continue
                    dnskeys = list(response_info.name_obj.ds_status_by_ds[rdtype][ds].keys())
                    dnskeys.sort()
                    for dnskey in dnskeys:
                        ds_status = response_info.name_obj.ds_status_by_ds[rdtype][ds][dnskey]
                        warnings = [w.terse_description for w in ds_status.warnings]
                        errors = [e.terse_description for e in ds_status.errors]
                        rdata_tup.append((Status.ds_status_mapping[ds_status.validation_status], warnings, errors, '%d/%d/%d' % (ds.algorithm, ds.key_tag, ds.digest_type)))
            elif rdtype == dns.rdatatype.NSEC3:
                rdata_tup.append((None, [], [], '%s %s' % (fmt.format_nsec3_name(info.rrset.name), fmt.format_nsec3_rrset_text(info.rrset[0].to_text()))))
            elif rdtype == dns.rdatatype.NSEC:
                rdata_tup.append((None, [], [], '%s %s' % (lb2s(info.rrset.name.to_text()), info.rrset[0].to_text())))
            elif rdtype == dns.rdatatype.DNAME:
                warnings = [w.terse_description for w in dname_status.warnings]
                errors = [e.terse_description for e in dname_status.errors]
                rdata_tup.append((Status.dname_status_mapping[dname_status.validation_status], warnings, errors, info.rrset[0].to_text()))
            else:
                rdata_tup.extend([(None, [], [], r.to_text()) for r in info.rrset])

            warnings = [w.terse_description for w in response_info.name_obj.rrset_warnings[info]]
            errors = [e.terse_description for e in response_info.name_obj.rrset_errors[info]]

            children.extend(self._serialize_rrsig_simple(response_info.name_obj, info))
            for wildcard_name in info.wildcard_info:
                children.extend(self._serialize_nsec_set_simple(info.wildcard_info[wildcard_name], response_info.name_obj.wildcard_status, response_info))

            if info in response_info.name_obj.dname_status:
                for dname_status in response_info.name_obj.dname_status[info]:
                    children.append(self._serialize_response_component_simple(dns.rdatatype.DNAME, response_info, dname_status.synthesized_cname.dname_info, True, dname_status))

        elif isinstance(info, Errors.DomainNameAnalysisError):
            warnings = []
            errors = []
            rdata_tup.append((None, [], [], '%s' % (info.terse_description)))

        elif info in self.nodata_status:
            warnings = [w.terse_description for w in response_info.name_obj.nodata_warnings[info]]
            errors = [e.terse_description for e in response_info.name_obj.nodata_errors[info]]

            # never show the negative response if show_neg_response is False
            if show_neg_response is False:
                return None
            # only show the negative response if there is a corresponding
            # status or show_neg_response is True
            if not self.nodata_status[info] and not show_neg_response:
                return None
            rdata_tup.append((None, [], [], 'NODATA'))
            for soa_rrset_info in info.soa_rrset_info:
                children.append(self._serialize_response_component_simple(dns.rdatatype.SOA, response_info, soa_rrset_info, True))
            children.extend(self._serialize_nsec_set_simple(info, response_info.name_obj.nodata_status, response_info))

        elif info in self.nxdomain_status:
            warnings = [w.terse_description for w in response_info.name_obj.nxdomain_warnings[info]]
            errors = [e.terse_description for e in response_info.name_obj.nxdomain_errors[info]]

            # never show the negative response if show_neg_response is False
            if show_neg_response is False:
                return None
            # only show the negative response if there is a corresponding
            # status or show_neg_response is True
            if not self.nxdomain_status[info] and not show_neg_response:
                return None
            rdata_tup.append((None, [], [], 'NXDOMAIN'))
            for soa_rrset_info in info.soa_rrset_info:
                children.append(self._serialize_response_component_simple(dns.rdatatype.SOA, response_info, soa_rrset_info, True))
            children.extend(self._serialize_nsec_set_simple(info, response_info.name_obj.nxdomain_status, response_info))

        return (dns.rdatatype.to_text(rdtype), status, warnings, errors, rdata_tup, children)

    def _serialize_response_component_list_simple(self, rdtype, response_info, show_neg_response):
        tup = []
        for info, cname_chain_info in response_info.response_info_list:
            val = self._serialize_response_component_simple(rdtype, response_info, info, show_neg_response)
            # this might not return a non-empty value for a negative response,
            # so we check for a non-empty value before appending it
            if val:
                tup.append(val)
        return tup

    def _serialize_status_simple(self, response_info_list, processed):
        tup = []
        cname_info_map = OrderedDict()

        # just get the first one since the names are all supposed to be the
        # same
        response_info = response_info_list[0]

        # first build the ancestry in reverse order
        ancestry = []
        parent_obj = response_info.zone_obj
        while parent_obj is not None:
            ancestry.insert(0, parent_obj)
            parent_obj = parent_obj.parent

        name_tup = None

        # now process the DS and DNSKEY for each name in the ancestry
        for parent_obj in ancestry:
            if (parent_obj.name, -1) in processed:
                continue
            processed.add((parent_obj.name, -1))

            if parent_obj.stub:
                continue

            zone_status = None
            zone_warnings = []
            zone_errors = []
            delegation_status = None
            delegation_warnings = []
            delegation_errors = []

            if parent_obj.is_zone():
                if self.response_component_status is not None:
                    zone_status = Status.delegation_status_mapping[self.response_component_status[parent_obj]]
                else:
                    zone_status = Status.delegation_status_mapping[Status.DELEGATION_STATUS_INSECURE]
                zone_warnings = [w.terse_description for w in parent_obj.zone_warnings]
                zone_errors = [e.terse_description for e in parent_obj.zone_errors]
                if parent_obj.parent is not None:
                    delegation_status = Status.delegation_status_mapping[parent_obj.delegation_status[dns.rdatatype.DS]]
                    delegation_warnings = [w.terse_description for w in parent_obj.delegation_warnings[dns.rdatatype.DS]]
                    delegation_errors = [e.terse_description for e in parent_obj.delegation_errors[dns.rdatatype.DS]]
            if parent_obj.parent is not None:
                ds_response_info = parent_obj.get_response_info(parent_obj.name, dns.rdatatype.DS)
            else:
                ds_response_info = None

            name_tup = (fmt.humanize_name(parent_obj.name), zone_status, zone_warnings, zone_errors, delegation_status, delegation_warnings, delegation_errors, [])
            tup.append(name_tup)

            if ds_response_info is not None:
                name_tup[7].extend(parent_obj._serialize_response_component_list_simple(dns.rdatatype.DS, ds_response_info, None))

            # if we only care about DS for the name itself, then don't
            # serialize the DNSKEY response
            if response_info.rdtype == dns.rdatatype.DS and parent_obj.name == response_info.qname:
                pass
            # if the servers were unresponsive, then it's possible that no
            # DNSKEY query was issued
            elif (parent_obj.name, dns.rdatatype.DNSKEY) not in parent_obj.queries:
                pass
            else:
                dnskey_response_info = parent_obj.get_response_info(parent_obj.name, dns.rdatatype.DNSKEY)
                name_tup[7].extend(parent_obj._serialize_response_component_list_simple(dns.rdatatype.DNSKEY, dnskey_response_info, False))

            parent_is_signed = parent_obj.signed

        # handle nxdomain_ancestor
        nxdomain_ancestor = response_info.name_obj.nxdomain_ancestor
        if nxdomain_ancestor is not None and \
                (nxdomain_ancestor.name, -1) not in processed:
            processed.add((nxdomain_ancestor.name, -1))

            name_tup = (fmt.humanize_name(nxdomain_ancestor.name), None, [], [], None, [], [], [])
            tup.append(name_tup)

            name_tup[7].extend(nxdomain_ancestor._serialize_response_component_list_simple(nxdomain_ancestor.referral_rdtype, nxdomain_ancestor.get_response_info(nxdomain_ancestor.name, nxdomain_ancestor.referral_rdtype), True))

        # in recursive analysis, if we don't contact any servers that are
        # valid and responsive, then we get a zone_obj (and thus
        # parent_obj, in this case) that is None (because we couldn't
        # detect any NS records in the ancestry)
        #
        # in this case, or in the case where the name is not a zone (and
        # thus changes), we create a new tuple.
        if parent_obj is None or response_info.qname != parent_obj.name or name_tup is None:
            name_tup = (fmt.humanize_name(response_info.qname), None, [], [], None, [], [], [])
            tup.append(name_tup)

        for response_info in response_info_list:
            # if we've already done this one (above) then just move along.
            # These were only done if the name is a zone.
            if response_info.name_obj.is_zone() and \
                    response_info.rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.DS):
                continue

            name_tup[7].extend(response_info.name_obj._serialize_response_component_list_simple(response_info.rdtype, response_info, True))

            # queue the cnames for later serialization
            for info, cname_info in response_info.response_info_list:
                if cname_info is None:
                    continue
                if cname_info.qname not in cname_info_map:
                    cname_info_map[cname_info.qname] = []
                cname_info_map[cname_info.qname].append(cname_info)

        # now serialize the cnames
        for qname in cname_info_map:
            tup.extend(self._serialize_status_simple(cname_info_map[qname], processed))

        return tup

    def serialize_status_simple(self, rdtypes=None, processed=None):
        if processed is None:
            processed = set()

        response_info_map = {}
        for qname, rdtype in self.queries:
            if rdtypes is None:
                # if rdtypes was not specified, then serialize all, with some exceptions
                if rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.DLV):
                    continue
            else:
                # if rdtypes was specified, then only serialize rdtypes that
                # were specified
                if qname != self.name or rdtype not in rdtypes:
                    continue
            if qname not in response_info_map:
                response_info_map[qname] = {}
            response_info_map[qname][rdtype] = self.get_response_info(qname, rdtype)

        tuples = []
        qnames = list(response_info_map.keys())
        qnames.sort()
        for qname in qnames:
            rdtypes = list(response_info_map[qname].keys())
            rdtypes.sort()
            response_info_list = [response_info_map[qname][r] for r in rdtypes]
            tuples.extend(self._serialize_status_simple(response_info_list, processed))

        return tuples

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

    def _server_responsive_with_condition(self, server, client, tcp, response_test):
        for query in self.queries.values():
            for query1 in query.queries.values():
                try:
                    if client is None:
                        clients = list(query1.responses[server].keys())
                    else:
                        clients = (client,)
                except KeyError:
                    continue

                for c in clients:
                    try:
                        response = query1.responses[server][client]
                    except KeyError:
                        continue
                    # if tcp is specified, then only follow through if the
                    # query was ultimately issued according to that value
                    if tcp is not None:
                        if tcp and not response.effective_tcp:
                            continue
                        if not tcp and response.effective_tcp:
                            continue
                    if response_test(response):
                        return True
        return False

    def server_responsive_for_action(self, server, client, tcp, action, action_arg, require_valid):
        '''Return True if at least one (optionally valid) response was returned
        by the server without the specified action.  This action is the value
        of the responsive_cause_index in the response's history.'''

        if action == Q.RETRY_ACTION_NO_CHANGE:
            return True

        elif action == Q.RETRY_ACTION_CHANGE_SPORT:
            return True

        elif action == Q.RETRY_ACTION_SET_FLAG:
            return self._server_responsive_with_condition(server, client, tcp,
                    lambda x: not (x.effective_flags & action_arg) and \

                            ((x.effective_tcp and x.tcp_responsive) or \
                            (not x.effective_tcp and x.udp_responsive)) and \
                            (not require_valid or x.is_valid_response()))

        elif action == Q.RETRY_ACTION_CLEAR_FLAG:
            return self._server_responsive_with_condition(server, client, tcp,
                    lambda x: x.effective_flags & action_arg and \

                            ((x.effective_tcp and x.tcp_responsive) or \
                            (not x.effective_tcp and x.udp_responsive)) and \
                            (not require_valid or x.is_valid_response()))

        elif action == Q.RETRY_ACTION_DISABLE_EDNS:
            return self._server_responsive_with_condition(server, client, tcp,
                    lambda x: x.effective_edns >= 0 and \

                            ((x.effective_tcp and x.tcp_responsive) or \
                            (not x.effective_tcp and x.udp_responsive)) and \
                            (not require_valid or x.is_valid_response()))

        elif action == Q.RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD:
            return self._server_responsive_with_condition(server, client, tcp,
                    lambda x: x.effective_edns >= 0 and \
                            x.effective_edns_max_udp_payload > action_arg and \
                            x.msg_size > action_arg and \

                            ((x.effective_tcp and x.tcp_responsive) or \
                            (not x.effective_tcp and x.udp_responsive)) and \
                            (not require_valid or x.is_valid_response()))

        elif action == Q.RETRY_ACTION_SET_EDNS_FLAG:
            return self._server_responsive_with_condition(server, client, tcp,
                    lambda x: x.effective_edns >= 0 and \
                            not (x.effective_edns_flags & action_arg) and \

                            ((x.effective_tcp and x.tcp_responsive) or \
                            (not x.effective_tcp and x.udp_responsive)) and \
                            (not require_valid or x.is_valid_response()))

        elif action == Q.RETRY_ACTION_CLEAR_EDNS_FLAG:
            return self._server_responsive_with_condition(server, client, tcp,
                    lambda x: x.effective_edns >= 0 and \
                            x.effective_edns_flags & action_arg and \

                            ((x.effective_tcp and x.tcp_responsive) or \
                            (not x.effective_tcp and x.udp_responsive)) and \
                            (not require_valid or x.is_valid_response()))

        elif action == Q.RETRY_ACTION_ADD_EDNS_OPTION:
            return self._server_responsive_with_condition(server, client, tcp,
                    lambda x: x.effective_edns >= 0 and \
                            not [y for y in x.effective_edns_options if action_arg == y.otype] and \

                            ((x.effective_tcp and x.tcp_responsive) or \
                            (not x.effective_tcp and x.udp_responsive)) and \
                            (not require_valid or x.is_valid_response()))

        elif action == Q.RETRY_ACTION_REMOVE_EDNS_OPTION:
            return self._server_responsive_with_condition(server, client, tcp,
                    lambda x: x.effective_edns >= 0 and \
                            [y for y in x.effective_edns_options if action_arg == y.otype] and \

                            ((x.effective_tcp and x.tcp_responsive) or \
                            (not x.effective_tcp and x.udp_responsive)) and \
                            (not require_valid or x.is_valid_response()))

        elif action == Q.RETRY_ACTION_CHANGE_EDNS_VERSION:
            return self._server_responsive_with_condition(server, client, tcp,
                    lambda x: x.effective_edns == action_arg and \

                            ((x.effective_tcp and x.tcp_responsive) or \
                            (not x.effective_tcp and x.udp_responsive)) and \
                            (not require_valid or x.is_valid_response()))

        else:
            return False

    def server_responsive_with_do(self, server, client, tcp, require_valid):
        return self._server_responsive_with_condition(server, client, tcp,
                lambda x: x.effective_edns >= 0 and \
                        x.effective_edns_flags & dns.flags.DO and \

                        ((x.effective_tcp and x.tcp_responsive) or \
                        (not x.effective_tcp and x.udp_responsive)) and \
                        (not require_valid or x.is_valid_response()))

    def _populate_status(self, trusted_keys, supported_algs=None, supported_digest_algs=None, is_dlv=False, trace=None, follow_mx=True):
        if trace is None:
            trace = []

        # avoid loops
        if self in trace:
            self._populate_name_status()
            return

        # if status has already been populated, then don't reevaluate
        if self.rrsig_status is not None:
            return

        # if we're a stub, there's nothing to evaluate
        if self.stub:
            return

        # populate status of dependencies
        for cname in self.cname_targets:
            for target, cname_obj in self.cname_targets[cname].items():
                if cname_obj is not None:
                    cname_obj._populate_status(trusted_keys, supported_algs, supported_digest_algs, trace=trace + [self])
        if follow_mx:
            for target, mx_obj in self.mx_targets.items():
                if mx_obj is not None:
                    mx_obj._populate_status(trusted_keys, supported_algs, supported_digest_algs, trace=trace + [self], follow_mx=False)
        for signer, signer_obj in self.external_signers.items():
            if signer_obj is not None:
                signer_obj._populate_status(trusted_keys, supported_algs, supported_digest_algs, trace=trace + [self])
        for target, ns_obj in self.ns_dependencies.items():
            if ns_obj is not None:
                ns_obj._populate_status(trusted_keys, supported_algs, supported_digest_algs, trace=trace + [self])

        # populate status of ancestry
        if self.nxdomain_ancestor is not None:
            self.nxdomain_ancestor._populate_status(trusted_keys, supported_algs, supported_digest_algs, trace=trace + [self])
        if self.parent is not None:
            self.parent._populate_status(trusted_keys, supported_algs, supported_digest_algs, trace=trace + [self])
        if self.dlv_parent is not None:
            self.dlv_parent._populate_status(trusted_keys, supported_algs, supported_digest_algs, is_dlv=True, trace=trace + [self])

        _logger.debug('Assessing status of %s...' % (fmt.humanize_name(self.name)))
        self._populate_name_status()
        self._index_dnskeys()
        self._populate_rrsig_status_all(supported_algs)
        self._populate_nodata_status(supported_algs)
        self._populate_nxdomain_status(supported_algs)
        self._populate_inconsistent_negative_dnssec_responses_all()
        self._finalize_key_roles()
        if not is_dlv:
            self._populate_delegation_status(supported_algs, supported_digest_algs)
        if self.dlv_parent is not None:
            self._populate_ds_status(dns.rdatatype.DLV, supported_algs, supported_digest_algs)
        self._populate_dnskey_status(trusted_keys)

    def populate_status(self, trusted_keys, supported_algs=None, supported_digest_algs=None, is_dlv=False, follow_mx=True, validate_prohibited_algs=False):
        # identify supported algorithms as intersection of explicitly supported
        # and software supported
        if supported_algs is not None:
            supported_algs.intersection_update(crypto._supported_algs)
        else:
            supported_algs = copy.copy(crypto._supported_algs)
        if supported_digest_algs is not None:
            supported_digest_algs.intersection_update(crypto._supported_digest_algs)
        else:
            supported_digest_algs = copy.copy(crypto._supported_digest_algs)

        # unless we are overriding, mark prohibited algorithms as not supported
        if not validate_prohibited_algs:
            supported_algs.difference_update(Status.DNSKEY_ALGS_VALIDATION_PROHIBITED)
            supported_digest_algs.difference_update(Status.DS_DIGEST_ALGS_VALIDATION_PROHIBITED)

        self._populate_status(trusted_keys, supported_algs, supported_digest_algs, is_dlv, None, follow_mx)

    def _populate_name_status(self, trace=None):
        # using trace allows _populate_name_status to be called independent of
        # populate_status
        if trace is None:
            trace = []

        # avoid loops
        if self in trace:
            return

        self.status = Status.NAME_STATUS_INDETERMINATE
        self.yxdomain = set()
        self.yxrrset_proper = set()
        self.yxrrset = set()
        self.nxrrset = set()

        bailiwick_map, default_bailiwick = self.get_bailiwick_mapping()

        for (qname, rdtype), query in self.queries.items():

            qname_obj = self.get_name(qname)
            if rdtype == dns.rdatatype.DS and \
                    qname_obj.name == qname and qname_obj.is_zone():
                qname_obj = qname_obj.parent
            elif rdtype == dns.rdatatype.DLV and qname == qname_obj.dlv_name:
                qname_obj = qname_obj.dlv_parent

            for rrset_info in query.answer_info:
                self.yxdomain.add(rrset_info.rrset.name)
                # for ALL types, add the name and type to yxrrset
                self.yxrrset.add((rrset_info.rrset.name, rrset_info.rrset.rdtype))
                # for all types EXCEPT where the record is a CNAME record
                # synthesized from a DNAME record, add the name and type to
                # yxrrset_proper
                if not (rrset_info.rrset.rdtype == dns.rdatatype.CNAME and rrset_info.cname_info_from_dname):
                    self.yxrrset_proper.add((rrset_info.rrset.name, rrset_info.rrset.rdtype))
                if rrset_info.dname_info is not None:
                    self.yxrrset.add((rrset_info.dname_info.rrset.name, rrset_info.dname_info.rrset.rdtype))
                for cname_rrset_info in rrset_info.cname_info_from_dname:
                    self.yxrrset.add((cname_rrset_info.dname_info.rrset.name, cname_rrset_info.dname_info.rrset.rdtype))
                    self.yxrrset.add((cname_rrset_info.rrset.name, cname_rrset_info.rrset.rdtype))
            for neg_response_info in query.nodata_info:
                for (server,client) in neg_response_info.servers_clients:
                    for response in neg_response_info.servers_clients[(server,client)]:
                        if neg_response_info.qname == qname or response.recursion_desired_and_available():
                            if not response.is_upward_referral(qname_obj.zone.name):
                                self.yxdomain.add(neg_response_info.qname)
                            self.nxrrset.add((neg_response_info.qname, neg_response_info.rdtype))
            for neg_response_info in query.nxdomain_info:
                for (server,client) in neg_response_info.servers_clients:
                    for response in neg_response_info.servers_clients[(server,client)]:
                        if neg_response_info.qname == qname or response.recursion_desired_and_available():
                            self.nxrrset.add((neg_response_info.qname, neg_response_info.rdtype))

            # now check referrals (if name hasn't already been identified as YXDOMAIN)
            if self.name == qname and self.name not in self.yxdomain:
                if rdtype not in (self.referral_rdtype, dns.rdatatype.NS):
                    continue
                try:
                    for query1 in query.queries.values():
                        for server in query1.responses:
                            bailiwick = bailiwick_map.get(server, default_bailiwick)
                            for client in query1.responses[server]:
                                if query1.responses[server][client].is_referral(self.name, rdtype, query.rdclass, bailiwick, proper=True):
                                    self.yxdomain.add(self.name)
                                    raise FoundYXDOMAIN
                except FoundYXDOMAIN:
                    pass

        # now add the values of CNAMEs
        for cname in self.cname_targets:
            for target, cname_obj in self.cname_targets[cname].items():
                if cname_obj is self:
                    continue
                if cname_obj is None:
                    continue
                if cname_obj.yxrrset is None:
                    cname_obj._populate_name_status(trace=trace + [self])
                for name, rdtype in cname_obj.yxrrset:
                    if name == target:
                        self.yxrrset.add((cname,rdtype))

        if self.name in self.yxdomain:
            self.status = Status.NAME_STATUS_NOERROR

        if self.status == Status.NAME_STATUS_INDETERMINATE:
            for (qname, rdtype), query in self.queries.items():
                if rdtype == dns.rdatatype.DS:
                    continue
                if [x for x in query.nxdomain_info if x.qname == qname]:
                    self.status = Status.NAME_STATUS_NXDOMAIN
                    break

    def _populate_responsiveness_errors(self, qname_obj, response, server, client, warnings, errors):
        # if we had to make some change to elicit a response, find out why that
        # was
        change_err = None
        if response.responsive_cause_index is not None:
            retry = response.history[response.responsive_cause_index]

            cause_err_class = None
            action_err_class = None

            cause_err_kwargs = { 'tcp': response.responsive_cause_index_tcp }
            action_err_kwargs = {}

            require_valid = False
            dnssec_downgrade_class = None

            #TODO - look for success ratio to servers due to timeout or network
            # error, for better determining if a problem is intermittent

            ####################
            # CAUSES
            #
            # Network error - kwargs: errno; don't require a valid response
            if retry.cause == Q.RETRY_CAUSE_NETWORK_ERROR:
                cause_err_class = Errors.NetworkError
                cause_err_kwargs['errno'] = errno.errorcode.get(retry.cause_arg, 'UNKNOWN')
                require_valid = False

            # Malformed response - kwargs: msg_size; require a valid response
            elif retry.cause == Q.RETRY_CAUSE_FORMERR:
                cause_err_class = Errors.FormError
                cause_err_kwargs['msg_size'] = response.msg_size
                require_valid = True

            # Timeout - kwargs: attempts; don't require a valid response
            elif retry.cause == Q.RETRY_CAUSE_TIMEOUT:
                cause_err_class = Errors.Timeout
                cause_err_kwargs['attempts'] = response.responsive_cause_index+1
                require_valid = False

            # Invalid RCODE - kwargs: rcode; require a valid response
            elif retry.cause == Q.RETRY_CAUSE_RCODE:
                # If the RCODE was FORMERR, SERVFAIL, or NOTIMP, then this is a
                # signal to the client that the server doesn't support EDNS.
                # Thus, *independent of action*, we mark this as a DNSSEC
                # downgrade, if the zone is signed.
                if retry.cause_arg in (dns.rcode.FORMERR, dns.rcode.SERVFAIL, dns.rcode.NOTIMP) and \
                        qname_obj is not None and qname_obj.zone.signed:
                    dnssec_downgrade_class = Errors.DNSSECDowngradeEDNSDisabled

                # if the RCODE was FORMERR, SERVFAIL, or NOTIMP, and the
                # corresponding action was to disable EDNS, then this was a
                # reasonable response from a server that doesn't support EDNS,
                # but it's only innocuous if the zone is not signed.
                if retry.cause_arg in (dns.rcode.FORMERR, dns.rcode.SERVFAIL, dns.rcode.NOTIMP) and \
                        retry.action == Q.RETRY_ACTION_DISABLE_EDNS and \
                        not (qname_obj is not None and qname_obj.zone.signed):
                    pass

                # or if the RCODE was BADVERS, and the corresponding action was
                # to change EDNS version, then this was a reasonable response
                # from a server that doesn't support the EDNS version
                elif retry.cause_arg == dns.rcode.BADVERS and \
                        retry.action == Q.RETRY_ACTION_CHANGE_EDNS_VERSION:
                    pass

                # or if the RCODE was SERVFAIL, and the corresponding action was
                # to set the CD flag, then this was a reasonable response
                # from a server that couldn't validate the query
                elif retry.cause_arg == dns.rcode.SERVFAIL and \
                        retry.action == Q.RETRY_ACTION_SET_FLAG and \
                        retry.action_arg == dns.flags.CD:
                    pass

                # or if the RCODE was BADCOOKIE, and the COOKIE opt we sent
                # contained only a client cookie or an invalid server cookie,
                # then this was a reasonable response from a server that
                # supports cookies
                elif retry.cause_arg == 23 and \
                        response.server_cookie_status in (Q.DNS_COOKIE_CLIENT_COOKIE_ONLY, Q.DNS_COOKIE_SERVER_COOKIE_BAD) and \
                        retry.action == Q.RETRY_ACTION_UPDATE_DNS_COOKIE:
                    pass

                # or if the RCODE was FORMERR, and the COOKIE opt we sent
                # contained a malformed cookie, then this was a reasonable
                # response from a server that supports cookies
                if retry.cause_arg == dns.rcode.FORMERR and \
                        response.server_cookie_status == Q.DNS_COOKIE_IMPROPER_LENGTH and \
                        (retry.action == Q.RETRY_ACTION_DISABLE_EDNS or \
                                (retry.action == Q.RETRY_ACTION_REMOVE_EDNS_OPTION and retry.action_arg == 10)):
                    pass

                # otherwise, set the error class and instantiation kwargs
                # appropriately
                else:
                    cause_err_class = Errors.InvalidRcode
                    cause_err_kwargs['rcode'] = dns.rcode.to_text(retry.cause_arg)
                    require_valid = True

            # Other errors
            elif retry.cause == Q.RETRY_CAUSE_OTHER:
                require_valid = True

            # by default, use the action argument as the argument
            action_arg = retry.action_arg

            ####################
            # ACTIONS
            #
            # No change was made; a valid response was received when the query
            # was issued again
            if retry.action == Q.RETRY_ACTION_NO_CHANGE:
                pass

            # Only the source port was changed; a valid response was received
            # when the query was issued again
            elif retry.action == Q.RETRY_ACTION_CHANGE_SPORT:
                pass

            # A flag was set to elicit a response; kwargs: flag
            elif retry.action == Q.RETRY_ACTION_SET_FLAG:
                action_err_class = Errors.ResponseErrorWithoutRequestFlag
                action_err_kwargs['flag'] = dns.flags.to_text(retry.action_arg)
                if not action_err_kwargs['flag']:
                    action_err_kwargs['flag'] = retry.action_arg

            # A flag was cleared to elicit a response; kwargs: flag
            elif retry.action == Q.RETRY_ACTION_CLEAR_FLAG:
                action_err_class = Errors.ResponseErrorWithRequestFlag
                action_err_kwargs['flag'] = dns.flags.to_text(retry.action_arg)
                if not action_err_kwargs['flag']:
                    action_err_kwargs['flag'] = retry.action_arg

            # EDNS was disabled to elicit a response; kwargs: None
            elif retry.action == Q.RETRY_ACTION_DISABLE_EDNS:
                action_err_class = Errors.ResponseErrorWithEDNS

                # DNSSEC was downgraded because DO bit is no longer available
                dnssec_downgrade_class = Errors.DNSSECDowngradeEDNSDisabled

            # The EDNS UDP max payload size was changed to elicit a response;
            # kwargs: pmtu_lower_bound, pmtu_upper_bound
            elif retry.action == Q.RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD:
                action_err_class = Errors.PMTUExceeded
                #TODO need bounding here
                action_err_kwargs['pmtu_lower_bound'] = None
                action_err_kwargs['pmtu_upper_bound'] = None

            # An EDNS flag was set to elicit a response; kwargs: flag
            elif retry.action == Q.RETRY_ACTION_SET_EDNS_FLAG:
                action_err_class = Errors.ResponseErrorWithoutEDNSFlag
                action_err_kwargs['flag'] = dns.flags.edns_to_text(retry.action_arg)
                if not action_err_kwargs['flag']:
                    action_err_kwargs['flag'] = retry.action_arg

            # An EDNS flag was cleared to elicit a response; kwargs: flag
            elif retry.action == Q.RETRY_ACTION_CLEAR_EDNS_FLAG:
                action_err_class = Errors.ResponseErrorWithEDNSFlag
                action_err_kwargs['flag'] = dns.flags.edns_to_text(retry.action_arg)
                if not action_err_kwargs['flag']:
                    action_err_kwargs['flag'] = retry.action_arg

                # if this was the DO flag, then DNSSEC was downgraded
                if retry.action_arg == dns.flags.DO:
                    dnssec_downgrade_class = Errors.DNSSECDowngradeDOBitCleared

            # An EDNS option was added to elicit a response; kwargs: option
            elif retry.action == Q.RETRY_ACTION_ADD_EDNS_OPTION:
                action_err_class = Errors.ResponseErrorWithoutEDNSOption
                #TODO convert numeric option ID to text
                action_err_kwargs['option'] = fmt.EDNS_OPT_DESCRIPTIONS.get(retry.action_arg, retry.action_arg)

            # An EDNS option was removed to elicit a response; kwargs: option
            elif retry.action == Q.RETRY_ACTION_REMOVE_EDNS_OPTION:
                action_err_class = Errors.ResponseErrorWithEDNSOption
                #TODO convert numeric option ID to text
                action_err_kwargs['option'] = fmt.EDNS_OPT_DESCRIPTIONS.get(retry.action_arg, retry.action_arg)

            # The EDNS version was changed to elicit a response; kwargs:
            # edns_old, edns_new
            elif retry.action == Q.RETRY_ACTION_CHANGE_EDNS_VERSION:
                action_err_class = Errors.ResponseErrorWithEDNSVersion
                action_err_kwargs['edns_old'] = response.query.edns
                action_err_kwargs['edns_new'] = retry.action_arg

                # if this was about changing EDNS version, then use the
                # original version number as the argument
                action_arg = response.query.edns

            if cause_err_class is not None and action_err_class is not None:
                if qname_obj is not None and qname_obj.zone.server_responsive_for_action(server, client, response.responsive_cause_index_tcp, \
                        retry.action, action_arg, require_valid):
                    query_specific = True
                else:
                    query_specific = False
                cause_err = cause_err_class(**cause_err_kwargs)
                change_err = action_err_class(response_error=cause_err, query_specific=query_specific, **action_err_kwargs)

        if change_err is not None:
            # if the error really matters (e.g., due to DNSSEC), note an error
            if dnssec_downgrade_class is not None and qname_obj is not None and qname_obj.zone.signed:
                Errors.DomainNameAnalysisError.insert_into_list(change_err, errors, server, client, response)
                Errors.DomainNameAnalysisError.insert_into_list(dnssec_downgrade_class(response_error=cause_err), errors, server, client, response)
            # otherwise, warn
            else:
                Errors.DomainNameAnalysisError.insert_into_list(change_err, warnings, server, client, response)

    def _populate_edns_errors(self, qname_obj, response, server, client, warnings, errors):

        # if we actually got a message response (as opposed to timeout, network
        # error, form error, etc.)
        if response.message is None:
            return

        edns_errs = []

        # if the effective request used EDNS
        if response.effective_edns >= 0:
            # if the message response didn't use EDNS, then create an error
            if response.message.edns < 0:
                # if there were indicators that the server supported EDNS
                # (e.g., by RRSIGs in the answer), then report it as such
                if [x for x in response.message.answer if x.rdtype == dns.rdatatype.RRSIG]:
                    edns_errs.append(Errors.EDNSSupportNoOpt())
                # otherwise, simply report it as a server not responding
                # properly to EDNS requests
                else:
                    edns_errs.append(Errors.EDNSIgnored())

            # the message response did use EDNS
            else:
                if response.message.rcode() == dns.rcode.BADVERS:
                    # if the message response code was BADVERS, then the EDNS
                    # version in the response should have been less than
                    # that of the request
                    if response.message.edns >= response.effective_edns:
                        edns_errs.append(Errors.ImplementedEDNSVersionNotProvided(request_version=response.effective_edns, response_version=response.message.edns))

                # if the message response used a version of EDNS other than
                # that requested, then create an error (should have been
                # answered with BADVERS)
                elif response.message.edns != response.effective_edns:
                    edns_errs.append(Errors.EDNSVersionMismatch(request_version=response.effective_edns, response_version=response.message.edns))

                # check that all EDNS flags are all zero, except for DO
                undefined_edns_flags_set = (response.message.ednsflags & 0xffff) & ~EDNS_DEFINED_FLAGS
                if undefined_edns_flags_set:
                    edns_errs.append(Errors.EDNSUndefinedFlagsSet(flags=undefined_edns_flags_set))

        else:
            # if the effective request didn't use EDNS, and we got a
            # message response with an OPT record
            if response.message.edns >= 0:
                edns_errs.append(Errors.GratuitousOPT())

        for edns_err in edns_errs:
            Errors.DomainNameAnalysisError.insert_into_list(edns_err, warnings, server, client, response)

    def _populate_cookie_errors(self, qname_obj, response, server, client, warnings, errors):

        if response.message is None:
            return

        cookie_errs = []

        try:
            cookie_opt = [o for o in response.effective_edns_options if o.otype == 10][0]
        except IndexError:
            cookie_opt = None

        try:
            cookie_opt_from_server = [o for o in response.message.options if o.otype == 10][0]
        except IndexError:
            cookie_opt_from_server = None

        # supports_cookies is a boolean value that indicates whether the server
        # supports DNS cookies.  Note that we are not looking for the value of
        # the server cookie itself, only whether the server supports cookies,
        # so we don't need to use get_cookie_jar_mapping().
        supports_cookies =  qname_obj is not None and server in qname_obj.cookie_jar

        # RFC 7873: 5.2.1.  No OPT RR or No COOKIE Option
        if response.query.edns < 0 or cookie_opt is None: # response.effective_server_cookie_status == Q.DNS_COOKIE_NO_COOKIE
            if cookie_opt_from_server is not None:
                cookie_errs.append(Errors.GratuitousCookie())

        elif supports_cookies:
            # The following are scenarios for DNS cookies.

            # RFC 7873: 5.2.2.  Malformed COOKIE Option
            if response.server_cookie_status == Q.DNS_COOKIE_IMPROPER_LENGTH:

                issued_formerr = False
                if response.effective_server_cookie_status == Q.DNS_COOKIE_IMPROPER_LENGTH:
                    if response.message.rcode() == dns.rcode.FORMERR:
                        # The query resulting in the response we got was sent
                        # with a COOKIE option with improper length, and the
                        # return code for the response was FORMERR.
                        issued_formerr = True
                elif response.responsive_cause_index is not None:
                    retry = response.history[response.responsive_cause_index]
                    if retry.cause == Q.RETRY_CAUSE_RCODE and \
                            retry.cause_arg == dns.rcode.FORMERR and \
                            (retry.action == Q.RETRY_ACTION_DISABLE_EDNS or \
                                    (retry.action == Q.RETRY_ACTION_REMOVE_EDNS_OPTION and retry.action_arg == 10)):
                        # We started with a COOKIE opt with improper length,
                        # and, in response to FORMERR, from the server, we
                        # changed EDNS behavior either by disabling EDNS or
                        # removing the DNS COOKIE OPT, which resulted in us
                        # getting a legitimate response.
                        issued_formerr = True
                if not issued_formerr:
                    cookie_errs.append(Errors.MalformedCookieWithoutFORMERR())

            # RFC 7873: 5.2.3.  Only a Client Cookie
            # RFC 7873: 5.2.4.  A Client Cookie and an Invalid Server Cookie
            if response.server_cookie_status in (Q.DNS_COOKIE_CLIENT_COOKIE_ONLY, Q.DNS_COOKIE_SERVER_COOKIE_BAD):
                if response.server_cookie_status == Q.DNS_COOKIE_CLIENT_COOKIE_ONLY:
                    err_cls = Errors.NoServerCookieWithoutBADCOOKIE
                else:
                    err_cls = Errors.InvalidServerCookieWithoutBADCOOKIE

                issued_badcookie = False
                if response.effective_server_cookie_status in (Q.DNS_COOKIE_CLIENT_COOKIE_ONLY, Q.DNS_COOKIE_SERVER_COOKIE_BAD):
                    # The query resulting in the response we got was sent with
                    # a bad server cookie.
                    if cookie_opt_from_server is None:
                        cookie_errs.append(Errors.NoCookieOption())
                    elif len(cookie_opt_from_server.data) == 8:
                        cookie_errs.append(Errors.NoServerCookie())

                    if response.message.rcode() == 23:
                        # The query resulting in the response we got was sent
                        # with an invalid server cookie, and the result was
                        # BADCOOKIE.
                        issued_badcookie = True

                elif response.responsive_cause_index is not None:
                    retry = response.history[response.responsive_cause_index]
                    if retry.cause == Q.RETRY_CAUSE_RCODE and \
                            retry.cause_arg == 23 and \
                            retry.action == Q.RETRY_ACTION_UPDATE_DNS_COOKIE:
                        # We started with a COOKIE opt with an invalid server
                        # cookie, and, in response to a BADCOOKIE response from
                        # the server, we updated to a fresh DNS server cookie,
                        # which resulted in us getting a legitimate response.
                        issued_badcookie = True

                if self._strict_cookies and not issued_badcookie:
                    cookie_errs.append(err_cls())

            # RFC 7873: 5.2.5.  A Client Cookie and a Valid Server Cookie
            if response.effective_server_cookie_status == Q.DNS_COOKIE_SERVER_COOKIE_FRESH:
                # The query resulting in the response we got was sent with only
                # a client cookie.
                if cookie_opt_from_server is None:
                    cookie_errs.append(Errors.NoCookieOption())
                elif len(cookie_opt_from_server.data) == 8:
                    cookie_errs.append(Errors.NoServerCookie())

        if cookie_opt is not None and cookie_opt_from_server is not None:
            # RFC 7873: 5.3.  Client cookie does not match
            if len(cookie_opt_from_server.data) >= 8 and \
                    cookie_opt_from_server.data[:8] != cookie_opt.data[:8]:
                cookie_errs.append(Errors.ClientCookieMismatch())

            # RFC 7873: 5.3.  Client cookie has and invalid length
            if len(cookie_opt_from_server.data) < 8 or \
                    len(cookie_opt_from_server.data) > 40:
                cookie_errs.append(Errors.CookieInvalidLength(length=len(cookie_opt_from_server.data)))

        for cookie_err in cookie_errs:
            Errors.DomainNameAnalysisError.insert_into_list(cookie_err, warnings, server, client, response)

    def _populate_response_errors(self, qname_obj, response, server, client, warnings, errors):
        query = response.query

        if qname_obj is not None:
            # if the response was complete (not truncated), then mark any
            # response flag issues as errors.  Otherwise, mark them as
            # warnings.
            if response.is_complete_response():
                group = errors
            else:
                group = warnings
            if qname_obj.analysis_type == ANALYSIS_TYPE_AUTHORITATIVE:
                if not response.is_authoritative():
                    ds_referral = False
                    if query.rdtype == dns.rdatatype.DS:
                        # handle DS as a special case
                        if response.is_referral(query.qname, query.rdtype, query.rdclass, qname_obj.name):
                            ds_referral = True

                    if ds_referral:
                        Errors.DomainNameAnalysisError.insert_into_list(Errors.ReferralForDSQuery(parent=fmt.humanize_name(qname_obj.name)), group, server, client, response)
                    else:
                        Errors.DomainNameAnalysisError.insert_into_list(Errors.NotAuthoritative(), group, server, client, response)

            elif qname_obj.analysis_type == ANALYSIS_TYPE_RECURSIVE:
                if response.recursion_desired() and not response.recursion_available():
                    Errors.DomainNameAnalysisError.insert_into_list(Errors.RecursionNotAvailable(), group, server, client, response)

            # check for NOERROR, inconsistent with NXDOMAIN in ancestor
            if response.is_complete_response() and response.message.rcode() == dns.rcode.NOERROR and qname_obj.nxdomain_ancestor is not None:
                Errors.DomainNameAnalysisError.insert_into_list(Errors.InconsistentNXDOMAINAncestry(qname=fmt.humanize_name(response.query.qname), ancestor_qname=fmt.humanize_name(qname_obj.nxdomain_ancestor.name)), errors, server, client, response)

    def _populate_foreign_class_warnings(self, qname_obj, response, server, client, warnings, errors):
        query = response.query
        cls = query.rdclass

        if response.message is None:
            return

        # if there was foriegn class data, then warn about it
        ans_cls = [r.rdclass for r in response.message.answer if r.rdclass != cls]
        auth_cls = [r.rdclass for r in response.message.authority if r.rdclass != cls]
        add_cls = [r.rdclass for r in response.message.additional if r.rdclass != cls]
        if ans_cls:
            Errors.DomainNameAnalysisError.insert_into_list(Errors.ForeignClassDataAnswer(cls=dns.rdataclass.to_text(ans_cls[0])), warnings, server, client, response)
        if auth_cls:
            Errors.DomainNameAnalysisError.insert_into_list(Errors.ForeignClassDataAuthority(cls=dns.rdataclass.to_text(auth_cls[0])), warnings, server, client, response)
        if add_cls:
            Errors.DomainNameAnalysisError.insert_into_list(Errors.ForeignClassDataAdditional(cls=dns.rdataclass.to_text(add_cls[0])), warnings, server, client, response)

    def _populate_case_preservation_warnings(self, qname_obj, response, server, client, warnings, errors):
        query = response.query
        msg = response.message

        # if there was a case mismatch, then warn about it
        if msg.question and query.qname.to_text() != msg.question[0].name.to_text():
            Errors.DomainNameAnalysisError.insert_into_list(Errors.CasePreservationError(qname=fmt.humanize_name(query.qname, canonicalize=False)), warnings, server, client, response)

    def _populate_wildcard_status(self, query, rrset_info, qname_obj, supported_algs):
        for wildcard_name in rrset_info.wildcard_info:
            if qname_obj is None:
                zone_name = wildcard_name.parent()
            else:
                zone_name = qname_obj.zone.name

            servers_missing_nsec = set()
            for server, client in rrset_info.wildcard_info[wildcard_name].servers_clients:
                for response in rrset_info.wildcard_info[wildcard_name].servers_clients[(server,client)]:
                    servers_missing_nsec.add((server,client,response))

            statuses = []
            status_by_response = {}
            for nsec_set_info in rrset_info.wildcard_info[wildcard_name].nsec_set_info:
                if nsec_set_info.use_nsec3:
                    status = Status.NSEC3StatusWildcard(rrset_info.rrset.name, wildcard_name, rrset_info.rrset.rdtype, zone_name, False, nsec_set_info)
                else:
                    status = Status.NSECStatusWildcard(rrset_info.rrset.name, wildcard_name, rrset_info.rrset.rdtype, zone_name, False, nsec_set_info)

                for nsec_rrset_info in nsec_set_info.rrsets.values():
                    self._populate_rrsig_status(query, nsec_rrset_info, qname_obj, supported_algs)

                if status.validation_status == Status.NSEC_STATUS_VALID:
                    if status not in statuses:
                        statuses.append(status)

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
                if status not in statuses:
                    statuses.append(status)

            self.wildcard_status[rrset_info.wildcard_info[wildcard_name]] = statuses

            for server, client, response in servers_missing_nsec:
                # by definition, DNSSEC was requested (otherwise we
                # wouldn't know this was a wildcard), so no need to
                # check for DO bit in request
                Errors.DomainNameAnalysisError.insert_into_list(Errors.MissingNSECForWildcard(), self.rrset_errors[rrset_info], server, client, response)

    def _detect_cname_loop(self, name, trace=None):
        if name not in self.cname_targets:
            return
        if trace is None:
            trace = []
        if name in trace:
            raise CNAMELoopDetected()

        for target, cname_obj in self.cname_targets[name].items():
            if cname_obj is not None:
                cname_obj._detect_cname_loop(target, trace=trace + [name])

    def _populate_cname_status(self, rrset_info):
        if rrset_info.rrset.rdtype == dns.rdatatype.CNAME:
            rdtypes = [r for (n, r) in self.yxrrset_proper if n == rrset_info.rrset.name and r != dns.rdatatype.CNAME]
            if rdtypes:
                Errors.DomainNameAnalysisError.insert_into_list(Errors.CNAMEWithOtherData(name=fmt.humanize_name(rrset_info.rrset.name)), self.rrset_warnings[rrset_info], None, None, None)

            try:
                self._detect_cname_loop(rrset_info.rrset.name)
            except CNAMELoopDetected:
                Errors.DomainNameAnalysisError.insert_into_list(Errors.CNAMELoop(), self.rrset_errors[rrset_info], None, None, None)

    def _initialize_rrset_status(self, rrset_info):
        self.rrset_warnings[rrset_info] = []
        self.rrset_errors[rrset_info] = []
        self.rrsig_status[rrset_info] = {}

    def _populate_rrsig_status(self, query, rrset_info, qname_obj, supported_algs, populate_response_errors=True):
        self._initialize_rrset_status(rrset_info)

        if qname_obj is None:
            zone_name = None
        else:
            zone_name = qname_obj.zone.name

        if qname_obj is None:
            dnssec_algorithms_in_dnskey = set()
            dnssec_algorithms_in_ds = set()
            dnssec_algorithms_in_dlv = set()
        else:
            dnssec_algorithms_in_dnskey = qname_obj.zone.dnssec_algorithms_in_dnskey
            if query.rdtype == dns.rdatatype.DLV:
                dnssec_algorithms_in_ds = set()
                dnssec_algorithms_in_dlv = set()
            else:
                dnssec_algorithms_in_ds = qname_obj.zone.dnssec_algorithms_in_ds
                dnssec_algorithms_in_dlv = qname_obj.zone.dnssec_algorithms_in_dlv

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

                if rrset_info not in self.dname_status:
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
                self_sig = rrset_info.rrset.rdtype == dns.rdatatype.DNSKEY and rrsig.signer == rrset_info.rrset.name

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
                        rrsig_status = Status.RRSIGStatus(rrset_info, rrsig, dnskey, zone_name, fmt.datetime_to_timestamp(self.analysis_end), supported_algs)
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
                                        if self.ksks is not None:
                                            self.ksks.add(rrsig_status.dnskey)
                                    else:
                                        if self.zsks is not None:
                                            self.zsks.add(rrsig_status.dnskey)

                                key = rrsig_status.rrset, rrsig_status.rrsig
                            break

            # no corresponding DNSKEY
            if not self.rrsig_status[rrset_info][rrsig]:
                rrsig_status = Status.RRSIGStatus(rrset_info, rrsig, None, zone_name, fmt.datetime_to_timestamp(self.analysis_end), supported_algs)
                self.rrsig_status[rrsig_status.rrset][rrsig_status.rrsig][None] = rrsig_status

        # list errors for rrsets with which no RRSIGs were returned or not all algorithms were accounted for
        for server,client,response in algs_signing_rrset:
            # if DNSSEC was not requested (e.g., for diagnostics purposes),
            # then don't report an issue
            if not (response.query.edns >= 0 and response.query.edns_flags & dns.flags.DO):
                continue

            errors = self.rrset_errors[rrset_info]
            # report an error if all RRSIGs are missing
            if not algs_signing_rrset[(server,client,response)]:
                if response.dnssec_requested():
                    Errors.DomainNameAnalysisError.insert_into_list(Errors.MissingRRSIG(), errors, server, client, response)
                elif qname_obj is not None and qname_obj.zone.server_responsive_with_do(server,client,response.effective_tcp,True):
                    Errors.DomainNameAnalysisError.insert_into_list(Errors.UnableToRetrieveDNSSECRecords(), errors, server, client, response)
            else:
                # report an error if RRSIGs for one or more algorithms are missing
                for alg in dnssec_algorithms_in_dnskey.difference(algs_signing_rrset[(server,client,response)]):
                    Errors.DomainNameAnalysisError.insert_into_list(Errors.MissingRRSIGForAlgDNSKEY(algorithm=alg), errors, server, client, response)
                for alg in dnssec_algorithms_in_ds.difference(algs_signing_rrset[(server,client,response)]):
                    Errors.DomainNameAnalysisError.insert_into_list(Errors.MissingRRSIGForAlgDS(algorithm=alg), errors, server, client, response)
                for alg in dnssec_algorithms_in_dlv.difference(algs_signing_rrset[(server,client,response)]):
                    Errors.DomainNameAnalysisError.insert_into_list(Errors.MissingRRSIGForAlgDLV(algorithm=alg), errors, server, client, response)

        self._populate_wildcard_status(query, rrset_info, qname_obj, supported_algs)
        self._populate_cname_status(rrset_info)

        if populate_response_errors:
            for server,client in rrset_info.servers_clients:
                for response in rrset_info.servers_clients[(server,client)]:
                    self._populate_responsiveness_errors(qname_obj, response, server, client, self.rrset_warnings[rrset_info], self.rrset_errors[rrset_info])
                    self._populate_response_errors(qname_obj, response, server, client, self.rrset_warnings[rrset_info], self.rrset_errors[rrset_info])
                    self._populate_edns_errors(qname_obj, response, server, client, self.rrset_warnings[rrset_info], self.rrset_errors[rrset_info])
                    self._populate_cookie_errors(qname_obj, response, server, client, self.rrset_warnings[rrset_info], self.rrset_errors[rrset_info])
                    self._populate_foreign_class_warnings(qname_obj, response, server, client, self.rrset_warnings[rrset_info], self.rrset_errors[rrset_info])
                    self._populate_case_preservation_warnings(qname_obj, response, server, client, self.rrset_warnings[rrset_info], self.rrset_errors[rrset_info])

    def _populate_invalid_response_status(self, query):
        self.response_errors[query] = []
        for error_info in query.error_info:
            for server, client in error_info.servers_clients:
                for response in error_info.servers_clients[(server, client)]:
                    if error_info.code == Q.RESPONSE_ERROR_NETWORK_ERROR:
                        Errors.DomainNameAnalysisError.insert_into_list(Errors.NetworkError(tcp=response.effective_tcp, errno=errno.errorcode.get(error_info.arg, 'UNKNOWN')), self.response_errors[query], server, client, response)
                    if error_info.code == Q.RESPONSE_ERROR_FORMERR:
                        #TODO determine if this was related to truncation;
                        #TODO add EDNS opt missing error, as appropriate
                        Errors.DomainNameAnalysisError.insert_into_list(Errors.FormError(tcp=response.effective_tcp, msg_size=response.msg_size), self.response_errors[query], server, client, response)
                    elif error_info.code == Q.RESPONSE_ERROR_TIMEOUT:
                        attempts = 1
                        for i in range(len(response.history) - 1, -1, -1):
                            if response.history[i].action in (Q.RETRY_ACTION_USE_TCP, Q.RETRY_ACTION_USE_UDP):
                                break
                            attempts += 1
                        Errors.DomainNameAnalysisError.insert_into_list(Errors.Timeout(tcp=response.effective_tcp, attempts=attempts), self.response_errors[query], server, client, response)
                    elif error_info.code == Q.RESPONSE_ERROR_INVALID_RCODE:
                        # if we used EDNS, the response did not, and the RCODE
                        # was FORMERR, SERVFAIL, or NOTIMP, then this is a
                        # legitimate reason for the RCODE
                        if response.effective_edns >= 0 and response.message.edns < 0 and \
                                response.message.rcode() in (dns.rcode.FORMERR, dns.rcode.SERVFAIL, dns.rcode.NOTIMP):
                            pass
                        # if we used EDNS, the response also used EDNS, and the
                        # RCODE was BADVERS, then this is a legitimate reason
                        # for the RCODE
                        elif response.effective_edns >= 0 and response.message.edns >= 0 and \
                                response.message.rcode() == dns.rcode.BADVERS:
                            pass
                        else:
                            Errors.DomainNameAnalysisError.insert_into_list(Errors.InvalidRcode(tcp=response.effective_tcp, rcode=dns.rcode.to_text(response.message.rcode())), self.response_errors[query], server, client, response)
                    elif error_info.code == Q.RESPONSE_ERROR_OTHER:
                        Errors.DomainNameAnalysisError.insert_into_list(Errors.UnknownResponseError(tcp=response.effective_tcp), self.response_errors[query], server, client, response)

        self.response_warnings[query] = []
        for referral_info in query.referral_info:
            for server, client in referral_info.servers_clients:
                for response in referral_info.servers_clients[(server, client)]:
                    if response.is_authoritative():
                        Errors.DomainNameAnalysisError.insert_into_list(Errors.AuthoritativeReferral(), self.response_warnings[query], server, client, response)

        for truncated_info in query.truncated_info:
            for server, client in truncated_info.servers_clients:
                for response in truncated_info.servers_clients[(server, client)]:
                    self._populate_responsiveness_errors(self, response, server, client, self.response_warnings[query], self.response_errors[query])
                    self._populate_response_errors(self, response, server, client, self.response_warnings[query], self.response_errors[query])
                    self._populate_edns_errors(self, response, server, client, self.response_warnings[query], self.response_errors[query])
                    self._populate_cookie_errors(self, response, server, client, self.response_warnings[query], self.response_errors[query])
                    self._populate_foreign_class_warnings(self, response, server, client, self.response_warnings[query], self.response_errors[query])
                    self._populate_case_preservation_warnings(self, response, server, client, self.response_warnings[query], self.response_errors[query])

    def _populate_rrsig_status_all(self, supported_algs):
        self.rrset_warnings = {}
        self.rrset_errors = {}
        self.rrsig_status = {}
        self.dname_status = {}
        self.wildcard_status = {}
        self.response_errors = {}
        self.response_warnings = {}

        if (self.name, dns.rdatatype.DNSKEY) in self.queries:
            self.zsks = set()
            self.ksks = set()

        _logger.debug('Assessing RRSIG status of %s...' % (fmt.humanize_name(self.name)))
        for (qname, rdtype), query in self.queries.items():

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
                if rdtype == dns.rdatatype.DS and \
                        qname_obj.name == rrset_info.rrset.name and qname_obj.is_zone():
                    qname_obj = qname_obj.parent
                elif rdtype == dns.rdatatype.DLV:
                    qname_obj = qname_obj.dlv_parent

                self._populate_rrsig_status(query, rrset_info, qname_obj, supported_algs)

            self._populate_invalid_response_status(query)

    def _finalize_key_roles(self):
        if (self.name, dns.rdatatype.DNSKEY) in self.queries:
            self.published_keys = set(self.get_dnskeys()).difference(self.zsks.union(self.ksks))
            self.revoked_keys = set([x for x in self.get_dnskeys() if x.rdata.flags & fmt.DNSKEY_FLAGS['revoke']])

    def _populate_ns_status(self, warn_no_ipv4=True, warn_no_ipv6=False):
        if not self.is_zone():
            return

        if self.parent is None:
            return

        if self.analysis_type != ANALYSIS_TYPE_AUTHORITATIVE:
            return

        if self.explicit_delegation:
            return

        all_names = self.get_ns_names()
        names_from_child = self.get_ns_names_in_child()
        names_from_parent = self.get_ns_names_in_parent()

        auth_ns_response = self.queries[(self.name, dns.rdatatype.NS)].is_valid_complete_authoritative_response_any()

        glue_mapping = self.get_glue_ip_mapping()
        auth_mapping = self.get_auth_ns_ip_mapping()

        ns_names_not_in_child = []
        ns_names_not_in_parent = []
        names_error_resolving = []
        names_with_glue_mismatch_ipv4 = []
        names_with_glue_mismatch_ipv6 = []
        names_with_no_glue_ipv4 = []
        names_with_no_glue_ipv6 = []
        names_with_no_auth_ipv4 = []
        names_with_no_auth_ipv6 = []
        names_missing_glue = []
        names_missing_auth = []

        names_auth_private = set()
        names_auth_zero = set()
        names_glue_private = set()
        names_glue_zero = set()

        for name in all_names:
            # if name resolution resulted in an error (other than NXDOMAIN)
            if name not in auth_mapping:
                auth_addrs = set()
                names_error_resolving.append(name)
            else:
                auth_addrs = auth_mapping[name]
                # if name resolution completed successfully, but the response was
                # negative for both A and AAAA (NXDOMAIN or NODATA)
                if not auth_mapping[name]:
                    names_missing_auth.append(name)

                for addr in auth_addrs:
                    if LOOPBACK_IPV4_RE.match(addr) or addr == LOOPBACK_IPV6 or \
                            RFC_1918_RE.match(addr) or LINK_LOCAL_RE.match(addr) or UNIQ_LOCAL_RE.match(addr):
                        names_auth_private.add(name)
                    if ZERO_SLASH8_RE.search(addr):
                        names_auth_zero.add(name)

            if names_from_parent:
                name_in_parent = name in names_from_parent
            elif self.delegation_status == Status.DELEGATION_STATUS_INCOMPLETE:
                name_in_parent = False
            else:
                name_in_parent = None

            if name_in_parent:
                # if glue is required and not supplied
                if name.is_subdomain(self.name) and not glue_mapping[name]:
                    names_missing_glue.append(name)

                for addr in glue_mapping[name]:
                    if LOOPBACK_IPV4_RE.match(addr) or addr == LOOPBACK_IPV6 or \
                            RFC_1918_RE.match(addr) or LINK_LOCAL_RE.match(addr) or UNIQ_LOCAL_RE.match(addr):
                        names_glue_private.add(name)
                    if ZERO_SLASH8_RE.search(addr):
                        names_glue_zero.add(name)

                # if there are both glue and authoritative addresses supplied, check that it matches the authoritative response
                if glue_mapping[name] and auth_addrs:
                    # there are authoritative address records either of type A
                    # or AAAA and also glue records of either type A or AAAA

                    glue_addrs_ipv4 = set([x for x in glue_mapping[name] if x.version == 4])
                    glue_addrs_ipv6 = set([x for x in glue_mapping[name] if x.version == 6])
                    auth_addrs_ipv4 = set([x for x in auth_addrs if x.version == 4])
                    auth_addrs_ipv6 = set([x for x in auth_addrs if x.version == 6])

                    if auth_addrs_ipv4:
                        # there are authoritative A records for the name...
                        if not glue_addrs_ipv4:
                            # ...but no A glue
                            names_with_no_glue_ipv4.append(name)
                        elif glue_addrs_ipv4 != auth_addrs_ipv4:
                            # ...but the A glue does not match
                            names_with_glue_mismatch_ipv4.append((name, glue_addrs_ipv4, auth_addrs_ipv4))
                    elif glue_addrs_ipv4:
                        # there are A glue records for the name
                        # but no authoritative A records.
                        names_with_no_auth_ipv4.append(name)

                    if auth_addrs_ipv6:
                        # there are authoritative AAAA records for the name
                        if not glue_addrs_ipv6:
                            # ...but no AAAA glue
                            names_with_no_glue_ipv6.append(name)
                        elif glue_addrs_ipv6 != auth_addrs_ipv6:
                            # ...but the AAAA glue does not match
                            names_with_glue_mismatch_ipv6.append((name, glue_addrs_ipv6, auth_addrs_ipv6))
                    elif glue_addrs_ipv6:
                        # there are AAAA glue records for the name
                        # but no authoritative AAAA records.
                        names_with_no_auth_ipv6.append(name)

            elif name_in_parent is False:
                ns_names_not_in_parent.append(name)

            if name not in names_from_child and auth_ns_response:
                ns_names_not_in_child.append(name)

        if ns_names_not_in_child:
            ns_names_not_in_child.sort()
            self.delegation_warnings[dns.rdatatype.DS].append(Errors.NSNameNotInChild(names=[fmt.humanize_name(x) for x in ns_names_not_in_child], parent=fmt.humanize_name(self.parent_name())))

        if ns_names_not_in_parent:
            ns_names_not_in_child.sort()
            self.delegation_warnings[dns.rdatatype.DS].append(Errors.NSNameNotInParent(names=[fmt.humanize_name(x) for x in ns_names_not_in_parent], parent=fmt.humanize_name(self.parent_name())))

        if names_error_resolving:
            names_error_resolving.sort()
            self.zone_errors.append(Errors.ErrorResolvingNSName(names=[fmt.humanize_name(x) for x in names_error_resolving]))

        if not self._allow_private:
            if names_auth_private:
                names_auth_private = list(names_auth_private)
                names_auth_private.sort()
                self.zone_errors.append(Errors.NSNameResolvesToPrivateIP(names=[fmt.humanize_name(x) for x in names_auth_private]))

            if names_glue_private:
                names_glue_private = list(names_glue_private)
                names_glue_private.sort()
                self.delegation_errors[dns.rdatatype.DS].append(Errors.GlueReferencesPrivateIP(names=[fmt.humanize_name(x) for x in names_glue_private]))

        if names_with_no_glue_ipv4:
            names_with_no_glue_ipv4.sort()
            for name in names_with_no_glue_ipv4:
                self.delegation_warnings[dns.rdatatype.DS].append(Errors.MissingGlueIPv4(name=fmt.humanize_name(name)))

        if names_with_no_glue_ipv6:
            names_with_no_glue_ipv6.sort()
            for name in names_with_no_glue_ipv6:
                self.delegation_warnings[dns.rdatatype.DS].append(Errors.MissingGlueIPv6(name=fmt.humanize_name(name)))

        if names_with_no_auth_ipv4:
            names_with_no_auth_ipv4.sort()
            for name in names_with_no_auth_ipv4:
                self.delegation_warnings[dns.rdatatype.DS].append(Errors.ExtraGlueIPv4(name=fmt.humanize_name(name)))

        if names_with_no_auth_ipv6:
            names_with_no_auth_ipv6.sort()
            for name in names_with_no_auth_ipv6:
                self.delegation_warnings[dns.rdatatype.DS].append(Errors.ExtraGlueIPv6(name=fmt.humanize_name(name)))

        if names_with_glue_mismatch_ipv4:
            names_with_glue_mismatch_ipv4.sort()
            for name, glue_addrs, auth_addrs in names_with_glue_mismatch_ipv4:
                glue_addrs = list(glue_addrs)
                glue_addrs.sort()
                auth_addrs = list(auth_addrs)
                auth_addrs.sort()
                self.delegation_warnings[dns.rdatatype.DS].append(Errors.GlueMismatchError(name=fmt.humanize_name(name), glue_addresses=glue_addrs, auth_addresses=auth_addrs))

        if names_with_glue_mismatch_ipv6:
            names_with_glue_mismatch_ipv6.sort()
            for name, glue_addrs, auth_addrs in names_with_glue_mismatch_ipv6:
                glue_addrs = list(glue_addrs)
                glue_addrs.sort()
                auth_addrs = list(auth_addrs)
                auth_addrs.sort()
                self.delegation_warnings[dns.rdatatype.DS].append(Errors.GlueMismatchError(name=fmt.humanize_name(name), glue_addresses=glue_addrs, auth_addresses=auth_addrs))

        if names_missing_glue:
            names_missing_glue.sort()
            self.delegation_warnings[dns.rdatatype.DS].append(Errors.MissingGlueForNSName(names=[fmt.humanize_name(x) for x in names_missing_glue]))

        if names_missing_auth:
            names_missing_auth.sort()
            self.zone_errors.append(Errors.NoAddressForNSName(names=[fmt.humanize_name(x) for x in names_missing_auth]))

        ips_from_parent = self.get_servers_in_parent()
        ips_from_parent_ipv4 = [x for x in ips_from_parent if x.version == 4]
        ips_from_parent_ipv6 = [x for x in ips_from_parent if x.version == 6]

        ips_from_child = self.get_servers_in_child()
        ips_from_child_ipv4 = [x for x in ips_from_child if x.version == 4]
        ips_from_child_ipv6 = [x for x in ips_from_child if x.version == 6]

        if not (ips_from_parent_ipv4 or ips_from_child_ipv4) and warn_no_ipv4:
            if ips_from_parent_ipv4:
                reference = 'child'
            elif ips_from_child_ipv4:
                reference = 'parent'
            else:
                reference = 'parent or child'
            self.zone_warnings.append(Errors.NoNSAddressesForIPv4(reference=reference))

        if not (ips_from_parent_ipv6 or ips_from_child_ipv6) and warn_no_ipv6:
            if ips_from_parent_ipv6:
                reference = 'child'
            elif ips_from_child_ipv6:
                reference = 'parent'
            else:
                reference = 'parent or child'
            self.zone_warnings.append(Errors.NoNSAddressesForIPv6(reference=reference))

    def _populate_delegation_status(self, supported_algs, supported_digest_algs):
        self.ds_status_by_ds = {}
        self.ds_status_by_dnskey = {}
        self.zone_errors = []
        self.zone_warnings = []
        self.zone_status = []
        self.delegation_errors = {}
        self.delegation_warnings = {}
        self.delegation_status = {}
        self.dnskey_with_ds = set()

        self._populate_ds_status(dns.rdatatype.DS, supported_algs, supported_digest_algs)
        if self.dlv_parent is not None:
            self._populate_ds_status(dns.rdatatype.DLV, supported_algs, supported_digest_algs)
        self._populate_ns_status()
        self._populate_server_status()

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
        self.delegation_warnings[rdtype] = []
        self.delegation_errors[rdtype] = []
        self.delegation_status[rdtype] = None

        try:
            ds_rrset_answer_info = self.queries[(name, rdtype)].answer_info
        except KeyError:
            # zones should have DS queries
            if self.is_zone():
                raise
            else:
                return

        ds_rrset_exists = False
        secure_path = False

        bailiwick_map, default_bailiwick = self.get_bailiwick_mapping()

        if (self.name, dns.rdatatype.DNSKEY) in self.queries:
            dnskey_multiquery = self.queries[(self.name, dns.rdatatype.DNSKEY)]
        else:
            dnskey_multiquery = self._query_cls(self.name, dns.rdatatype.DNSKEY, dns.rdataclass.IN)

        # populate all the servers queried for DNSKEYs to determine
        # what problems there were with regard to DS records and if
        # there is at least one match
        dnskey_server_client_responses = set()
        for dnskey_query in dnskey_multiquery.queries.values():
            # for responsive servers consider only those designated as
            # authoritative
            for server in set(dnskey_query.responses).intersection(self.zone.get_auth_or_designated_servers()):
                bailiwick = bailiwick_map.get(server, default_bailiwick)
                for client in dnskey_query.responses[server]:
                    response = dnskey_query.responses[server][client]
                    if response.is_valid_response() and response.is_complete_response() and not response.is_referral(self.name, dns.rdatatype.DNSKEY, dnskey_query.rdclass, bailiwick):
                        dnskey_server_client_responses.add((server,client,response))

        for ds_rrset_info in ds_rrset_answer_info:
            # there are CNAMEs that show up here...
            if not (ds_rrset_info.rrset.name == name and ds_rrset_info.rrset.rdtype == rdtype):
                continue
            ds_rrset_exists = True

            # for each set of DS records provided by one or more servers,
            # identify the set of DNSSEC algorithms and the set of digest
            # algorithms per algorithm/key tag combination
            ds_algs = set()
            supported_ds_algs = set()
            for ds_rdata in ds_rrset_info.rrset:
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
                        ds_status = Status.DSStatus(ds_rdata, ds_rrset_info, dnskey, supported_digest_algs)
                        validation_status_mapping[ds_status.digest_valid].add(ds_status)

                        # if dnskey exists, then add to dnskey_with_ds
                        if ds_status.validation_status not in \
                                (Status.DS_STATUS_INDETERMINATE_NO_DNSKEY, Status.DS_STATUS_INDETERMINATE_MATCH_PRE_REVOKE):
                            self.dnskey_with_ds.add(dnskey)

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
                                                rrsig_status.validation_status == Status.RRSIG_STATUS_VALID:
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
                    ds_status = Status.DSStatus(ds_rdata, ds_rrset_info, None, supported_digest_algs)
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
                            Errors.DomainNameAnalysisError.insert_into_list(Errors.NoSEP(source=dns.rdatatype.to_text(rdtype)), self.delegation_errors[rdtype], server, client, response)

                # report an error if one or more algorithms are incorrectly validated
                for (server,client,response) in algs_signing_sep:
                    for alg in ds_algs.difference(algs_signing_sep[(server,client,response)]):
                        Errors.DomainNameAnalysisError.insert_into_list(Errors.MissingSEPForAlg(algorithm=alg, source=dns.rdatatype.to_text(rdtype)), self.delegation_errors[rdtype], server, client, response)
            else:
                Errors.DomainNameAnalysisError.insert_into_list(Errors.NoSEP(source=dns.rdatatype.to_text(rdtype)), self.delegation_errors[rdtype], None, None, None)

        if self.delegation_status[rdtype] is None:
            if ds_rrset_answer_info:
                if ds_rrset_exists:
                    # DS RRs exist
                    if secure_path:
                        # If any DNSSEC algorithms are supported, then status
                        # is bogus because there should have been matching KSK.
                        self.delegation_status[rdtype] = Status.DELEGATION_STATUS_BOGUS
                    else:
                        # If no algorithms are supported, then this is a
                        # provably insecure delegation.
                        self.delegation_status[rdtype] = Status.DELEGATION_STATUS_INSECURE
                else:
                    # Only CNAME returned for DS query.  With no DS records and
                    # no valid non-existence proof, the delegation is bogus.
                    self.delegation_status[rdtype] = Status.DELEGATION_STATUS_BOGUS
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

        # if no servers (designated or stealth authoritative) respond or none
        # respond authoritatively, then make the delegation as lame
        if not self.get_auth_or_designated_servers():
            if self.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_LAME
        elif not self.get_responsive_auth_or_designated_servers():
            if self.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_LAME
        elif not self.get_valid_auth_or_designated_servers():
            if self.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_LAME
        elif self.analysis_type == ANALYSIS_TYPE_AUTHORITATIVE and not self._auth_servers_clients:
            if self.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                self.delegation_status[rdtype] = Status.DELEGATION_STATUS_LAME

        if rdtype == dns.rdatatype.DS:
            try:
                ds_nxdomain_info = [x for x in self.queries[(name, rdtype)].nxdomain_info if x.qname == name and x.rdtype == dns.rdatatype.DS][0]
            except IndexError:
                pass
            else:
                if self.referral_rdtype is not None:
                    # now check if there is a parent server that is providing an
                    # NXDOMAIN for the referral.  If so, this is due to the
                    # delegation not being found on all servers.
                    try:
                        delegation_nxdomain_info = [x for x in self.queries[(name, self.referral_rdtype)].nxdomain_info if x.qname == name and x.rdtype == self.referral_rdtype][0]
                    except IndexError:
                        # if there were not NXDOMAINs received in response to the
                        # referral query, then use all the servers/clients
                        servers_clients = ds_nxdomain_info.servers_clients
                    else:
                        # if there were NXDOMAINs received in response to the
                        # referral query, then filter those out
                        servers_clients = set(ds_nxdomain_info.servers_clients).difference(delegation_nxdomain_info.servers_clients)
                else:
                    # if there was no referral query, then use all the
                    # servers/clients
                    servers_clients = ds_nxdomain_info.servers_clients

                # if there were any remaining NXDOMAIN responses, then add the
                # error
                if servers_clients:
                    err = Errors.NoNSInParent(parent=fmt.humanize_name(self.parent_name()))
                    for server, client in servers_clients:
                        for response in ds_nxdomain_info.servers_clients[(server, client)]:
                            err.add_server_client(server, client, response)
                    self.delegation_errors[rdtype].append(err)
                    if self.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                        self.delegation_status[rdtype] = Status.DELEGATION_STATUS_INCOMPLETE

    def _populate_server_status(self):
        if not self.is_zone():
            return

        if self.parent is None:
            return

        designated_servers = self.get_designated_servers()
        servers_queried_udp = set([x for x in self._all_servers_clients_queried if x[0] in designated_servers])
        servers_queried_tcp = set([x for x in self._all_servers_clients_queried_tcp if x[0] in designated_servers])
        servers_queried = servers_queried_udp.union(servers_queried_tcp)

        unresponsive_udp = servers_queried_udp.difference(self._responsive_servers_clients_udp)
        unresponsive_tcp = servers_queried_tcp.difference(self._responsive_servers_clients_tcp)
        invalid_response_udp = servers_queried.intersection(self._responsive_servers_clients_udp).difference(self._valid_servers_clients_udp)
        invalid_response_tcp = servers_queried.intersection(self._responsive_servers_clients_tcp).difference(self._valid_servers_clients_tcp)
        not_authoritative = servers_queried.intersection(self._valid_servers_clients_udp.union(self._valid_servers_clients_tcp)).difference(self._auth_servers_clients)

        if unresponsive_udp:
            err = Errors.ServerUnresponsiveUDP()
            for server, client in unresponsive_udp:
                err.add_server_client(server, client, None)
            self.zone_errors.append(err)

        if unresponsive_tcp:
            err = Errors.ServerUnresponsiveTCP()
            for server, client in unresponsive_tcp:
                err.add_server_client(server, client, None)
            self.zone_errors.append(err)

        if invalid_response_udp:
            err = Errors.ServerInvalidResponseUDP()
            for server, client in invalid_response_udp:
                err.add_server_client(server, client, None)
            self.zone_errors.append(err)

        if invalid_response_tcp:
            err = Errors.ServerInvalidResponseTCP()
            for server, client in invalid_response_tcp:
                err.add_server_client(server, client, None)
            self.zone_errors.append(err)

        if self.analysis_type == ANALYSIS_TYPE_AUTHORITATIVE:
            if not_authoritative:
                err = Errors.ServerNotAuthoritative()
                for server, client in not_authoritative:
                    err.add_server_client(server, client, None)
                self.zone_errors.append(err)

    def _populate_negative_response_status(self, query, neg_response_info, \
            bad_soa_error_cls, missing_soa_error_cls, upward_referral_error_cls, missing_nsec_error_cls, \
            nsec_status_cls, nsec3_status_cls, warnings, errors, supported_algs):

        qname_obj = self.get_name(neg_response_info.qname)
        is_zone = qname_obj.name == neg_response_info.qname and qname_obj.is_zone()
        if query.rdtype == dns.rdatatype.DS and is_zone:
            qname_obj = qname_obj.parent

        soa_owner_name_for_servers = {}
        servers_without_soa = set()
        servers_missing_nsec = set()

        #TODO Handle the case where a parent server sends NXDOMAIN for a
        # delegated child, even when other parent servers, send a proper
        # referral.

        # populate NXDOMAIN status for only those responses that are from
        # servers authoritative or designated as such
        auth_servers = qname_obj.zone.get_auth_or_designated_servers()
        for server, client in neg_response_info.servers_clients:
            if server not in auth_servers:
                continue
            for response in neg_response_info.servers_clients[(server, client)]:
                servers_without_soa.add((server, client, response))
                servers_missing_nsec.add((server, client, response))

                self._populate_responsiveness_errors(qname_obj, response, server, client, warnings, errors)
                self._populate_response_errors(qname_obj, response, server, client, warnings, errors)
                self._populate_edns_errors(qname_obj, response, server, client, warnings, errors)
                self._populate_cookie_errors(qname_obj, response, server, client, warnings, errors)
                self._populate_foreign_class_warnings(qname_obj, response, server, client, warnings, errors)
                self._populate_case_preservation_warnings(qname_obj, response, server, client, warnings, errors)

        for soa_rrset_info in neg_response_info.soa_rrset_info:
            soa_owner_name = soa_rrset_info.rrset.name

            self._populate_rrsig_status(query, soa_rrset_info, self.get_name(soa_owner_name), supported_algs, populate_response_errors=False)

            # make sure this query was made to a server designated as
            # authoritative
            if not set([s for (s,c) in soa_rrset_info.servers_clients]).intersection(auth_servers):
                continue

            if soa_owner_name != qname_obj.zone.name:
                err = Errors.DomainNameAnalysisError.insert_into_list(bad_soa_error_cls(soa_owner_name=fmt.humanize_name(soa_owner_name), zone_name=fmt.humanize_name(qname_obj.zone.name)), errors, None, None, None)
            else:
                err = None

            for server, client in soa_rrset_info.servers_clients:
                if server not in auth_servers:
                    continue
                for response in soa_rrset_info.servers_clients[(server, client)]:
                    servers_without_soa.remove((server, client, response))
                    soa_owner_name_for_servers[(server,client,response)] = soa_owner_name

                    if err is not None:
                        if neg_response_info.qname == query.qname or response.recursion_desired_and_available():
                            err.add_server_client(server, client, response)

        for server,client,response in servers_without_soa:
            if neg_response_info.qname == query.qname or response.recursion_desired_and_available():
                # check for an upward referral
                if upward_referral_error_cls is not None and response.is_upward_referral(qname_obj.zone.name):
                    Errors.DomainNameAnalysisError.insert_into_list(upward_referral_error_cls(), errors, server, client, response)
                else:
                    ds_referral = False
                    if query.rdtype == dns.rdatatype.DS:
                        # handle DS as a special case
                        if response.is_referral(query.qname, query.rdtype, query.rdclass, qname_obj.name):
                            ds_referral = True

                    if not ds_referral:
                        Errors.DomainNameAnalysisError.insert_into_list(missing_soa_error_cls(), errors, server, client, response)

        if upward_referral_error_cls is not None:
            try:
                index = errors.index(upward_referral_error_cls())
            except ValueError:
                pass
            else:
                upward_referral_error = errors[index]
                for notices in errors, warnings:
                    not_auth_notices = [x for x in notices if isinstance(x, Errors.NotAuthoritative)]
                    for notice in not_auth_notices:
                        for server, client in upward_referral_error.servers_clients:
                            for response in upward_referral_error.servers_clients[(server, client)]:
                                notice.remove_server_client(server, client, response)
                        if not notice.servers_clients:
                            notices.remove(notice)

        statuses = []
        status_by_response = {}
        for nsec_set_info in neg_response_info.nsec_set_info:
            status_by_soa_name = {}

            for nsec_rrset_info in nsec_set_info.rrsets.values():
                self._populate_rrsig_status(query, nsec_rrset_info, qname_obj, supported_algs, populate_response_errors=False)

            for server, client in nsec_set_info.servers_clients:
                if server not in auth_servers:
                    continue
                for response in nsec_set_info.servers_clients[(server,client)]:
                    soa_owner_name = soa_owner_name_for_servers.get((server,client,response), qname_obj.zone.name)
                    if soa_owner_name not in status_by_soa_name:
                        if nsec_set_info.use_nsec3:
                            status = nsec3_status_cls(neg_response_info.qname, query.rdtype, \
                                    soa_owner_name, is_zone, nsec_set_info)
                        else:
                            status = nsec_status_cls(neg_response_info.qname, query.rdtype, \
                                    soa_owner_name, is_zone, nsec_set_info)
                        if status.validation_status == Status.NSEC_STATUS_VALID:
                            if status not in statuses:
                                statuses.append(status)
                        status_by_soa_name[soa_owner_name] = status
                    status = status_by_soa_name[soa_owner_name]

                    if (server,client,response) in servers_missing_nsec:
                        servers_missing_nsec.remove((server,client,response))
                    if status.validation_status == Status.NSEC_STATUS_VALID:
                        if (server,client,response) in status_by_response:
                            del status_by_response[(server,client,response)]
                    elif neg_response_info.qname == query.qname or response.recursion_desired_and_available():
                        status_by_response[(server,client,response)] = status

        for (server,client,response), status in status_by_response.items():
            if status not in statuses:
                statuses.append(status)

        for server, client, response in servers_missing_nsec:
            # if DNSSEC was not requested (e.g., for diagnostics purposes),
            # then don't report an issue
            if not (response.query.edns >= 0 and response.query.edns_flags & dns.flags.DO):
                continue

            # report that no NSEC(3) records were returned
            if qname_obj.zone.signed and (neg_response_info.qname == query.qname or response.recursion_desired_and_available()):
                if response.dnssec_requested():
                    Errors.DomainNameAnalysisError.insert_into_list(missing_nsec_error_cls(), errors, server, client, response)
                elif qname_obj is not None and qname_obj.zone.server_responsive_with_do(server,client,response.effective_tcp,True):
                    Errors.DomainNameAnalysisError.insert_into_list(Errors.UnableToRetrieveDNSSECRecords(), errors, server, client, response)

        return statuses

    def _populate_nxdomain_status(self, supported_algs):
        self.nxdomain_status = {}
        self.nxdomain_warnings = {}
        self.nxdomain_errors = {}

        _logger.debug('Assessing NXDOMAIN response status of %s...' % (fmt.humanize_name(self.name)))
        for (qname, rdtype), query in self.queries.items():

            for neg_response_info in query.nxdomain_info:
                self.nxdomain_warnings[neg_response_info] = []
                self.nxdomain_errors[neg_response_info] = []
                self.nxdomain_status[neg_response_info] = \
                        self._populate_negative_response_status(query, neg_response_info, \
                                Errors.SOAOwnerNotZoneForNXDOMAIN, Errors.MissingSOAForNXDOMAIN, None, \
                                Errors.MissingNSECForNXDOMAIN, Status.NSECStatusNXDOMAIN, Status.NSEC3StatusNXDOMAIN, \
                                self.nxdomain_warnings[neg_response_info], self.nxdomain_errors[neg_response_info], \
                                supported_algs)

                # check for NOERROR/NXDOMAIN inconsistencies
                if neg_response_info.qname in self.yxdomain and rdtype not in (dns.rdatatype.DS, dns.rdatatype.DLV):
                    for (qname2, rdtype2), query2 in self.queries.items():
                        if rdtype2 in (dns.rdatatype.DS, dns.rdatatype.DLV):
                            continue

                        for rrset_info in [x for x in query2.answer_info if x.rrset.name == neg_response_info.qname]:
                            shared_servers_clients = set(rrset_info.servers_clients).intersection(neg_response_info.servers_clients)
                            if shared_servers_clients:
                                err1 = Errors.DomainNameAnalysisError.insert_into_list(Errors.InconsistentNXDOMAIN(qname=fmt.humanize_name(neg_response_info.qname), rdtype_nxdomain=dns.rdatatype.to_text(rdtype), rdtype_noerror=dns.rdatatype.to_text(query2.rdtype)), self.nxdomain_warnings[neg_response_info], None, None, None)
                                err2 = Errors.DomainNameAnalysisError.insert_into_list(Errors.InconsistentNXDOMAIN(qname=fmt.humanize_name(neg_response_info.qname), rdtype_nxdomain=dns.rdatatype.to_text(rdtype), rdtype_noerror=dns.rdatatype.to_text(query2.rdtype)), self.rrset_warnings[rrset_info], None, None, None)
                                for server, client in shared_servers_clients:
                                    for response in neg_response_info.servers_clients[(server, client)]:
                                        err1.add_server_client(server, client, response)
                                        err2.add_server_client(server, client, response)

                        for neg_response_info2 in [x for x in query2.nodata_info if x.qname == neg_response_info.qname]:
                            shared_servers_clients = set(neg_response_info2.servers_clients).intersection(neg_response_info.servers_clients)
                            if shared_servers_clients:
                                err1 = Errors.DomainNameAnalysisError.insert_into_list(Errors.InconsistentNXDOMAIN(qname=fmt.humanize_name(neg_response_info.qname), rdtype_nxdomain=dns.rdatatype.to_text(rdtype), rdtype_noerror=dns.rdatatype.to_text(query2.rdtype)), self.nxdomain_warnings[neg_response_info], None, None, None)
                                err2 = Errors.DomainNameAnalysisError.insert_into_list(Errors.InconsistentNXDOMAIN(qname=fmt.humanize_name(neg_response_info.qname), rdtype_nxdomain=dns.rdatatype.to_text(rdtype), rdtype_noerror=dns.rdatatype.to_text(query2.rdtype)), self.nodata_warnings[neg_response_info2], None, None, None)
                                for server, client in shared_servers_clients:
                                    for response in neg_response_info.servers_clients[(server, client)]:
                                        err1.add_server_client(server, client, response)
                                        err2.add_server_client(server, client, response)

    def _populate_nodata_status(self, supported_algs):
        self.nodata_status = {}
        self.nodata_warnings = {}
        self.nodata_errors = {}

        _logger.debug('Assessing NODATA response status of %s...' % (fmt.humanize_name(self.name)))
        for (qname, rdtype), query in self.queries.items():

            for neg_response_info in query.nodata_info:
                self.nodata_warnings[neg_response_info] = []
                self.nodata_errors[neg_response_info] = []
                self.nodata_status[neg_response_info] = \
                        self._populate_negative_response_status(query, neg_response_info, \
                                Errors.SOAOwnerNotZoneForNODATA, Errors.MissingSOAForNODATA, Errors.UpwardReferral, \
                                Errors.MissingNSECForNODATA, Status.NSECStatusNODATA, Status.NSEC3StatusNODATA, \
                                self.nodata_warnings[neg_response_info], self.nodata_errors[neg_response_info], \
                                supported_algs)

    def _populate_inconsistent_negative_dnssec_responses(self, neg_response_info, neg_status):
        for nsec_status in neg_status[neg_response_info]:
            queries_by_error = {
                    Errors.ExistingTypeNotInBitmapNSEC3: [],
                    Errors.ExistingTypeNotInBitmapNSEC: [],
                    Errors.ExistingCoveredNSEC3: [],
                    Errors.ExistingCoveredNSEC: [],
            }
            nsec_set_info = nsec_status.nsec_set_info
            for (qname, rdtype) in self.yxrrset_proper:
                if rdtype in (dns.rdatatype.DS, dns.rdatatype.DLV):
                    continue
                if nsec_set_info.use_nsec3:
                    status = Status.NSEC3StatusNXDOMAIN(qname, rdtype, nsec_status.origin, nsec_status.is_zone, nsec_set_info)
                    err_cls = Errors.ExistingCoveredNSEC3
                else:
                    status = Status.NSECStatusNXDOMAIN(qname, rdtype, nsec_status.origin, nsec_status.is_zone, nsec_set_info)
                    err_cls = Errors.ExistingCoveredNSEC

                if status.validation_status == Status.NSEC_STATUS_VALID and not status.opt_out:
                    queries_by_error[err_cls].append((qname, rdtype))

                if nsec_set_info.use_nsec3:
                    status = Status.NSEC3StatusNODATA(qname, rdtype, nsec_status.origin, nsec_status.is_zone, nsec_set_info)
                    err_cls = Errors.ExistingTypeNotInBitmapNSEC3
                else:
                    status = Status.NSECStatusNODATA(qname, rdtype, nsec_status.origin, nsec_status.is_zone, nsec_set_info, sname_must_match=True)
                    err_cls = Errors.ExistingTypeNotInBitmapNSEC

                if status.validation_status == Status.NSEC_STATUS_VALID and not status.opt_out:
                    queries_by_error[err_cls].append((qname, rdtype))

            for err_cls in queries_by_error:
                if not queries_by_error[err_cls]:
                    continue
                queries = [(fmt.humanize_name(qname), dns.rdatatype.to_text(rdtype)) for qname, rdtype in queries_by_error[err_cls]]
                err = Errors.DomainNameAnalysisError.insert_into_list(err_cls(queries=queries), nsec_status.errors, None, None, None)

    def _populate_inconsistent_negative_dnssec_responses_all(self):

        _logger.debug('Looking for negative responses that contradict positive responses (%s)...' % (fmt.humanize_name(self.name)))
        for (qname, rdtype), query in self.queries.items():
            if rdtype in (dns.rdatatype.DS, dns.rdatatype.DLV):
                continue
            for neg_response_info in query.nodata_info:
                self._populate_inconsistent_negative_dnssec_responses(neg_response_info, self.nodata_status)
            for neg_response_info in query.nxdomain_info:
                self._populate_inconsistent_negative_dnssec_responses(neg_response_info, self.nxdomain_status)

    def _populate_dnskey_status(self, trusted_keys):
        if (self.name, dns.rdatatype.DNSKEY) not in self.queries:
            return

        trusted_keys_rdata = set([k for z, k in trusted_keys if z == self.name])
        trusted_keys_self_signing = set()

        # buid a list of responsive servers
        bailiwick_map, default_bailiwick = self.get_bailiwick_mapping()
        servers_responsive = set()
        servers_authoritative = self.zone.get_auth_or_designated_servers()
        # only consider those servers that are supposed to answer authoritatively
        for query in self.queries[(self.name, dns.rdatatype.DNSKEY)].queries.values():
            servers_responsive.update([(server,client,query.responses[server][client]) for (server,client) in query.servers_with_valid_complete_response(bailiwick_map, default_bailiwick) if server in servers_authoritative])

        # any errors point to their own servers_clients value
        for dnskey in self.get_dnskeys():
            if dnskey.rdata in trusted_keys_rdata and dnskey in self.ksks:
                trusted_keys_self_signing.add(dnskey)
            if dnskey in self.revoked_keys and dnskey not in self.ksks:
                err = Errors.RevokedNotSigning()
                err.servers_clients = dnskey.servers_clients
                dnskey.errors.append(err)
            if not self.is_zone():
                err = Errors.DNSKEYNotAtZoneApex(zone=fmt.humanize_name(self.zone.name), name=fmt.humanize_name(self.name))
                err.servers_clients = dnskey.servers_clients
                dnskey.errors.append(err)

            # if there were servers responsive for the query but that didn't return the dnskey
            servers_with_dnskey = set()
            for (server,client) in dnskey.servers_clients:
                for response in dnskey.servers_clients[(server,client)]:
                    servers_with_dnskey.add((server,client,response))
            servers_clients_without = servers_responsive.difference(servers_with_dnskey)
            if servers_clients_without:
                err = Errors.DNSKEYMissingFromServers()
                # if the key is shown to be signing anything other than the
                # DNSKEY RRset, or if it associated with a DS or trust anchor,
                # then mark it as an error; otherwise, mark it as a warning.
                if dnskey in self.zsks or dnskey in self.dnskey_with_ds or dnskey.rdata in trusted_keys_rdata:
                    dnskey.errors.append(err)
                else:
                    dnskey.warnings.append(err)
                for (server,client,response) in servers_clients_without:
                    err.add_server_client(server, client, response)

            if not dnskey.rdata.key:
                dnskey.errors.append(Errors.DNSKEYZeroLength())
            elif dnskey.rdata.algorithm in DNSSEC_KEY_LENGTHS_BY_ALGORITHM and \
                    dnskey.key_len != DNSSEC_KEY_LENGTHS_BY_ALGORITHM[dnskey.rdata.algorithm]:
                dnskey.errors.append(DNSSEC_KEY_LENGTH_ERRORS[dnskey.rdata.algorithm](length=dnskey.key_len))

        if trusted_keys_rdata and not trusted_keys_self_signing:
            self.zone_errors.append(Errors.NoTrustAnchorSigning(zone=fmt.humanize_name(self.zone.name)))

    def populate_response_component_status(self, G):
        response_component_status = {}
        for obj in G.node_reverse_mapping:
            if isinstance(obj, (Response.DNSKEYMeta, Response.RRsetInfo, Response.NSECSet, Response.NegativeResponseInfo, self.__class__)):
                node_str = G.node_reverse_mapping[obj]
                status = G.status_for_node(node_str)
                response_component_status[obj] = status

                if isinstance(obj, Response.DNSKEYMeta):
                    for rrset_info in obj.rrset_info:
                        if rrset_info in G.secure_dnskey_rrsets:
                            response_component_status[rrset_info] = Status.RRSET_STATUS_SECURE
                        else:
                            response_component_status[rrset_info] = status

                # Mark each individual NSEC in the set
                elif isinstance(obj, Response.NSECSet):
                    for nsec_name in obj.rrsets:
                        nsec_name_str = lb2s(nsec_name.canonicalize().to_text()).replace(r'"', r'\"')
                        response_component_status[obj.rrsets[nsec_name]] = G.status_for_node(node_str, nsec_name_str)

                elif isinstance(obj, Response.NegativeResponseInfo):
                    # the following two cases are only for zones
                    if G.is_invis(node_str):
                        # A negative response info for a DS query points to the
                        # "top node" of a zone in the graph.  If this "top node" is
                        # colored "insecure", then it indicates that the negative
                        # response has been authenticated.  To reflect this
                        # properly, we change the status to "secure".
                        if obj.rdtype == dns.rdatatype.DS:
                            if status == Status.RRSET_STATUS_INSECURE:
                                if G.secure_nsec_nodes_covering_node(node_str):
                                    response_component_status[obj] = Status.RRSET_STATUS_SECURE

                    # for non-DNSKEY responses, verify that the negative
                    # response is secure by checking that the SOA is also
                    # secure (the fact that it is marked "secure" indicates
                    # that the NSEC proof was already authenticated)
                    if obj.rdtype != dns.rdatatype.DNSKEY:
                        # check for secure opt out
                        opt_out_secure = bool(G.secure_nsec3_optout_nodes_covering_node(node_str))
                        if status == Status.RRSET_STATUS_SECURE or \
                                (status == Status.RRSET_STATUS_INSECURE and opt_out_secure):
                            soa_secure = False
                            for soa_rrset in obj.soa_rrset_info:
                                if G.status_for_node(G.node_reverse_mapping[soa_rrset]) == Status.RRSET_STATUS_SECURE:
                                    soa_secure = True
                            if not soa_secure:
                                response_component_status[obj] = Status.RRSET_STATUS_BOGUS

        self._set_response_component_status(response_component_status)

    def _set_response_component_status(self, response_component_status, is_dlv=False, trace=None, follow_mx=True):
        if trace is None:
            trace = []

        # avoid loops
        if self in trace:
            return

        # populate status of dependencies
        for cname in self.cname_targets:
            for target, cname_obj in self.cname_targets[cname].items():
                if cname_obj is not None:
                    cname_obj._set_response_component_status(response_component_status, trace=trace + [self])
        if follow_mx:
            for target, mx_obj in self.mx_targets.items():
                if mx_obj is not None:
                    mx_obj._set_response_component_status(response_component_status, trace=trace + [self], follow_mx=False)
        for signer, signer_obj in self.external_signers.items():
            if signer_obj is not None:
                signer_obj._set_response_component_status(response_component_status, trace=trace + [self])
        for target, ns_obj in self.ns_dependencies.items():
            if ns_obj is not None:
                ns_obj._set_response_component_status(response_component_status, trace=trace + [self])

        # populate status of ancestry
        if self.nxdomain_ancestor is not None:
            self.nxdomain_ancestor._set_response_component_status(response_component_status, trace=trace + [self])
        if self.parent is not None:
            self.parent._set_response_component_status(response_component_status, trace=trace + [self])
        if self.dlv_parent is not None:
            self.dlv_parent._set_response_component_status(response_component_status, is_dlv=True, trace=trace + [self])

        self.response_component_status = response_component_status

    def _serialize_rrset_info(self, rrset_info, consolidate_clients=False, show_servers=True, show_server_meta=True, loglevel=logging.DEBUG, html_format=False):
        d = OrderedDict()

        rrsig_list = []
        if self.rrsig_status[rrset_info]:
            rrsigs = list(self.rrsig_status[rrset_info].keys())
            rrsigs.sort()
            for rrsig in rrsigs:
                dnskeys = list(self.rrsig_status[rrset_info][rrsig].keys())
                dnskeys.sort()
                for dnskey in dnskeys:
                    rrsig_status = self.rrsig_status[rrset_info][rrsig][dnskey]
                    rrsig_serialized = rrsig_status.serialize(consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format, map_ip_to_ns_name=self.zone.get_ns_name_for_ip)
                    if rrsig_serialized:
                        rrsig_list.append(rrsig_serialized)

        dname_list = []
        if rrset_info in self.dname_status:
            for dname_status in self.dname_status[rrset_info]:
                dname_serialized = dname_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format, map_ip_to_ns_name=self.zone.get_ns_name_for_ip)
                if dname_serialized:
                    dname_list.append(dname_serialized)

        wildcard_proof_list = OrderedDict()
        if rrset_info.wildcard_info:
            wildcard_names = list(rrset_info.wildcard_info.keys())
            wildcard_names.sort()
            for wildcard_name in wildcard_names:
                wildcard_name_str = lb2s(wildcard_name.canonicalize().to_text())
                wildcard_proof_list[wildcard_name_str] = []
                for nsec_status in self.wildcard_status[rrset_info.wildcard_info[wildcard_name]]:
                    nsec_serialized = nsec_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format, map_ip_to_ns_name=self.zone.get_ns_name_for_ip)
                    if nsec_serialized:
                        wildcard_proof_list[wildcard_name_str].append(nsec_serialized)
                if not wildcard_proof_list[wildcard_name_str]:
                    del wildcard_proof_list[wildcard_name_str]

        show_id = loglevel <= logging.INFO or \
                (self.rrset_warnings[rrset_info] and loglevel <= logging.WARNING) or \
                (self.rrset_errors[rrset_info] and loglevel <= logging.ERROR) or \
                (rrsig_list or dname_list or wildcard_proof_list)

        if show_id:
            if rrset_info.rrset.rdtype == dns.rdatatype.NSEC3:
                d['id'] = '%s/%s/%s' % (fmt.format_nsec3_name(rrset_info.rrset.name), dns.rdataclass.to_text(rrset_info.rrset.rdclass), dns.rdatatype.to_text(rrset_info.rrset.rdtype))
            else:
                d['id'] = '%s/%s/%s' % (lb2s(rrset_info.rrset.name.canonicalize().to_text()), dns.rdataclass.to_text(rrset_info.rrset.rdclass), dns.rdatatype.to_text(rrset_info.rrset.rdtype))

        if loglevel <= logging.DEBUG:
            d['description'] = str(rrset_info)
            d.update(rrset_info.serialize(consolidate_clients=consolidate_clients, show_servers=False, html_format=html_format, map_ip_to_ns_name=self.zone.get_ns_name_for_ip))

        if rrsig_list:
            d['rrsig'] = rrsig_list

        if dname_list:
            d['dname'] = dname_list

        if wildcard_proof_list:
            d['wildcard_proof'] = wildcard_proof_list

        if loglevel <= logging.INFO and self.response_component_status is not None:
            d['status'] = Status.rrset_status_mapping[self.response_component_status[rrset_info]]

        if loglevel <= logging.INFO and show_servers:
            servers = tuple_to_dict(rrset_info.servers_clients)
            server_list = list(servers)
            server_list.sort()
            if consolidate_clients:
                servers = server_list
            d['servers'] = servers

            ns_names = list(set([lb2s(self.zone.get_ns_name_for_ip(s)[0][0].canonicalize().to_text()) for s in servers]))
            ns_names.sort()
            d['ns_names'] = ns_names

            if show_server_meta:
                tags = set()
                nsids = set()
                cookie_tags = {}
                for server,client in rrset_info.servers_clients:
                    for response in rrset_info.servers_clients[(server,client)]:
                        tags.add(response.effective_query_tag())
                        nsid = response.nsid_val()
                        if nsid is not None:
                            nsids.add(nsid)
                        cookie_tags[server] = OrderedDict((
                            ('request', response.request_cookie_tag()),
                            ('response', response.response_cookie_tag()),
                        ))

                if nsids:
                    d['nsid_values'] = list(nsids)
                    d['nsid_values'].sort()

                d['query_options'] = list(tags)
                d['query_options'].sort()

                cookie_tag_mapping = OrderedDict()
                for server in server_list:
                    cookie_tag_mapping[server] = cookie_tags[server]
                d['cookie_status'] = cookie_tag_mapping

        if self.rrset_warnings[rrset_info] and loglevel <= logging.WARNING:
            d['warnings'] = [w.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for w in self.rrset_warnings[rrset_info]]

        if self.rrset_errors[rrset_info] and loglevel <= logging.ERROR:
            d['errors'] = [e.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for e in self.rrset_errors[rrset_info]]

        return d

    def _serialize_negative_response_info(self, neg_response_info, neg_status, warnings, errors, consolidate_clients=False, loglevel=logging.DEBUG, html_format=False):
        d = OrderedDict()

        proof_list = []
        for nsec_status in neg_status[neg_response_info]:
            nsec_serialized = nsec_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format, map_ip_to_ns_name=self.zone.get_ns_name_for_ip)
            if nsec_serialized:
                proof_list.append(nsec_serialized)

        soa_list = []
        for soa_rrset_info in neg_response_info.soa_rrset_info:
            rrset_serialized = self._serialize_rrset_info(soa_rrset_info, consolidate_clients=consolidate_clients, show_server_meta=False, loglevel=loglevel, html_format=html_format)
            if rrset_serialized:
                soa_list.append(rrset_serialized)

        show_id = loglevel <= logging.INFO or \
                (warnings[neg_response_info] and loglevel <= logging.WARNING) or \
                (errors[neg_response_info] and loglevel <= logging.ERROR) or \
                (proof_list or soa_list)

        if show_id:
            d['id'] = '%s/%s/%s' % (lb2s(neg_response_info.qname.canonicalize().to_text()), 'IN', dns.rdatatype.to_text(neg_response_info.rdtype))

        if proof_list:
            d['proof'] = proof_list

        if soa_list:
            d['soa'] = soa_list

        if loglevel <= logging.INFO and self.response_component_status is not None:
            d['status'] = Status.rrset_status_mapping[self.response_component_status[neg_response_info]]

        if loglevel <= logging.INFO:
            servers = tuple_to_dict(neg_response_info.servers_clients)
            server_list = list(servers)
            server_list.sort()
            if consolidate_clients:
                servers = server_list
            d['servers'] = servers

            ns_names = list(set([lb2s(self.zone.get_ns_name_for_ip(s)[0][0].canonicalize().to_text()) for s in servers]))
            ns_names.sort()
            d['ns_names'] = ns_names

            tags = set()
            nsids = set()
            cookie_tags = {}
            for server,client in neg_response_info.servers_clients:
                for response in neg_response_info.servers_clients[(server,client)]:
                    tags.add(response.effective_query_tag())
                    nsid = response.nsid_val()
                    if nsid is not None:
                        nsids.add(nsid)
                    cookie_tags[server] = OrderedDict((
                        ('request', response.request_cookie_tag()),
                        ('response', response.response_cookie_tag()),
                    ))

            if nsids:
                d['nsid_values'] = list(nsids)
                d['nsid_values'].sort()

            d['query_options'] = list(tags)
            d['query_options'].sort()

            cookie_tag_mapping = OrderedDict()
            for server in server_list:
                cookie_tag_mapping[server] = cookie_tags[server]
            d['cookie_status'] = cookie_tag_mapping

        if warnings[neg_response_info] and loglevel <= logging.WARNING:
            d['warnings'] = [w.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for w in warnings[neg_response_info]]

        if errors[neg_response_info] and loglevel <= logging.ERROR:
            d['errors'] = [e.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for e in errors[neg_response_info]]

        return d

    def _serialize_query_status(self, query, consolidate_clients=False, loglevel=logging.DEBUG, html_format=False):
        d = OrderedDict()
        d['answer'] = []
        d['nxdomain'] = []
        d['nodata'] = []
        d['error'] = []
        d['warning'] = []

        for rrset_info in query.answer_info:
            if rrset_info.rrset.name == query.qname or self.analysis_type == ANALYSIS_TYPE_RECURSIVE:
                rrset_serialized = self._serialize_rrset_info(rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format)
                if rrset_serialized:
                    d['answer'].append(rrset_serialized)

        for neg_response_info in query.nxdomain_info:
            # make sure this query was made to a server designated as
            # authoritative
            if not set([s for (s,c) in neg_response_info.servers_clients]).intersection(self.zone.get_auth_or_designated_servers()):
                continue
            # only look at qname
            if neg_response_info.qname == query.qname or self.analysis_type == ANALYSIS_TYPE_RECURSIVE:
                neg_response_serialized = self._serialize_negative_response_info(neg_response_info, self.nxdomain_status, self.nxdomain_warnings, self.nxdomain_errors, consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format)
                if neg_response_serialized:
                    d['nxdomain'].append(neg_response_serialized)

        for neg_response_info in query.nodata_info:
            # only look at qname
            if neg_response_info.qname == query.qname or self.analysis_type == ANALYSIS_TYPE_RECURSIVE:
                neg_response_serialized = self._serialize_negative_response_info(neg_response_info, self.nodata_status, self.nodata_warnings, self.nodata_errors, consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format)
                if neg_response_serialized:
                    d['nodata'].append(neg_response_serialized)

        if loglevel <= logging.WARNING:
            for warning in self.response_warnings[query]:
                warning_serialized = warning.serialize(consolidate_clients=consolidate_clients, html_format=html_format)
                if warning_serialized:
                    d['warning'].append(warning_serialized)

        for error in self.response_errors[query]:
            error_serialized = error.serialize(consolidate_clients=consolidate_clients, html_format=html_format)
            if error_serialized:
                d['error'].append(error_serialized)

        if not d['answer']: del d['answer']
        if not d['nxdomain']: del d['nxdomain']
        if not d['nodata']: del d['nodata']
        if not d['error']: del d['error']
        if not d['warning']: del d['warning']

        return d

    def _serialize_dnskey_status(self, consolidate_clients=False, loglevel=logging.DEBUG, html_format=False):
        d = []

        for dnskey in self.get_dnskeys():
            dnskey_serialized = dnskey.serialize(consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format, map_ip_to_ns_name=self.zone.get_ns_name_for_ip)
            if dnskey_serialized:
                if loglevel <= logging.INFO and self.response_component_status is not None:
                    dnskey_serialized['status'] = Status.rrset_status_mapping[self.response_component_status[dnskey]]
                d.append(dnskey_serialized)

        return d

    def _serialize_delegation_status(self, rdtype, consolidate_clients=False, loglevel=logging.DEBUG, html_format=False):
        d = OrderedDict()

        dss = list(self.ds_status_by_ds[rdtype].keys())
        d['ds'] = []
        dss.sort()
        for ds in dss:
            dnskeys = list(self.ds_status_by_ds[rdtype][ds].keys())
            dnskeys.sort()
            for dnskey in dnskeys:
                ds_status = self.ds_status_by_ds[rdtype][ds][dnskey]
                ds_serialized = ds_status.serialize(consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format, map_ip_to_ns_name=self.zone.get_ns_name_for_ip)
                if ds_serialized:
                    d['ds'].append(ds_serialized)
        if not d['ds']:
            del d['ds']

        try:
            neg_response_info = [x for x in self.nodata_status if x.qname == self.name and x.rdtype == rdtype][0]
            status = self.nodata_status
        except IndexError:
            try:
                neg_response_info = [x for x in self.nxdomain_status if x.qname == self.name and x.rdtype == rdtype][0]
                status = self.nxdomain_status
            except IndexError:
                neg_response_info = None

        if neg_response_info is not None:
            d['insecurity_proof'] = []
            for nsec_status in status[neg_response_info]:
                nsec_serialized = nsec_status.serialize(self._serialize_rrset_info, consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format, map_ip_to_ns_name=self.zone.get_ns_name_for_ip)
                if nsec_serialized:
                    d['insecurity_proof'].append(nsec_serialized)
            if not d['insecurity_proof']:
                del d['insecurity_proof']

        erroneous_status = self.delegation_status[rdtype] not in (Status.DELEGATION_STATUS_SECURE, Status.DELEGATION_STATUS_INSECURE)

        if loglevel <= logging.INFO or erroneous_status:
            d['status'] = Status.delegation_status_mapping[self.delegation_status[rdtype]]

        if self.delegation_warnings[rdtype] and loglevel <= logging.WARNING:
            d['warnings'] = [w.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for w in self.delegation_warnings[rdtype]]

        if self.delegation_errors[rdtype] and loglevel <= logging.ERROR:
            d['errors'] = [e.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for e in self.delegation_errors[rdtype]]

        return d

    def _serialize_zone_status(self, consolidate_clients=False, loglevel=logging.DEBUG, html_format=False):
        d = OrderedDict()

        if loglevel <= logging.DEBUG:
            glue_ip_mapping = self.get_glue_ip_mapping()
            auth_ns_ip_mapping = self.get_auth_ns_ip_mapping()
            d['servers'] = OrderedDict()
            names = list(self.get_ns_names())
            names.sort()
            for name in names:
                name_str = lb2s(name.canonicalize().to_text())
                d['servers'][name_str] = OrderedDict()
                if name in glue_ip_mapping and glue_ip_mapping[name]:
                    servers = list(glue_ip_mapping[name])
                    servers.sort()
                    d['servers'][name_str]['glue'] = servers
                if name in auth_ns_ip_mapping and auth_ns_ip_mapping[name]:
                    servers = list(auth_ns_ip_mapping[name])
                    servers.sort()
                    d['servers'][name_str]['auth'] = servers
            if not d['servers']:
                del d['servers']

            stealth_servers = self.get_stealth_servers()
            if stealth_servers:
                stealth_mapping = {}
                for server in stealth_servers:
                    names, ancestor_name = self.get_ns_name_for_ip(server)
                    for name in names:
                        if name not in stealth_mapping:
                            stealth_mapping[name] = []
                        stealth_mapping[name].append(server)

                names = list(stealth_mapping)
                names.sort()
                for name in names:
                    name_str = lb2s(name.canonicalize().to_text())
                    servers = stealth_mapping[name]
                    servers.sort()
                    d['servers'][name_str] = OrderedDict((
                        ('stealth', servers),
                    ))

        if loglevel <= logging.INFO and self.response_component_status is not None:
            d['status'] = Status.delegation_status_mapping[self.response_component_status[self]]

        if self.zone_warnings and loglevel <= logging.WARNING:
            d['warnings'] = [w.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for w in self.zone_warnings]

        if self.zone_errors and loglevel <= logging.ERROR:
            d['errors'] = [e.serialize(consolidate_clients=consolidate_clients, html_format=html_format) for e in self.zone_errors]

        return d

    def serialize_status(self, d=None, is_dlv=False, loglevel=logging.DEBUG, ancestry_only=False, level=RDTYPES_ALL, trace=None, follow_mx=True, html_format=False):
        if d is None:
            d = OrderedDict()

        if trace is None:
            trace = []

        # avoid loops
        if self in trace:
            return d

        # if we're a stub, there's no status to serialize
        if self.stub:
            return d

        name_str = lb2s(self.name.canonicalize().to_text())
        if name_str in d:
            return d

        cname_ancestry_only = self.analysis_type == ANALYSIS_TYPE_RECURSIVE

        # serialize status of dependencies first because their version of the
        # analysis might be the most complete (considering re-dos)
        if level <= self.RDTYPES_NS_TARGET:
            for cname in self.cname_targets:
                for target, cname_obj in self.cname_targets[cname].items():
                    if cname_obj is not None:
                        cname_obj.serialize_status(d, loglevel=loglevel, ancestry_only=cname_ancestry_only, level=max(self.RDTYPES_ALL_SAME_NAME, level), trace=trace + [self], html_format=html_format)
            if follow_mx:
                for target, mx_obj in self.mx_targets.items():
                    if mx_obj is not None:
                        mx_obj.serialize_status(d, loglevel=loglevel, level=max(self.RDTYPES_ALL_SAME_NAME, level), trace=trace + [self], follow_mx=False, html_format=html_format)
        if level <= self.RDTYPES_SECURE_DELEGATION:
            for signer, signer_obj in self.external_signers.items():
                signer_obj.serialize_status(d, loglevel=loglevel, level=self.RDTYPES_SECURE_DELEGATION, trace=trace + [self], html_format=html_format)
            for target, ns_obj in self.ns_dependencies.items():
                if ns_obj is not None:
                    ns_obj.serialize_status(d, loglevel=loglevel, level=self.RDTYPES_NS_TARGET, trace=trace + [self], html_format=html_format)

        # serialize status of ancestry
        if level <= self.RDTYPES_SECURE_DELEGATION:
            if self.nxdomain_ancestor is not None:
                self.nxdomain_ancestor.serialize_status(d, loglevel=loglevel, level=self.RDTYPES_ALL_SAME_NAME, trace=trace + [self], html_format=html_format)
            if self.parent is not None:
                self.parent.serialize_status(d, loglevel=loglevel, level=self.RDTYPES_SECURE_DELEGATION, trace=trace + [self], html_format=html_format)
            if self.dlv_parent is not None:
                self.dlv_parent.serialize_status(d, is_dlv=True, loglevel=loglevel, level=self.RDTYPES_SECURE_DELEGATION, trace=trace + [self], html_format=html_format)

        # if we're only looking for the secure ancestry of a name, and not the
        # name itself (i.e., because this is a subsequent name in a CNAME
        # chain)
        if ancestry_only:

            # only proceed if the name is a zone (and thus as DNSKEY, DS, etc.)
            if not self.is_zone():
                return d

            # explicitly set the level to self.RDTYPES_SECURE_DELEGATION, so
            # the other query types aren't retrieved.
            level = self.RDTYPES_SECURE_DELEGATION

        consolidate_clients = self.single_client()

        erroneous_status = self.status not in (Status.NAME_STATUS_NOERROR, Status.NAME_STATUS_NXDOMAIN)

        d[name_str] = OrderedDict()
        if loglevel <= logging.INFO or erroneous_status:
            d[name_str]['status'] = Status.name_status_mapping[self.status]

        d[name_str]['queries'] = OrderedDict()
        query_keys = list(self.queries.keys())
        query_keys.sort()
        required_rdtypes = self._rdtypes_for_analysis_level(level)

        # don't serialize NS data in names for which delegation-only
        # information is required
        if level >= self.RDTYPES_SECURE_DELEGATION:
            required_rdtypes.difference_update([self.referral_rdtype, dns.rdatatype.NS])

        for (qname, rdtype) in query_keys:

            if level > self.RDTYPES_ALL and qname not in (self.name, self.dlv_name):
                continue

            if required_rdtypes is not None and rdtype not in required_rdtypes:
                continue

            query_serialized = self._serialize_query_status(self.queries[(qname, rdtype)], consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format)
            if query_serialized:
                qname_type_str = '%s/%s/%s' % (lb2s(qname.canonicalize().to_text()), dns.rdataclass.to_text(dns.rdataclass.IN), dns.rdatatype.to_text(rdtype))
                d[name_str]['queries'][qname_type_str] = query_serialized

        if not d[name_str]['queries']:
            del d[name_str]['queries']

        if level <= self.RDTYPES_SECURE_DELEGATION and (self.name, dns.rdatatype.DNSKEY) in self.queries:
            dnskey_serialized = self._serialize_dnskey_status(consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format)
            if dnskey_serialized:
                d[name_str]['dnskey'] = dnskey_serialized

        if self.is_zone():
            zone_serialized = self._serialize_zone_status(consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format)
            if zone_serialized:
                d[name_str]['zone'] = zone_serialized

            if self.parent is not None and not is_dlv:
                delegation_serialized = self._serialize_delegation_status(dns.rdatatype.DS, consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format)
                if delegation_serialized:
                    d[name_str]['delegation'] = delegation_serialized

            if self.dlv_parent is not None:
                if (self.dlv_name, dns.rdatatype.DLV) in self.queries:
                    delegation_serialized = self._serialize_delegation_status(dns.rdatatype.DLV, consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format)
                    if delegation_serialized:
                        d[name_str]['dlv'] = delegation_serialized

        if not d[name_str]:
            del d[name_str]

        return d

class TTLAgnosticOfflineDomainNameAnalysis(OfflineDomainNameAnalysis):
    QUERY_CLASS = Q.MultiQueryAggregateDNSResponse
