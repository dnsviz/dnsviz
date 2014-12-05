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
# Copyright 2014 VeriSign, Inc.
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

import base32
import base64
import collections
import datetime
import logging

import dns.name, dns.rdatatype

import crypto
import format as fmt
from util import tuple_to_dict

STATUS_VALID = 0
STATUS_INDETERMINATE = 1
STATUS_INVALID = 2
status_mapping = {
        STATUS_VALID: 'VALID',
        True: 'VALID',
        STATUS_INDETERMINATE: 'INDETERMINATE',
        None: 'INDETERMINATE',
        STATUS_INVALID: 'INVALID',
        False: 'INVALID',
}

NAME_STATUS_YXDOMAIN = 0
NAME_STATUS_NXDOMAIN = 1
NAME_STATUS_INDETERMINATE = 2
name_status_mapping = {
        NAME_STATUS_YXDOMAIN: 'YXDOMAIN',
        NAME_STATUS_NXDOMAIN: 'NXDOMAIN',
        NAME_STATUS_INDETERMINATE: 'INDETERMINATE',
}

RRSIG_STATUS_VALID = STATUS_VALID
RRSIG_STATUS_INDETERMINATE_NO_DNSKEY = 1
RRSIG_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM = 2
RRSIG_STATUS_EXPIRED = 3
RRSIG_STATUS_PREMATURE = 4
RRSIG_STATUS_INVALID_SIG = 5
RRSIG_STATUS_INVALID = 6
RRSIG_STATUS_MATCH_PRE_REVOKE = 7
rrsig_status_mapping = {
        RRSIG_STATUS_VALID: 'VALID',
        RRSIG_STATUS_INDETERMINATE_NO_DNSKEY: 'INDETERMINATE_NO_DNSKEY',
        RRSIG_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM: 'INDETERMINATE_UNKNOWN_ALGORITHM',
        RRSIG_STATUS_EXPIRED: 'EXPIRED',
        RRSIG_STATUS_PREMATURE: 'PREMATURE',
        RRSIG_STATUS_INVALID_SIG: 'INVALID_SIG',
        RRSIG_STATUS_INVALID: 'INVALID',
        RRSIG_STATUS_MATCH_PRE_REVOKE: 'MATCH_PRE_REVOKE',
}

DS_STATUS_VALID = STATUS_VALID
DS_STATUS_INDETERMINATE_NO_DNSKEY = 1
DS_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM = 2
DS_STATUS_INVALID_DIGEST = 3
DS_STATUS_INVALID = 4
DS_STATUS_MATCH_PRE_REVOKE = 5
ds_status_mapping = {
        DS_STATUS_VALID: 'VALID',
        DS_STATUS_INDETERMINATE_NO_DNSKEY: 'INDETERMINATE_NO_DNSKEY',
        DS_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM: 'INDETERMINATE_UNKNOWN_ALGORITHM',
        DS_STATUS_INVALID_DIGEST: 'INVALID_DIGEST',
        DS_STATUS_INVALID: 'INVALID',
        DS_STATUS_MATCH_PRE_REVOKE: 'MATCH_PRE_REVOKE',
}

DELEGATION_STATUS_SECURE = 0
DELEGATION_STATUS_INSECURE = 1
DELEGATION_STATUS_BOGUS = 2
DELEGATION_STATUS_INCOMPLETE = 3
DELEGATION_STATUS_LAME = 4
delegation_status_mapping = {
        DELEGATION_STATUS_SECURE: 'SECURE',
        DELEGATION_STATUS_INSECURE: 'INSECURE',
        DELEGATION_STATUS_BOGUS: 'BOGUS',
        DELEGATION_STATUS_INCOMPLETE: 'INCOMPLETE',
        DELEGATION_STATUS_LAME: 'LAME',
}

RRSET_STATUS_SECURE = 0
RRSET_STATUS_INSECURE = 1
RRSET_STATUS_BOGUS = 2
RRSET_STATUS_NON_EXISTENT = 3
rrset_status_mapping = {
        RRSET_STATUS_SECURE: 'SECURE',
        RRSET_STATUS_INSECURE: 'INSECURE',
        RRSET_STATUS_BOGUS: 'BOGUS',
        RRSET_STATUS_NON_EXISTENT: 'NON_EXISTENT',
}

NSEC_STATUS_VALID = STATUS_VALID
NSEC_STATUS_INDETERMINATE = STATUS_INDETERMINATE
NSEC_STATUS_INVALID = 2
nsec_status_mapping = {
        NSEC_STATUS_VALID: 'VALID',
        NSEC_STATUS_INDETERMINATE: 'INDETERMINATE',
        NSEC_STATUS_INVALID: 'INVALID',
}

DNAME_STATUS_VALID = STATUS_VALID
DNAME_STATUS_INDETERMINATE = STATUS_INDETERMINATE
DNAME_STATUS_INVALID_TARGET = 2
DNAME_STATUS_INVALID = 3
dname_status_mapping = {
        DNAME_STATUS_VALID: 'VALID',
        DNAME_STATUS_INDETERMINATE: 'INDETERMINATE',
        DNAME_STATUS_INVALID_TARGET: 'INVALID_TARGET',
        DNAME_STATUS_INVALID: 'INVALID',
}

RRSIG_ERROR_SIGNER_NOT_ZONE = 1
RRSIG_ERROR_RRSET_TTL_MISMATCH = 2
RRSIG_ERROR_ORIGINAL_TTL_MISMATCH = 3
RRSIG_ERROR_TTL_BEYOND_EXPIRY = 4
RRSIG_ERROR_ALGORITHM_NOT_SUPPORTED = 5
RRSIG_ERROR_DNSKEY_REVOKED = 6
RRSIG_ERROR_DNSKEY_REVOKED_POST_SIGN = 7
RRSIG_ERROR_PREMATURE = 8
RRSIG_ERROR_EXPIRED = 9
RRSIG_ERROR_NO_DNSKEY = 10
RRSIG_ERROR_SIG_INVALID = 11
rrsig_error_mapping = {
        RRSIG_ERROR_SIGNER_NOT_ZONE: 'SIGNER_NOT_ZONE',
        RRSIG_ERROR_RRSET_TTL_MISMATCH: 'RRSET_TTL_MISMATCH',
        RRSIG_ERROR_ORIGINAL_TTL_MISMATCH: 'ORIGINAL_TTL_MISMATCH',
        RRSIG_ERROR_TTL_BEYOND_EXPIRY: 'TTL_BEYOND_EXPIRY',
        RRSIG_ERROR_ALGORITHM_NOT_SUPPORTED: 'ALGORITHM_NOT_SUPPORTED',
        RRSIG_ERROR_DNSKEY_REVOKED: 'DNSKEY_REVOKED',
        RRSIG_ERROR_DNSKEY_REVOKED_POST_SIGN: 'DNSKEY_REVOKED_POST_SIGN',
        RRSIG_ERROR_PREMATURE: 'PREMATURE',
        RRSIG_ERROR_EXPIRED: 'EXPIRED',
        RRSIG_ERROR_NO_DNSKEY: 'NO_DNSKEY',
        RRSIG_ERROR_SIG_INVALID: 'SIG_INVALID',
}

DS_ERROR_DIGEST_ALGORITHM_NOT_SUPPORTED = 1
DS_ERROR_DNSKEY_REVOKED = 2
DS_ERROR_DNSKEY_REVOKED_POST_DS = 3
DS_ERROR_NO_DNSKEY = 4
DS_ERROR_DIGEST_INVALID = 5
ds_error_mapping = {
    DS_ERROR_DIGEST_ALGORITHM_NOT_SUPPORTED: 'DIGEST_ALGORITHM_NOT_SUPPORTED',
    DS_ERROR_DNSKEY_REVOKED: 'DNSKEY_REVOKED',
    DS_ERROR_DNSKEY_REVOKED_POST_DS: 'DNSKEY_REVOKED_POST_DS',
    DS_ERROR_NO_DNSKEY: 'NO_DNSKEY',
    DS_ERROR_DIGEST_INVALID: 'DIGEST_INVALID',
}

NSEC_ERROR_QNAME_NOT_COVERED = 1
NSEC_ERROR_WILDCARD_NOT_COVERED = 2
NSEC_ERROR_NO_CLOSEST_ENCLOSER = 3
NSEC_ERROR_REFERRAL_BAD_RDTYPES = 4
NSEC_ERROR_RDTYPE_IN_BITMAP = 5
NSEC_ERROR_CNAME_IN_BITMAP = 6
NSEC_ERROR_NO_MATCHING_NSEC = 7
NSEC_ERROR_WILDCARD_EXPANSION_INVALID = 8
NSEC_ERROR_WILDCARD_COVERED = 9
nsec_error_mapping = {
    NSEC_ERROR_QNAME_NOT_COVERED: 'QNAME_NOT_COVERED',
    NSEC_ERROR_WILDCARD_NOT_COVERED: 'WILDCARD_NOT_COVERED',
    NSEC_ERROR_NO_CLOSEST_ENCLOSER: 'NO_CLOSEST_ENCLOSER',
    NSEC_ERROR_REFERRAL_BAD_RDTYPES: 'REFERRAL_BAD_RDTYPES',
    NSEC_ERROR_RDTYPE_IN_BITMAP: 'RDTYPE_IN_BITMAP',
    NSEC_ERROR_CNAME_IN_BITMAP: 'CNAME_IN_BITMAP',
    NSEC_ERROR_NO_MATCHING_NSEC: 'NO_MATCHING_NSEC',
    NSEC_ERROR_WILDCARD_EXPANSION_INVALID: 'WILDCARD_EXPANSION_INVALID',
    NSEC_ERROR_WILDCARD_COVERED: 'WILDCARD_COVERED',
}

RESPONSE_ERROR_NOT_AUTHORITATIVE = 1
RESPONSE_ERROR_TIMEOUT_WITH_EDNS = 2
RESPONSE_ERROR_BAD_RCODE_WITH_EDNS = 3
RESPONSE_ERROR_UNSUPPORTED_EDNS_VERSION = 4
RESPONSE_ERROR_EDNS_IGNORED = 5
RESPONSE_ERROR_TIMEOUT_WITH_DO_FLAG = 6
RESPONSE_ERROR_UNABLE_TO_RETRIEVE_DNSSEC_RECORDS = 7
RESPONSE_ERROR_MISSING_RRSIGS = 8
RESPONSE_ERROR_MISSING_ALGS_FROM_DNSKEY = 9
RESPONSE_ERROR_MISSING_ALGS_FROM_DS = 10
RESPONSE_ERROR_MISSING_ALGS_FROM_DLV = 11
RESPONSE_ERROR_MISSING_NSEC_FOR_WILDCARD = 12
RESPONSE_ERROR_MISSING_NSEC_FOR_NXDOMAIN = 13
RESPONSE_ERROR_MISSING_NSEC_FOR_NODATA = 14
RESPONSE_ERROR_MISSING_SOA_FOR_NXDOMAIN = 15
RESPONSE_ERROR_MISSING_SOA_FOR_NODATA = 16
RESPONSE_ERROR_UPWARD_REFERRAL = 17
RESPONSE_ERROR_BAD_SOA_FOR_NXDOMAIN = 18
RESPONSE_ERROR_BAD_SOA_FOR_NODATA = 19
RESPONSE_ERROR_BAD_NXDOMAIN= 20
RESPONSE_ERROR_INTERMITTENT_RESPONSE = 21
response_error_mapping = {
    RESPONSE_ERROR_NOT_AUTHORITATIVE: 'NOT_AUTHORITATIVE',
    RESPONSE_ERROR_TIMEOUT_WITH_EDNS: 'TIMEOUT_WITH_EDNS',
    RESPONSE_ERROR_BAD_RCODE_WITH_EDNS: 'BAD_RCODE_WITH_EDNS',
    RESPONSE_ERROR_UNSUPPORTED_EDNS_VERSION: 'UNSUPPORTED_EDNS_VERSION',
    RESPONSE_ERROR_EDNS_IGNORED: 'EDNS_IGNORED',
    RESPONSE_ERROR_TIMEOUT_WITH_DO_FLAG: 'TIMEOUT_WITH_DO_FLAG',
    RESPONSE_ERROR_UNABLE_TO_RETRIEVE_DNSSEC_RECORDS: 'UNABLE_TO_RETRIEVE_DNSSEC_RECORDS',
    RESPONSE_ERROR_MISSING_RRSIGS: 'MISSING_RRSIGS',
    RESPONSE_ERROR_MISSING_ALGS_FROM_DNSKEY: 'MISSING_ALGS_FROM_DNSKEY',
    RESPONSE_ERROR_MISSING_ALGS_FROM_DS: 'MISSING_ALGS_FROM_DS',
    RESPONSE_ERROR_MISSING_ALGS_FROM_DLV: 'MISSING_ALGS_FROM_DLV',
    RESPONSE_ERROR_MISSING_NSEC_FOR_WILDCARD: 'MISSING_NSEC_FOR_WILDCARD',
    RESPONSE_ERROR_MISSING_NSEC_FOR_NXDOMAIN: 'MISSING_NSEC_FOR_NXDOMAIN',
    RESPONSE_ERROR_MISSING_NSEC_FOR_NODATA: 'MISSING_NSEC_FOR_NODATA',
    RESPONSE_ERROR_MISSING_SOA_FOR_NXDOMAIN: 'MISSING_SOA_FOR_NXDOMAIN',
    RESPONSE_ERROR_MISSING_SOA_FOR_NODATA: 'MISSING_SOA_FOR_NODATA',
    RESPONSE_ERROR_UPWARD_REFERRAL: 'UPWARD_REFERRAL',
    RESPONSE_ERROR_BAD_SOA_FOR_NXDOMAIN: 'BAD_SOA_FOR_NXDOMAIN',
    RESPONSE_ERROR_BAD_SOA_FOR_NODATA: 'BAD_SOA_FOR_NODATA',
    RESPONSE_ERROR_BAD_NXDOMAIN: 'BAD_NXDOMAIN',
    RESPONSE_ERROR_INTERMITTENT_RESPONSE: 'INTERMITTENT_RESPONSE',
}

DELEGATION_ERROR_NO_SEP_FOR_SOME_ALGS = 1
DELEGATION_ERROR_NO_SEP = 2
DELEGATION_ERROR_NO_NS_IN_PARENT = 3
DELEGATION_ERROR_NO_RESPONSIVE_SERVERS = 4
DELEGATION_ERROR_NO_VALID_RCODE_RESPONSE = 5
DELEGATION_ERROR_NO_AUTHORITATIVE_RESPONSE = 6
delegation_error_mapping = {
    DELEGATION_ERROR_NO_SEP_FOR_SOME_ALGS: 'NO_SEP_FOR_SOME_ALGS',
    DELEGATION_ERROR_NO_SEP: 'NO_SEP',
    DELEGATION_ERROR_NO_NS_IN_PARENT: 'NO_NS_IN_PARENT',
    DELEGATION_ERROR_NO_RESPONSIVE_SERVERS: 'NO_RESPONSIVE_SERVERS',
    DELEGATION_ERROR_NO_VALID_RCODE_RESPONSE: 'NO_VALID_RCODE_RESPONSE',
    DELEGATION_ERROR_NO_AUTHORITATIVE_RESPONSE: 'NO_AUTHORITATIVE_RESPONSE',
}

DNAME_ERROR_NO_CNAME = 1
DNAME_ERROR_TARGET_MISMATCH = 2
DNAME_ERROR_TTL_ZERO = 3
DNAME_ERROR_TTL_MISMATCH = 4
dname_error_mapping = {
    DNAME_ERROR_NO_CNAME: 'NO_CNAME',
    DNAME_ERROR_TARGET_MISMATCH: 'TARGET_MISMATCH',
    DNAME_ERROR_TTL_ZERO: 'TTL_ZERO',
    DNAME_ERROR_TTL_MISMATCH: 'TTL_MISMATCH'
}

DNSKEY_ERROR_DNSKEY_MISSING_FROM_SOME_SERVERS = 1
DNSKEY_ERROR_DNSKEY_NOT_AT_ZONE_APEX = 2
DNSKEY_ERROR_TRUST_ANCHOR_NOT_SIGNING = 3
DNSKEY_ERROR_REVOKED_NOT_SIGNING = 4
dnskey_error_mapping = {
    DNSKEY_ERROR_DNSKEY_MISSING_FROM_SOME_SERVERS: 'DNSKEY_MISSING_FROM_SOME_SERVERS',
    DNSKEY_ERROR_DNSKEY_NOT_AT_ZONE_APEX: 'DNSKEY_NOT_AT_ZONE_APEX',
    DNSKEY_ERROR_TRUST_ANCHOR_NOT_SIGNING: 'TRUST_ANCHOR_NOT_SIGNING',
    DNSKEY_ERROR_REVOKED_NOT_SIGNING: 'REVOKED_NOT_SIGNING',
}

class RRSIGStatus(object):
    def __init__(self, rrset, rrsig, dnskey, zone_name, reference_ts, algorithm_unknown=False):
        self.rrset = rrset
        self.rrsig = rrsig
        self.dnskey = dnskey
        self.zone_name = zone_name
        self.reference_ts = reference_ts
        self.algorithm_unknown = algorithm_unknown
        self.warnings = []
        self.errors = []

        if self.dnskey is None:
            self.signature_valid = None
        else:
            self.signature_valid = crypto.validate_rrsig(dnskey.rdata.algorithm, rrsig.signature, rrset.message_for_rrsig(rrsig), dnskey.rdata.key)

        self.validation_status = RRSIG_STATUS_VALID
        if self.signature_valid is None or self.algorithm_unknown:
            if self.dnskey is None:
                if self.validation_status == RRSIG_STATUS_VALID:
                    self.validation_status = RRSIG_STATUS_INDETERMINATE_NO_DNSKEY
            else:
                if self.validation_status == RRSIG_STATUS_VALID:
                    self.validation_status = RRSIG_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM
                self.warnings.append(RRSIG_ERROR_ALGORITHM_NOT_SUPPORTED)

        if self.rrset.rrset.ttl != self.rrset.rrsig_info[self.rrsig].ttl:
            self.warnings.append(RRSIG_ERROR_RRSET_TTL_MISMATCH)
        #XXX consider taking into consideration RD/RA bits in request/response
        if self.rrset.rrsig_info[self.rrsig].ttl > self.rrsig.original_ttl:
            self.warnings.append(RRSIG_ERROR_ORIGINAL_TTL_MISMATCH)

        min_ttl = min(self.rrset.rrset.ttl, self.rrset.rrsig_info[self.rrsig].ttl, self.rrsig.original_ttl)
            
        #XXX get parent right for DS and related NSEC(3)
        #if self.rrsig.signer != zone_name:
        if not self.rrset.rrset.name.is_subdomain(self.rrsig.signer):
            if self.validation_status == RRSIG_STATUS_VALID:
                self.validation_status = RRSIG_STATUS_INVALID
            self.errors.append(RRSIG_ERROR_SIGNER_NOT_ZONE)

        if self.dnskey is not None and \
                self.dnskey.rdata.flags & fmt.DNSKEY_FLAGS['revoke'] and self.rrsig.covers() != dns.rdatatype.DNSKEY:
            if self.rrsig.key_tag != self.dnskey.key_tag:
                self.errors.append(RRSIG_ERROR_DNSKEY_REVOKED_POST_SIGN)
                if self.validation_status == RRSIG_STATUS_VALID:
                    self.validation_status = RRSIG_STATUS_MATCH_PRE_REVOKE
            else:
                self.errors.append(RRSIG_ERROR_DNSKEY_REVOKED)
                if self.validation_status == RRSIG_STATUS_VALID:
                    self.validation_status = RRSIG_STATUS_INVALID

        if self.reference_ts < self.rrsig.inception: 
            if self.validation_status == RRSIG_STATUS_VALID:
                self.validation_status = RRSIG_STATUS_PREMATURE
            self.errors.append(RRSIG_ERROR_PREMATURE)
        if self.reference_ts >= self.rrsig.expiration: 
            if self.validation_status == RRSIG_STATUS_VALID:
                self.validation_status = RRSIG_STATUS_EXPIRED
            self.errors.append(RRSIG_ERROR_EXPIRED)
        elif self.reference_ts + min_ttl >= self.rrsig.expiration:
            self.errors.append(RRSIG_ERROR_TTL_BEYOND_EXPIRY)

        if not self.algorithm_unknown and self.signature_valid == False:
            # only report this if we're not referring to a key revoked post-sign
            if self.dnskey.key_tag == self.rrsig.key_tag:
                if self.validation_status == RRSIG_STATUS_VALID:
                    self.validation_status = RRSIG_STATUS_INVALID_SIG
                self.errors.append(RRSIG_ERROR_SIG_INVALID)

    def __unicode__(self):
        return u'RRSIG covering %s/%s' % (self.rrset.rrset.name.canonicalize().to_text(), dns.rdatatype.to_text(self.rrset.rrset.rdtype))

    def serialize(self, consolidate_clients=True, loglevel=logging.DEBUG):
        d = collections.OrderedDict()

        show_basic = (self.warnings and loglevel <= logging.WARNING) or (self.errors and loglevel <= logging.ERROR) or self.validation_status not in (RRSIG_STATUS_VALID, RRSIG_STATUS_INDETERMINATE_NO_DNSKEY, RRSIG_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM)

        if loglevel <= logging.INFO or show_basic:
            d['description'] = unicode(self)

        if loglevel <= logging.DEBUG:
            d.update((
                ('rdata', collections.OrderedDict((
                    ('signer', self.rrsig.signer.canonicalize().to_text()),
                    ('algorithm', self.rrsig.algorithm),
                    ('key_tag', self.rrsig.key_tag),
                    ('original_ttl', self.rrsig.original_ttl),
                    ('labels', self.rrsig.labels),
                    ('inception', fmt.timestamp_to_str(self.rrsig.inception)),
                    ('expiration', fmt.timestamp_to_str(self.rrsig.expiration)),
                    ('signature', base64.b64encode(self.rrsig.signature)),
                ))),
                ('meta', collections.OrderedDict((
                    ('ttl', self.rrset.rrsig_info[self.rrsig].ttl),
                    ('age', int(self.reference_ts - self.rrsig.inception)),
                    ('remaining_lifetime', int(self.rrsig.expiration - self.reference_ts)),
                ))),
            ))

        if loglevel <= logging.DEBUG and self.dnskey is not None:
            d['meta']['dnskey'] = self.dnskey.rdata.to_text()
            if self.rrsig.key_tag != self.dnskey.key_tag:
                d['meta']['dnskey_key_tag_pre_revoke'] = self.dnskey.key_tag_no_revoke

        if loglevel <= logging.INFO or show_basic:
            d['status'] = rrsig_status_mapping[self.validation_status]

        if loglevel <= logging.DEBUG or show_basic:
            servers = tuple_to_dict(self.rrset.rrsig_info[self.rrsig].servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

        if self.warnings and loglevel <= logging.WARNING:
            d['warnings'] = [rrsig_error_mapping[e] for e in self.warnings]
        if self.errors and loglevel <= logging.ERROR:
            d['errors'] = [rrsig_error_mapping[e] for e in self.errors]
        return d


class DSStatus(object):
    def __init__(self, ds, ds_meta, dnskey, digest_algorithm_unknown=False):
        self.ds = ds
        self.ds_meta = ds_meta
        self.dnskey = dnskey
        self.digest_algorithm_unknown = digest_algorithm_unknown
        self.warnings = []
        self.errors = []

        if self.dnskey is None:
            self.digest_valid = None
        else:
            self.digest_valid = crypto.validate_ds_digest(ds.digest_type, ds.digest, dnskey.message_for_ds())

        self.validation_status = DS_STATUS_VALID
        if self.digest_valid is None or self.digest_algorithm_unknown:
            if self.dnskey is None:
                if self.validation_status == DS_STATUS_VALID:
                    self.validation_status = DS_STATUS_INDETERMINATE_NO_DNSKEY
            else:
                if self.validation_status == DS_STATUS_VALID:
                    self.validation_status = DS_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM
                self.warnings.append(DS_ERROR_DIGEST_ALGORITHM_NOT_SUPPORTED)

        if self.dnskey is not None and \
                self.dnskey.rdata.flags & fmt.DNSKEY_FLAGS['revoke']:
            if self.dnskey.key_tag != self.ds.key_tag:
                self.errors.append(DS_ERROR_DNSKEY_REVOKED_POST_DS)
                if self.validation_status == DS_STATUS_VALID:
                    self.validation_status = DS_STATUS_MATCH_PRE_REVOKE
            else:
                self.errors.append(DS_ERROR_DNSKEY_REVOKED)
                if self.validation_status == DS_STATUS_VALID:
                    self.validation_status = DS_STATUS_INVALID

        if not self.digest_algorithm_unknown and self.digest_valid == False:
            # only report this if we're not referring to a key revoked post-DS
            if self.dnskey.key_tag == self.ds.key_tag:
                if self.validation_status == DS_STATUS_VALID:
                    self.validation_status = DS_STATUS_INVALID_DIGEST
                self.errors.append(DS_ERROR_DIGEST_INVALID)

    def __unicode__(self):
        return u'%s record(s) corresponding to DNSKEY for %s (algorithm %d (%s), key tag %d)' % (dns.rdatatype.to_text(self.ds_meta.rrset.rdtype), self.ds_meta.rrset.name.canonicalize().to_text(), self.ds.algorithm, fmt.DNSKEY_ALGORITHMS.get(self.ds.algorithm, self.ds.algorithm), self.ds.key_tag)

    def serialize(self, consolidate_clients=True, loglevel=logging.DEBUG):
        d = collections.OrderedDict()

        show_basic = (self.warnings and loglevel <= logging.WARNING) or (self.errors and loglevel <= logging.ERROR) or self.validation_status not in (DS_STATUS_VALID, DS_STATUS_INDETERMINATE_NO_DNSKEY, DS_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM)

        if loglevel <= logging.INFO or show_basic:
            d['description'] = unicode(self)

        if loglevel <= logging.DEBUG:
            d.update((
                ('rdata', collections.OrderedDict((
                    ('algorithm', self.ds.algorithm),
                    ('key_tag', self.ds.key_tag),
                    ('digest_type', self.ds.digest_type),
                    ('digest', base64.b64encode(self.ds.digest)),
                ))),
                ('meta', collections.OrderedDict()),
            ))

        if loglevel <= logging.DEBUG:
            d['meta']['ttl'] = self.ds_meta.rrset.ttl
            if self.dnskey is None:
                d['meta']['dnskey'] = None
            else:
                d['meta']['dnskey'] = self.dnskey.rdata.to_text()
                if self.ds.key_tag != self.dnskey.key_tag:
                    d['meta']['dnskey_key_tag_pre_revoke'] = self.dnskey.key_tag_no_revoke

        if loglevel <= logging.INFO or show_basic:
            d['status'] = ds_status_mapping[self.validation_status]

        if loglevel <= logging.DEBUG or show_basic:
            servers = tuple_to_dict(self.ds_meta.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

        if self.warnings and loglevel <= logging.WARNING:
            d['warnings'] = [ds_error_mapping[e] for e in self.warnings]
        if self.errors and loglevel <= logging.ERROR:
            d['errors'] = [ds_error_mapping[e] for e in self.errors]
        return d

class NSECStatusNXDOMAIN(object):
    def __init__(self, qname, origin, nsec_set_info):
        self.qname = qname
        self.origin = origin
        self.warnings = []
        self.errors = []

        self.wildcard_name = dns.name.from_text('*', self.origin)

        self.nsec_names_covering_qname = {}
        covering_names = nsec_set_info.nsec_covering_name(self.qname)
        if covering_names:
            self.nsec_names_covering_qname[self.qname] = covering_names

        self.nsec_names_covering_wildcard = {}
        wildcard_cover = qname
        # check that at least one wildcard is covered between qname and origin,
        # any one of which could be expanded into wildcard
        while wildcard_cover != self.origin:
            wildcard_name = dns.name.from_text('*', wildcard_cover.parent())
            covering_names = nsec_set_info.nsec_covering_name(wildcard_name)
            if covering_names:
                self.wildcard_name = wildcard_name
                self.nsec_names_covering_wildcard[self.wildcard_name] = covering_names
                break
            wildcard_cover = wildcard_cover.parent()

        self._set_validation_status(nsec_set_info)

    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, self.qname)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                self.qname == other.qname and self.origin == other.origin and self.nsec_set_info == other.nsec_set_info

    def _set_validation_status(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        if not self.nsec_names_covering_qname:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(NSEC_ERROR_QNAME_NOT_COVERED)
        if not self.nsec_names_covering_wildcard:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(NSEC_ERROR_WILDCARD_NOT_COVERED)
    
        # if it validation_status, we project out just the pertinent NSEC records
        # otherwise clone it by projecting them all
        if self.validation_status == NSEC_STATUS_VALID:
            covering_names = set()
            for names in self.nsec_names_covering_qname.values() + self.nsec_names_covering_wildcard.values():
                covering_names.update(names)
            self.nsec_set_info = nsec_set_info.project(*list(covering_names))
        else:
            self.nsec_set_info = nsec_set_info.project(*list(nsec_set_info.rrsets))

    def __unicode__(self):
        return u'NSEC record(s) proving the non-existence (NXDOMAIN) of %s' % (self.qname.canonicalize().to_text())

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG):
        d = collections.OrderedDict()

        show_basic = (self.warnings and loglevel <= logging.WARNING) or (self.errors and loglevel <= logging.ERROR) or self.validation_status != STATUS_VALID

        if loglevel <= logging.INFO or show_basic:
            d['description'] = unicode(self)

        d['nsec'] = []
        for nsec_rrset in self.nsec_set_info.rrsets.values():
            if rrset_info_serializer is not None:
                nsec_serialized = rrset_info_serializer(nsec_rrset, consolidate_clients=consolidate_clients, show_servers=False, loglevel=loglevel)
                if nsec_serialized:
                    d['nsec'].append(nsec_serialized)
            elif loglevel <= logging.DEBUG:
                d['nsec'].append(nsec_rrset.serialize(consolidate_clients=consolidate_clients, show_servers=False))
        if not d['nsec']:
            del d['nsec']

        if loglevel <= logging.DEBUG:
            d['meta'] = collections.OrderedDict()
            d['meta']['qname'] = self.qname.canonicalize().to_text()
            if self.nsec_names_covering_qname:
                qname, nsec_names = self.nsec_names_covering_qname.items()[0]
                nsec_name = list(nsec_names)[0]
                nsec_rr = self.nsec_set_info.rrsets[nsec_name].rrset[0]
                d['meta']['nsec_chain_covering_qname'] = collections.OrderedDict((
                    ('qname', qname.canonicalize().to_text()),
                    ('nsec_owner', nsec_name.canonicalize().to_text()),
                    ('nsec_next', nsec_rr.next.canonicalize().to_text())
                ))
            d['meta']['wildcard'] = self.wildcard_name.canonicalize().to_text()
            if self.nsec_names_covering_wildcard:
                wildcard, nsec_names = self.nsec_names_covering_wildcard.items()[0]
                nsec_name = list(nsec_names)[0]
                nsec_rr = self.nsec_set_info.rrsets[nsec_name].rrset[0]
                d['meta']['nsec_chain_covering_wildcard'] = collections.OrderedDict((
                    ('wildcard', wildcard.canonicalize().to_text()),
                    ('nsec_owner', nsec_name.canonicalize().to_text()),
                    ('nsec_next', nsec_rr.next.canonicalize().to_text())
                ))

        if loglevel <= logging.INFO or show_basic:
            d['status'] = nsec_status_mapping[self.validation_status]

        if loglevel <= logging.DEBUG or show_basic:
            servers = tuple_to_dict(self.nsec_set_info.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

        if self.warnings and loglevel <= logging.WARNING:
            d['warnings'] = [nsec_error_mapping[e] for e in self.warnings]
        if self.errors and loglevel <= logging.ERROR:
            d['errors'] = [nsec_error_mapping[e] for e in self.errors]
        return d

class NSECStatusWildcard(NSECStatusNXDOMAIN):
    def __init__(self, qname, wildcard_name, origin, nsec_set_info):
        super(NSECStatusWildcard, self).__init__(qname, origin, nsec_set_info)
        self.wildcard_name = wildcard_name
        self.nsec_names_covering_wildcard = {}

        self._set_validation_status2(nsec_set_info)

    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, self.qname)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                super(NSECStatusWildcard, self).__eq__(other) and self.wildcard_name == other.wildcard_name
            
    def _next_closest_encloser(self):
        return dns.name.Name(self.qname.labels[-len(self.wildcard_name):])

    def _set_validation_status(self, nsec_set_info):
        pass

    def _set_validation_status2(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        if self.nsec_names_covering_qname:
            next_closest_encloser = self._next_closest_encloser()
            if not nsec_set_info.nsec_covering_name(next_closest_encloser):
                self.validation_status = NSEC_STATUS_INVALID
                self.errors.append(NSEC_ERROR_WILDCARD_EXPANSION_INVALID)
        else:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(NSEC_ERROR_QNAME_NOT_COVERED)

        # if it validation_status, we project out just the pertinent NSEC records
        # otherwise clone it by projecting them all
        if self.validation_status == NSEC_STATUS_VALID:
            covering_names = set()
            for names in self.nsec_names_covering_qname.values():
                covering_names.update(names)
            self.nsec_set_info = nsec_set_info.project(*list(covering_names))
        else:
            self.nsec_set_info = nsec_set_info.project(*list(nsec_set_info.rrsets))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG):
        d = super(NSECStatusWildcard, self).serialize(rrset_info_serializer, consolidate_clients=consolidate_clients, loglevel=loglevel)
        try:
            del d['meta']['wildcard']
        except KeyError:
            pass
        return d

class NSECStatusNoAnswer(object):
    def __init__(self, qname, rdtype, origin, referral, nsec_set_info):
        self.qname = qname
        self.rdtype = rdtype
        self.origin = origin
        self.referral = referral
        self.warnings = []
        self.errors = []
        self.wildcard_name = dns.name.from_text('*', origin)

        try:
            self.nsec_for_qname = nsec_set_info.rrsets[self.qname]
            self.has_rdtype = nsec_set_info.rdtype_exists_in_bitmap(self.qname, self.rdtype)
            self.has_ns = nsec_set_info.rdtype_exists_in_bitmap(self.qname, dns.rdatatype.NS)
            self.has_ds = nsec_set_info.rdtype_exists_in_bitmap(self.qname, dns.rdatatype.DS)
            self.has_soa = nsec_set_info.rdtype_exists_in_bitmap(self.qname, dns.rdatatype.SOA)
        except KeyError:
            self.nsec_for_qname = None
            self.has_rdtype = False
            self.has_ns = False
            self.has_ds = False
            self.has_soa = False

            # If no NSEC exists for the name itself, then look for an NSEC with
            # an (empty non-terminal) ancestor
            for nsec_name in nsec_set_info.rrsets:
                next_name = nsec_set_info.rrsets[nsec_name].rrset[0].next
                if next_name.is_subdomain(self.qname) and next_name != self.qname:
                    self.nsec_for_qname = nsec_set_info.rrsets[nsec_name]
                    break

        self.nsec_names_covering_qname = {}
        covering_names = nsec_set_info.nsec_covering_name(self.qname)
        if covering_names:
            self.nsec_names_covering_qname[self.qname] = covering_names

        self.nsec_for_wildcard_name = None
        self.wildcard_has_rdtype = None
        wildcard_cover = qname
        # check that at least one wildcard is covered between qname and origin,
        # any one of which could be expanded into wildcard
        while wildcard_cover != self.origin:
            wildcard_name = dns.name.from_text('*', wildcard_cover.parent())
            try:
                self.nsec_for_wildcard_name = nsec_set_info.rrsets[wildcard_name]
                self.wildcard_has_rdtype = nsec_set_info.rdtype_exists_in_bitmap(wildcard_name, self.rdtype)
                self.wildcard_name = wildcard_name
            except KeyError:
                pass
            wildcard_cover = wildcard_cover.parent()

        self._set_validation_status(nsec_set_info)

    def __unicode__(self):
        return u'NSEC record(s) proving non-existence (NXRRSET) of %s/%s' % (self.qname.canonicalize().to_text(), dns.rdatatype.to_text(self.rdtype))

    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, self.qname)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                self.qname == other.qname and self.rdtype == other.rdtype and self.origin == other.origin and self.referral == other.referral and self.nsec_set_info == other.nsec_set_info
            
    def _set_validation_status(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        if self.nsec_for_qname is not None:
            # RFC 4034 5.2, 6840 4.4
            if self.rdtype == dns.rdatatype.DS or self.referral:
                if not (self.has_ns and not self.has_ds and not self.has_soa):
                    self.errors.append(NSEC_ERROR_REFERRAL_BAD_RDTYPES)
                    self.validation_status = NSEC_STATUS_INVALID
            if self.has_rdtype:
                self.errors.append(NSEC_ERROR_RDTYPE_IN_BITMAP)
                self.validation_status = NSEC_STATUS_INVALID

        else:
            if self.nsec_for_wildcard_name is None:
                self.errors.append(NSEC_ERROR_NO_MATCHING_NSEC)
                self.validation_status = NSEC_STATUS_INVALID
            if not self.nsec_names_covering_qname:
                self.errors.append(NSEC_ERROR_QNAME_NOT_COVERED)
                self.validation_status = NSEC_STATUS_INVALID
            if self.wildcard_has_rdtype:
                self.errors.append(NSEC_ERROR_RDTYPE_IN_BITMAP)
                self.validation_status = NSEC_STATUS_INVALID
                
        # if it validation_status, we project out just the pertinent NSEC records
        # otherwise clone it by projecting them all
        if self.validation_status == NSEC_STATUS_VALID:
            covering_names = set()
            if self.nsec_for_qname is not None:
                covering_names.add(self.nsec_for_qname.rrset.name)
            else:
                for names in self.nsec_names_covering_qname.values():
                    covering_names.update(names)
            if self.nsec_for_wildcard_name is not None:
                covering_names.add(self.wildcard_name)
            self.nsec_set_info = nsec_set_info.project(*list(covering_names))
        else:
            self.nsec_set_info = nsec_set_info.project(*list(nsec_set_info.rrsets))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG):
        d = collections.OrderedDict()
        
        show_basic = (self.warnings and loglevel <= logging.WARNING) or (self.errors and loglevel <= logging.ERROR) or self.validation_status != STATUS_VALID

        if loglevel <= logging.INFO or show_basic:
            d['description'] = unicode(self)

        d['nsec'] = []
        for nsec_rrset in self.nsec_set_info.rrsets.values():
            if rrset_info_serializer is not None:
                nsec_serialized = rrset_info_serializer(nsec_rrset, consolidate_clients=consolidate_clients, show_servers=False, loglevel=loglevel)
                if nsec_serialized:
                    d['nsec'].append(nsec_serialized)
            elif loglevel <= logging.DEBUG:
                d['nsec'].append(nsec_rrset.serialize(consolidate_clients=consolidate_clients, show_servers=False))
        if not d['nsec']:
            del d['nsec']

        if loglevel <= logging.DEBUG:
            d['meta'] = collections.OrderedDict()
            d['meta']['qname'] = self.qname.canonicalize().to_text()
            if self.nsec_for_qname is not None:
                d['meta']['nsec_matching_qname'] = collections.OrderedDict((
                    ('qname', self.nsec_for_qname.rrset.name.canonicalize().to_text()),
                    #TODO - add rdtypes bitmap (when NSEC matches qname--not for empty non-terminal)
                ))

            if self.nsec_names_covering_qname:
                qname, nsec_names = self.nsec_names_covering_qname.items()[0]
                nsec_name = list(nsec_names)[0]
                nsec_rr = self.nsec_set_info.rrsets[nsec_name].rrset[0]
                d['meta']['nsec_chain_covering_qname'] = collections.OrderedDict((
                    ('qname', qname.canonicalize().to_text()),
                    ('nsec_owner', nsec_name.canonicalize().to_text()),
                    ('nsec_next', nsec_rr.next.canonicalize().to_text())
                ))

            d['meta']['wildcard'] = self.wildcard_name.canonicalize().to_text()
            if self.nsec_for_wildcard_name is not None:
                d['meta']['nsec_matching_wildcard'] = collections.OrderedDict((
                    ('wildcard', self.wildcard_name.canonicalize().to_text()),
                    #TODO - add rdtypes bitmap
                ))

        if loglevel <= logging.INFO or show_basic:
            d['status'] = nsec_status_mapping[self.validation_status]

        if loglevel <= logging.DEBUG or show_basic:
            servers = tuple_to_dict(self.nsec_set_info.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

        if self.warnings and loglevel <= logging.WARNING:
            d['warnings'] = [nsec_error_mapping[e] for e in self.warnings]
        if self.errors and loglevel <= logging.ERROR:
            d['errors'] = [nsec_error_mapping[e] for e in self.errors]
        return d

class NSEC3StatusNXDOMAIN(object):
    def __init__(self, qname, origin, nsec_set_info):
        self.qname = qname
        self.origin = origin
        self.warnings = []
        self.errors = []

        self.name_digest_map = {}

        self._set_closest_encloser(nsec_set_info)

        self.nsec_names_covering_qname = {}
        self.nsec_names_covering_wildcard = {}

        for (salt, alg, iterations), nsec3_names in nsec_set_info.nsec3_params.items():
            digest_name = nsec_set_info.get_digest_name_for_nsec3(self.qname, self.origin, salt, alg, iterations)
            if self.qname not in self.name_digest_map:
                self.name_digest_map[self.qname] = {}
            self.name_digest_map[self.qname][(salt, alg, iterations)] = digest_name

        for encloser in self.closest_encloser:
            next_closest_encloser = self._get_next_closest_encloser(encloser)
            for salt, alg, iterations in nsec_set_info.nsec3_params:
                try:
                    digest_name = self.name_digest_map[next_closest_encloser][(salt, alg, iterations)]
                except KeyError:
                    digest_name = nsec_set_info.get_digest_name_for_nsec3(next_closest_encloser, self.origin, salt, alg, iterations)

                covering_names = nsec_set_info.nsec3_covering_name(digest_name, salt, alg, iterations)
                if covering_names:
                    self.nsec_names_covering_qname[digest_name] = covering_names

                if next_closest_encloser not in self.name_digest_map:
                    self.name_digest_map[next_closest_encloser] = {}
                self.name_digest_map[next_closest_encloser][(salt, alg, iterations)] = digest_name

                wildcard_name = self._get_wildcard(encloser)
                digest_name = nsec_set_info.get_digest_name_for_nsec3(wildcard_name, self.origin, salt, alg, iterations)

                covering_names = nsec_set_info.nsec3_covering_name(digest_name, salt, alg, iterations)
                if covering_names:
                    self.nsec_names_covering_wildcard[digest_name] = covering_names

                if wildcard_name not in self.name_digest_map:
                    self.name_digest_map[wildcard_name] = {}
                self.name_digest_map[wildcard_name][(salt, alg, iterations)] = digest_name

        self._set_validation_status(nsec_set_info)

    def __unicode__(self):
        return u'NSEC3 record(s) proving the non-existence (NXDOMAIN) of %s' % (self.qname.canonicalize().to_text())

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.qname)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                self.qname == other.qname and self.origin == other.origin and self.nsec_set_info == other.nsec_set_info

    def _get_next_closest_encloser(self, encloser):
        return dns.name.Name(self.qname.labels[-(len(encloser)+1):])

    def _get_wildcard(self, encloser):
        return dns.name.from_text('*', encloser)

    def _set_closest_encloser(self, nsec_set_info):
        self.closest_encloser = nsec_set_info.get_closest_encloser(self.qname, self.origin)
            
    def _set_validation_status(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        if not self.closest_encloser:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(NSEC_ERROR_NO_CLOSEST_ENCLOSER)
        if not self.nsec_names_covering_qname:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(NSEC_ERROR_QNAME_NOT_COVERED)
        if not self.nsec_names_covering_wildcard:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(NSEC_ERROR_WILDCARD_NOT_COVERED)

        # if it validation_status, we project out just the pertinent NSEC records
        # otherwise clone it by projecting them all
        if self.validation_status == NSEC_STATUS_VALID:
            covering_names = set()
            for names in self.closest_encloser.values() + self.nsec_names_covering_qname.values() + self.nsec_names_covering_wildcard.values():
                covering_names.update(names)
            self.nsec_set_info = nsec_set_info.project(*list(covering_names))
        else:
            self.nsec_set_info = nsec_set_info.project(*list(nsec_set_info.rrsets))
    
    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG):
        d = collections.OrderedDict()
        
        show_basic = (self.warnings and loglevel <= logging.WARNING) or (self.errors and loglevel <= logging.ERROR) or self.validation_status != STATUS_VALID

        if loglevel <= logging.INFO or show_basic:
            d['description'] = unicode(self)

        d['nsec3'] = []
        for nsec_rrset in self.nsec_set_info.rrsets.values():
            if rrset_info_serializer is not None:
                nsec_serialized = rrset_info_serializer(nsec_rrset, consolidate_clients=consolidate_clients, show_servers=False, loglevel=loglevel)
                if nsec_serialized:
                    d['nsec3'].append(nsec_serialized)
            elif loglevel <= logging.DEBUG:
                d['nsec3'].append(nsec_rrset.serialize(consolidate_clients=consolidate_clients, show_servers=False))
        if not d['nsec3']:
            del d['nsec3']

        if loglevel <= logging.DEBUG:
            d['meta'] = collections.OrderedDict()

            if self.closest_encloser:
                encloser_name, nsec_names = self.closest_encloser.items()[0]
                nsec_name = list(nsec_names)[0]
                d['meta']['closest_encloser'] = collections.OrderedDict((
                    ('name', encloser_name.canonicalize().to_text()),
                ))
                # could be inferred from wildcard
                if nsec_name is not None:
                    d['meta']['closest_encloser']['name_digest'] = fmt.format_nsec3_name(nsec_name)

                next_closest_encloser = self._get_next_closest_encloser(encloser_name)
                d['meta']['next_closest_encloser'] = fmt.humanize_name(next_closest_encloser)
                d['meta']['next_closest_encloser_digest'] = fmt.format_nsec3_name(self.name_digest_map[next_closest_encloser].items()[0][1])

                if self.nsec_names_covering_qname:
                    qname, nsec_names = self.nsec_names_covering_qname.items()[0]
                    nsec_name = list(nsec_names)[0]
                    next_name = self.nsec_set_info.name_for_nsec3_next(nsec_name)
                    d['meta']['nsec_chain_covering_next_closest_encloser'] = collections.OrderedDict((
                        ('next_closest_encloser_digest', fmt.format_nsec3_name(qname)),
                        ('nsec3_owner', fmt.format_nsec3_name(nsec_name)),
                        ('nsec3_next', fmt.format_nsec3_name(next_name)),
                    ))

                wildcard_name = self._get_wildcard(encloser_name)
                wildcard_digest = self.name_digest_map[wildcard_name].items()[0][1]
                d['meta']['wildcard'] = wildcard_name.canonicalize().to_text()
                d['meta']['wildcard_digest'] = fmt.format_nsec3_name(wildcard_digest)
                if self.nsec_names_covering_wildcard:
                    wildcard, nsec_names = self.nsec_names_covering_wildcard.items()[0]
                    nsec_name = list(nsec_names)[0]
                    next_name = self.nsec_set_info.name_for_nsec3_next(nsec_name)
                    d['meta']['nsec_chain_covering_wildcard'] = collections.OrderedDict((
                        ('wildcard_digest', fmt.format_nsec3_name(wildcard)),
                        ('nsec3_owner', fmt.format_nsec3_name(nsec_name)),
                        ('nsec3_next', fmt.format_nsec3_name(next_name)),
                    ))

            else:
                d['meta']['qname'] = fmt.humanize_name(self.qname)
                d['meta']['qname_digest'] = fmt.format_nsec3_name(self.name_digest_map[self.qname].items()[0][1])

        if loglevel <= logging.INFO or show_basic:
            d['status'] = nsec_status_mapping[self.validation_status]

        if loglevel <= logging.DEBUG or show_basic:
            servers = tuple_to_dict(self.nsec_set_info.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

        if self.warnings and loglevel <= logging.WARNING:
            d['warnings'] = [nsec_error_mapping[e] for e in self.warnings]
        if self.errors and loglevel <= logging.ERROR:
            d['errors'] = [nsec_error_mapping[e] for e in self.errors]
        return d

class NSEC3StatusWildcard(NSEC3StatusNXDOMAIN):
    def __init__(self, qname, wildcard_name, origin, nsec_set_info):
        self.wildcard_name = wildcard_name
        super(NSEC3StatusWildcard, self).__init__(qname, origin, nsec_set_info)

    def _set_closest_encloser(self, nsec_set_info):
        super(NSEC3StatusWildcard, self)._set_closest_encloser(nsec_set_info)
            
        if not self.closest_encloser:
            self.closest_encloser = { self.wildcard_name.parent(): set([None]) }
            # fill in a dummy value for wildcard_name_digest_map
            self.name_digest_map[self.wildcard_name] = { None: self.wildcard_name }

    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, self.qname)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                super(NSEC3StatusWildcard, self).__eq__(other) and self.wildcard_name == other.wildcard_name
            
    def _set_validation_status(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        if not self.nsec_names_covering_qname:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(NSEC_ERROR_QNAME_NOT_COVERED)

        if self.nsec_names_covering_wildcard:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(NSEC_ERROR_WILDCARD_COVERED)

        # if it validation_status, we project out just the pertinent NSEC records
        # otherwise clone it by projecting them all
        if self.validation_status == NSEC_STATUS_VALID:
            covering_names = set()
            for names in self.closest_encloser.values() + self.nsec_names_covering_qname.values():
                covering_names.update(names)
            self.nsec_set_info = nsec_set_info.project(*filter(lambda x: x is not None, covering_names))
        else:
            self.nsec_set_info = nsec_set_info.project(*list(nsec_set_info.rrsets))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG):
        d = super(NSEC3StatusWildcard, self).serialize(rrset_info_serializer, consolidate_clients=consolidate_clients, loglevel=loglevel)
        try:
            del d['meta']['wildcard']
        except KeyError:
            pass
        try:
            del d['meta']['wildcard_digest']
        except KeyError:
            pass
        if loglevel <= logging.DEBUG:
            if None in self.closest_encloser.values()[0]:
                d['meta']['closest_encloser']['inferred_from_wildcard'] = True
            else:
                d['meta']['closest_encloser']['inferred_from_wildcard'] = False
        return d
    
class NSEC3StatusNoAnswer(object):
    def __init__(self, qname, rdtype, origin, referral, nsec_set_info):
        self.qname = qname
        self.rdtype = rdtype
        self.origin = origin
        self.referral = referral
        self.wildcard_name = None
        self.warnings = []
        self.errors = []

        self.name_digest_map = {}

        self.closest_encloser = nsec_set_info.get_closest_encloser(qname, origin)

        self.nsec_names_covering_qname = {}
        self.nsec_names_covering_wildcard = {}
        self.nsec_for_qname = set()
        self.nsec_for_wildcard_name = set()
        self.has_rdtype = False
        self.has_cname = False
        self.has_ns = False
        self.has_ds = False
        self.has_soa = False
        self.opt_out = False
        self.wildcard_has_rdtype = False
        self.wildcard_has_cname = False

        for (salt, alg, iterations), nsec3_names in nsec_set_info.nsec3_params.items():
            digest_name = nsec_set_info.get_digest_name_for_nsec3(self.qname, self.origin, salt, alg, iterations)
            if self.qname not in self.name_digest_map:
                self.name_digest_map[self.qname] = {}
            self.name_digest_map[self.qname][(salt, alg, iterations)] = digest_name

            for encloser in self.closest_encloser:
                wildcard_name = self._get_wildcard(encloser)
                digest_name = nsec_set_info.get_digest_name_for_nsec3(wildcard_name, self.origin, salt, alg, iterations)
                if digest_name in nsec3_names:
                    self.nsec_for_wildcard_name.add(digest_name)
                    if nsec_set_info.rdtype_exists_in_bitmap(digest_name, rdtype): self.wildcard_has_rdtype = True
                    if nsec_set_info.rdtype_exists_in_bitmap(digest_name, dns.rdatatype.CNAME): self.wildcard_has_cname = True

                if wildcard_name not in self.name_digest_map:
                    self.name_digest_map[wildcard_name] = {}
                self.name_digest_map[wildcard_name][(salt, alg, iterations)] = digest_name

        for (salt, alg, iterations), nsec3_names in nsec_set_info.nsec3_params.items():
            digest_name = self.name_digest_map[self.qname][(salt, alg, iterations)]
            if digest_name in nsec3_names:
                self.nsec_for_qname.add(digest_name)
                if nsec_set_info.rdtype_exists_in_bitmap(digest_name, rdtype): self.has_rdtype = True
                if nsec_set_info.rdtype_exists_in_bitmap(digest_name, dns.rdatatype.CNAME): self.has_cname = True
                if nsec_set_info.rdtype_exists_in_bitmap(digest_name, dns.rdatatype.NS): self.has_ns = True
                if nsec_set_info.rdtype_exists_in_bitmap(digest_name, dns.rdatatype.DS): self.has_ds = True
                if nsec_set_info.rdtype_exists_in_bitmap(digest_name, dns.rdatatype.SOA): self.has_soa = True

            else:
                for encloser in self.closest_encloser:
                    next_closest_encloser = self._get_next_closest_encloser(encloser)
                    digest_name = nsec_set_info.get_digest_name_for_nsec3(next_closest_encloser, self.origin, salt, alg, iterations)
                    if next_closest_encloser not in self.name_digest_map:
                        self.name_digest_map[next_closest_encloser] = {}
                    self.name_digest_map[next_closest_encloser][(salt, alg, iterations)] = digest_name

                    covering_names = nsec_set_info.nsec3_covering_name(digest_name, salt, alg, iterations)
                    if covering_names:
                        self.nsec_names_covering_qname[digest_name] = covering_names

        self._set_validation_status(nsec_set_info)

    def __unicode__(self):
        return u'NSEC3 record(s) proving non-existence (NXRRSET) of %s/%s' % (self.qname.canonicalize().to_text(), dns.rdatatype.to_text(self.rdtype))

    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, self.qname)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                self.qname == other.qname and self.rdtype == other.rdtype and self.origin == other.origin and self.referral == other.referral and self.nsec_set_info == other.nsec_set_info

    def _get_next_closest_encloser(self, encloser):
        return dns.name.Name(self.qname.labels[-(len(encloser)+1):])

    def _get_wildcard(self, encloser):
        return dns.name.from_text('*', encloser)

    def _set_validation_status(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        if self.nsec_for_qname:
            # RFC 4034 5.2, 6840 4.4
            if self.rdtype == dns.rdatatype.DS or self.referral:
                if not (self.has_ns and not self.has_ds and not self.has_soa):
                    self.errors.append(NSEC_ERROR_REFERRAL_BAD_RDTYPES)
                    self.validation_status = NSEC_STATUS_INVALID
            # RFC 5155, section 8.5, 8.6
            if self.has_rdtype:
                self.errors.append(NSEC_ERROR_RDTYPE_IN_BITMAP)
                self.validation_status = NSEC_STATUS_INVALID
            if self.has_cname:
                self.errors.append(NSEC_ERROR_CNAME_IN_BITMAP)
                self.validation_status = NSEC_STATUS_INVALID
        elif self.nsec_for_wildcard_name:
            if not self.closest_encloser:
                self.errors.append(NSEC_ERROR_NO_CLOSEST_ENCLOSER)
                self.validation_status = NSEC_STATUS_INVALID
            if not self.nsec_names_covering_qname:
                self.errors.append(NSEC_ERROR_QNAME_NOT_COVERED)
                self.validation_status = NSEC_STATUS_INVALID
            if self.wildcard_has_rdtype:
                self.errors.append(NSEC_ERROR_RDTYPE_IN_BITMAP)
                self.validation_status = NSEC_STATUS_INVALID
        elif self.rdtype == dns.rdatatype.DS and self.nsec_names_covering_qname and self.closest_encloser:
            for digest_name, covering_names in self.nsec_names_covering_qname.items():
                for nsec_name in covering_names:
                    if nsec_set_info.rrsets[nsec_name].rrset[0].flags & 0x01:
                        self.opt_out = True
            if not self.opt_out:
                self.errors.append(NSEC_ERROR_NO_MATCHING_NSEC)
                self.validation_status = NSEC_STATUS_INVALID
        else:
            self.errors.append(NSEC_ERROR_NO_MATCHING_NSEC)
            self.validation_status = NSEC_STATUS_INVALID

        # if it validation_status, we project out just the pertinent NSEC records
        # otherwise clone it by projecting them all
        if self.validation_status == NSEC_STATUS_VALID:
            covering_names = set()
            for names in self.closest_encloser.values():
                covering_names.update(names)
            if self.nsec_for_qname:
                covering_names.update(self.nsec_for_qname)
            else:
                for names in self.nsec_names_covering_qname.values():
                    covering_names.update(names)
            if self.nsec_for_wildcard_name is not None:
                covering_names.update(self.nsec_for_wildcard_name)
            self.nsec_set_info = nsec_set_info.project(*list(covering_names))
        else:
            self.nsec_set_info = nsec_set_info.project(*list(nsec_set_info.rrsets))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG):
        d = collections.OrderedDict()

        show_basic = (self.warnings and loglevel <= logging.WARNING) or (self.errors and loglevel <= logging.ERROR) or self.validation_status != STATUS_VALID

        if loglevel <= logging.INFO or show_basic:
            d['description'] = unicode(self)

        d['nsec3'] = []
        for nsec_rrset in self.nsec_set_info.rrsets.values():
            if rrset_info_serializer is not None:
                nsec_serialized = rrset_info_serializer(nsec_rrset, consolidate_clients=consolidate_clients, show_servers=False, loglevel=loglevel)
                if nsec_serialized:
                    d['nsec3'].append(nsec_serialized)
            elif loglevel <= logging.DEBUG:
                d['nsec3'].append(nsec_rrset.serialize(consolidate_clients=consolidate_clients, show_servers=False))
        if not d['nsec3']:
            del d['nsec3']

        if loglevel <= logging.DEBUG:
            d['meta'] = collections.OrderedDict()
            d['meta']['opt_out'] = self.opt_out

            if self.nsec_for_qname:
                d['meta']['qname'] = fmt.humanize_name(self.qname)
                d['meta']['qname_digest'] = fmt.format_nsec3_name(self.name_digest_map[self.qname].items()[0][1])
                d['meta']['nsec_matching_qname'] = collections.OrderedDict((
                    ('qname_digest', fmt.format_nsec3_name(list(self.nsec_for_qname)[0])),
                    #TODO - add rdtypes bitmap
                ))

            if self.closest_encloser:
                encloser_name, nsec_names = self.closest_encloser.items()[0]
                nsec_name = list(nsec_names)[0]
                d['meta']['closest_encloser'] = collections.OrderedDict((
                    ('name', encloser_name.canonicalize().to_text()),
                    ('name_digest', fmt.format_nsec3_name(nsec_name)),
                ))

                next_closest_encloser = self._get_next_closest_encloser(encloser_name)
                d['meta']['next_closest_encloser'] = fmt.humanize_name(next_closest_encloser)
                d['meta']['next_closest_encloser_digest'] = fmt.format_nsec3_name(self.name_digest_map[next_closest_encloser].items()[0][1])

                if self.nsec_names_covering_qname:
                    qname, nsec_names = self.nsec_names_covering_qname.items()[0]
                    nsec_name = list(nsec_names)[0]
                    next_name = self.nsec_set_info.name_for_nsec3_next(nsec_name)
                    d['meta']['nsec_chain_covering_next_closest_encloser'] = collections.OrderedDict((
                        ('qname_digest', fmt.format_nsec3_name(qname)),
                        ('nsec3_owner', fmt.format_nsec3_name(nsec_name)),
                        ('nsec3_next', fmt.format_nsec3_name(next_name)),
                    ))

                wildcard_name = self._get_wildcard(encloser_name)
                wildcard_digest = self.name_digest_map[wildcard_name].items()[0][1]
                d['meta']['wildcard'] = wildcard_name.canonicalize().to_text()
                d['meta']['wildcard_digest'] = fmt.format_nsec3_name(wildcard_digest)
                if self.nsec_for_wildcard_name:
                    d['meta']['nsec_matching_wildcard'] = collections.OrderedDict((
                        ('wildcard_digest', fmt.format_nsec3_name(list(self.nsec_for_wildcard_name)[0])),
                        #TODO - add rdtypes bitmap
                    ))

            if not self.nsec_for_qname and not self.closest_encloser:
                d['meta']['qname'] = fmt.humanize_name(self.qname)
                d['meta']['qname_digest'] = fmt.format_nsec3_name(self.name_digest_map[self.qname].items()[0][1])

        if loglevel <= logging.INFO or show_basic:
            d['status'] = nsec_status_mapping[self.validation_status]

        if loglevel <= logging.DEBUG or show_basic:
            servers = tuple_to_dict(self.nsec_set_info.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

        if self.warnings and loglevel <= logging.WARNING:
            d['warnings'] = [nsec_error_mapping[e] for e in self.warnings]
        if self.errors and loglevel <= logging.ERROR:
            d['errors'] = [nsec_error_mapping[e] for e in self.errors]
        return d

class CNAMEFromDNAMEStatus(object):
    def __init__(self, synthesized_cname, included_cname):
        self.synthesized_cname = synthesized_cname
        self.included_cname = included_cname
        self.warnings = []
        self.errors = []

        if self.included_cname is None:
            self.validation_status = DNAME_STATUS_INVALID
            self.errors.append(DNAME_ERROR_NO_CNAME)
        else:
            self.validation_status = DNAME_STATUS_VALID
            if self.included_cname.rrset[0].target != self.synthesized_cname.rrset[0].target:
                self.errors.append(DNAME_ERROR_TARGET_MISMATCH)
                self.validation_status = DNAME_STATUS_INVALID_TARGET
            if self.included_cname.rrset.ttl != self.synthesized_cname.rrset.ttl:
                if self.included_cname.rrset.ttl == 0:
                    self.warnings.append(DNAME_ERROR_TTL_ZERO)
                else:
                    self.warnings.append(DNAME_ERROR_TTL_MISMATCH)

    def __unicode__(self):
        return u'CNAME synthesis for %s from %s/%s' % (self.synthesized_cname.rrset.name.canonicalize().to_text(), self.synthesized_cname.dname_info.rrset.name.canonicalize().to_text(), dns.rdatatype.to_text(self.synthesized_cname.dname_info.rrset.rdtype))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG):
        values = []
        d = collections.OrderedDict()

        show_basic = (self.warnings and loglevel <= logging.WARNING) or (self.errors and loglevel <= logging.ERROR) or self.validation_status != STATUS_VALID

        if loglevel <= logging.INFO or show_basic:
            d['description'] = unicode(self)

        if rrset_info_serializer is not None:
            dname_serialized = rrset_info_serializer(self.synthesized_cname.dname_info, consolidate_clients=consolidate_clients, show_servers=False, loglevel=loglevel)
            if dname_serialized:
                d['dname'] = dname_serialized
        elif loglevel <= logging.DEBUG:
            d['dname'] = self.synthesized_cname.dname_info.serialize(consolidate_clients=consolidate_clients, show_servers=False)

        if loglevel <= logging.DEBUG:
            d['meta'] = collections.OrderedDict()
            if self.included_cname is not None:
                d['meta']['cname_owner'] = self.included_cname.rrset.name.canonicalize().to_text()
                d['meta']['cname_target'] = self.included_cname.rrset[0].target.canonicalize().to_text()

        if loglevel <= logging.INFO or self.validation_status != STATUS_VALID:
            d['status'] = dname_status_mapping[self.validation_status]

        if loglevel <= logging.DEBUG or show_basic:
            servers = tuple_to_dict(self.synthesized_cname.dname_info.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

        if self.warnings and loglevel <= logging.WARNING:
            d['warnings'] = [dname_error_mapping[e] for e in self.warnings]
        if self.errors and loglevel <= logging.ERROR:
            d['errors'] = [dname_error_mapping[e] for e in self.errors]
        return d
