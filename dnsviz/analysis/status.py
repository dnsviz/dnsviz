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
import datetime
import logging

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

import dns.name, dns.rdatatype

from dnsviz import base32
from dnsviz import crypto
from dnsviz import format as fmt
from dnsviz.util import tuple_to_dict
lb2s = fmt.latin1_binary_to_string

from . import errors as Errors

CLOCK_SKEW_WARNING = 300

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

NAME_STATUS_NOERROR = 0
NAME_STATUS_NXDOMAIN = 1
NAME_STATUS_INDETERMINATE = 2
name_status_mapping = {
        NAME_STATUS_NOERROR: 'NOERROR',
        NAME_STATUS_NXDOMAIN: 'NXDOMAIN',
        NAME_STATUS_INDETERMINATE: 'INDETERMINATE',
}

RRSIG_STATUS_VALID = STATUS_VALID
RRSIG_STATUS_INDETERMINATE_NO_DNSKEY = 1
RRSIG_STATUS_INDETERMINATE_MATCH_PRE_REVOKE = 2
RRSIG_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM = 3
RRSIG_STATUS_ALGORITHM_IGNORED = 4
RRSIG_STATUS_EXPIRED = 5
RRSIG_STATUS_PREMATURE = 6
RRSIG_STATUS_INVALID_SIG = 7
RRSIG_STATUS_INVALID = 8
rrsig_status_mapping = {
        RRSIG_STATUS_VALID: 'VALID',
        RRSIG_STATUS_INDETERMINATE_NO_DNSKEY: 'INDETERMINATE_NO_DNSKEY',
        RRSIG_STATUS_INDETERMINATE_MATCH_PRE_REVOKE: 'INDETERMINATE_MATCH_PRE_REVOKE',
        RRSIG_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM: 'INDETERMINATE_UNKNOWN_ALGORITHM',
        RRSIG_STATUS_ALGORITHM_IGNORED: 'ALGORITHM_IGNORED',
        RRSIG_STATUS_EXPIRED: 'EXPIRED',
        RRSIG_STATUS_PREMATURE: 'PREMATURE',
        RRSIG_STATUS_INVALID_SIG: 'INVALID_SIG',
        RRSIG_STATUS_INVALID: 'INVALID',
}

DS_STATUS_VALID = STATUS_VALID
DS_STATUS_INDETERMINATE_NO_DNSKEY = 1
DS_STATUS_INDETERMINATE_MATCH_PRE_REVOKE = 2
DS_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM = 3
DS_STATUS_ALGORITHM_IGNORED = 4
DS_STATUS_INVALID_DIGEST = 5
DS_STATUS_INVALID = 6
ds_status_mapping = {
        DS_STATUS_VALID: 'VALID',
        DS_STATUS_INDETERMINATE_NO_DNSKEY: 'INDETERMINATE_NO_DNSKEY',
        DS_STATUS_INDETERMINATE_MATCH_PRE_REVOKE: 'INDETERMINATE_MATCH_PRE_REVOKE',
        DS_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM: 'INDETERMINATE_UNKNOWN_ALGORITHM',
        DS_STATUS_ALGORITHM_IGNORED: 'ALGORITHM_IGNORED',
        DS_STATUS_INVALID_DIGEST: 'INVALID_DIGEST',
        DS_STATUS_INVALID: 'INVALID',
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

RRSIG_SIG_LENGTHS_BY_ALGORITHM = {
        12: 512, 13: 512, 14: 768, 15: 512, 16: 912,
}
RRSIG_SIG_LENGTH_ERRORS = {
        12: Errors.RRSIGBadLengthGOST, 13: Errors.RRSIGBadLengthECDSA256,
        14: Errors.RRSIGBadLengthECDSA384, 15: Errors.RRSIGBadLengthEd25519,
        16: Errors.RRSIGBadLengthEd448,
}
DS_DIGEST_ALGS_STRONGER_THAN_SHA1 = (2, 4)
DS_DIGEST_ALGS_IGNORING_SHA1 = (2,)

# RFC 8624 Section 3.1
DNSKEY_ALGS_NOT_RECOMMENDED = (5, 7, 10)
DNSKEY_ALGS_PROHIBITED = (1, 3, 6, 12)
DNSKEY_ALGS_VALIDATION_PROHIBITED = (1, 3, 6)

# RFC 8624 Section 3.2
DS_DIGEST_ALGS_NOT_RECOMMENDED = ()
DS_DIGEST_ALGS_PROHIBITED = (0, 1, 3)
DS_DIGEST_ALGS_VALIDATION_PROHIBITED = ()

class RRSIGStatus(object):
    def __init__(self, rrset, rrsig, dnskey, zone_name, reference_ts, supported_algs):
        self.rrset = rrset
        self.rrsig = rrsig
        self.dnskey = dnskey
        self.zone_name = zone_name
        self.reference_ts = reference_ts
        self.warnings = []
        self.errors = []

        if self.dnskey is None:
            self.signature_valid = None
        else:
            self.signature_valid = crypto.validate_rrsig(dnskey.rdata.algorithm, rrsig.signature, rrset.message_for_rrsig(rrsig), dnskey.rdata.key)

        self.validation_status = RRSIG_STATUS_VALID
        if self.signature_valid is None or self.rrsig.algorithm not in supported_algs:
            # Either we can't validate the cryptographic signature, or we are
            # explicitly directed to ignore the algorithm.
            if self.dnskey is None:
                # In this case, there is no corresponding DNSKEY, so we make
                # the status "INDETERMINATE".
                if self.validation_status == RRSIG_STATUS_VALID:
                    self.validation_status = RRSIG_STATUS_INDETERMINATE_NO_DNSKEY

            else:
                # If there is a DNSKEY, then we look at *why* we are ignoring
                # the cryptographic signature.
                if self.dnskey.rdata.algorithm in DNSKEY_ALGS_VALIDATION_PROHIBITED:
                    # In this case, specification dictates that the algorithm
                    # MUST NOT be validated, so we mark it as ignored.
                    if self.validation_status == RRSIG_STATUS_VALID:
                        self.validation_status = RRSIG_STATUS_ALGORITHM_IGNORED
                else:
                    # In this case, we can't validate this particular
                    # algorithm, either because the code doesn't support it,
                    # or because we have been explicitly directed to ignore it.
                    # In either case, mark it as "UNKNOWN", and warn that it is
                    # not supported.
                    if self.validation_status == RRSIG_STATUS_VALID:
                        self.validation_status = RRSIG_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM
                    self.warnings.append(Errors.AlgorithmNotSupported(algorithm=self.rrsig.algorithm))

        # Independent of whether or not we considered the cryptographic
        # validation, issue a warning if we are using an algorithm for which
        # validation or signing has been prohibited.
        #
        # Signing is prohibited
        if self.rrsig.algorithm in DNSKEY_ALGS_VALIDATION_PROHIBITED:
            self.warnings.append(Errors.AlgorithmValidationProhibited(algorithm=self.rrsig.algorithm))
        # Validation is prohibited or, at least, not recommended
        if self.rrsig.algorithm in DNSKEY_ALGS_PROHIBITED:
            self.warnings.append(Errors.AlgorithmProhibited(algorithm=self.rrsig.algorithm))
        elif self.rrsig.algorithm in DNSKEY_ALGS_NOT_RECOMMENDED:
            self.warnings.append(Errors.AlgorithmNotRecommended(algorithm=self.rrsig.algorithm))

        if self.rrset.ttl_cmp:
            if self.rrset.rrset.ttl != self.rrset.rrsig_info[self.rrsig].ttl:
                self.warnings.append(Errors.RRsetTTLMismatch(rrset_ttl=self.rrset.rrset.ttl, rrsig_ttl=self.rrset.rrsig_info[self.rrsig].ttl))
        if self.rrset.rrsig_info[self.rrsig].ttl > self.rrsig.original_ttl:
            self.errors.append(Errors.OriginalTTLExceeded(rrset_ttl=self.rrset.rrset.ttl, original_ttl=self.rrsig.original_ttl))

        min_ttl = min(self.rrset.rrset.ttl, self.rrset.rrsig_info[self.rrsig].ttl, self.rrsig.original_ttl)

        if (zone_name is not None and self.rrsig.signer != zone_name) or \
                (zone_name is None and not self.rrset.rrset.name.is_subdomain(self.rrsig.signer)):
            if self.validation_status == RRSIG_STATUS_VALID:
                self.validation_status = RRSIG_STATUS_INVALID
            if zone_name is None:
                zn = self.rrsig.signer
            else:
                zn = zone_name
            self.errors.append(Errors.SignerNotZone(zone_name=fmt.humanize_name(zn), signer_name=fmt.humanize_name(self.rrsig.signer)))

        if self.dnskey is not None and \
                self.dnskey.rdata.flags & fmt.DNSKEY_FLAGS['revoke'] and self.rrsig.covers() != dns.rdatatype.DNSKEY:
            if self.rrsig.key_tag != self.dnskey.key_tag:
                if self.validation_status == RRSIG_STATUS_VALID:
                    self.validation_status = RRSIG_STATUS_INDETERMINATE_MATCH_PRE_REVOKE
            else:
                self.errors.append(Errors.DNSKEYRevokedRRSIG())
                if self.validation_status == RRSIG_STATUS_VALID:
                    self.validation_status = RRSIG_STATUS_INVALID

        sig_len = len(self.rrsig.signature) << 3
        if self.rrsig.algorithm in RRSIG_SIG_LENGTHS_BY_ALGORITHM and \
                sig_len != RRSIG_SIG_LENGTHS_BY_ALGORITHM[self.rrsig.algorithm]:
            self.errors.append(RRSIG_SIG_LENGTH_ERRORS[self.rrsig.algorithm](length=sig_len))

        if self.reference_ts < self.rrsig.inception:
            if self.validation_status == RRSIG_STATUS_VALID:
                self.validation_status = RRSIG_STATUS_PREMATURE
            self.errors.append(Errors.InceptionInFuture(inception=fmt.timestamp_to_datetime(self.rrsig.inception), reference_time=fmt.timestamp_to_datetime(self.reference_ts)))
        elif self.reference_ts - CLOCK_SKEW_WARNING < self.rrsig.inception:
            self.warnings.append(Errors.InceptionWithinClockSkew(inception=fmt.timestamp_to_datetime(self.rrsig.inception), reference_time=fmt.timestamp_to_datetime(self.reference_ts)))

        if self.reference_ts >= self.rrsig.expiration:
            if self.validation_status == RRSIG_STATUS_VALID:
                self.validation_status = RRSIG_STATUS_EXPIRED
            self.errors.append(Errors.ExpirationInPast(expiration=fmt.timestamp_to_datetime(self.rrsig.expiration), reference_time=fmt.timestamp_to_datetime(self.reference_ts)))
        elif self.reference_ts + min_ttl >= self.rrsig.expiration:
            self.errors.append(Errors.TTLBeyondExpiration(expiration=fmt.timestamp_to_datetime(self.rrsig.expiration), rrsig_ttl=min_ttl, reference_time=fmt.timestamp_to_datetime(self.reference_ts)))
        elif self.reference_ts + CLOCK_SKEW_WARNING >= self.rrsig.expiration:
            self.warnings.append(Errors.ExpirationWithinClockSkew(expiration=fmt.timestamp_to_datetime(self.rrsig.expiration), reference_time=fmt.timestamp_to_datetime(self.reference_ts)))

        if self.signature_valid == False and self.dnskey.rdata.algorithm in supported_algs:
            # only report this if we're not referring to a key revoked post-sign
            if self.dnskey.key_tag == self.rrsig.key_tag:
                if self.validation_status == RRSIG_STATUS_VALID:
                    self.validation_status = RRSIG_STATUS_INVALID_SIG
                self.errors.append(Errors.SignatureInvalid())

    def __str__(self):
        return 'RRSIG covering %s/%s' % (fmt.humanize_name(self.rrset.rrset.name), dns.rdatatype.to_text(self.rrset.rrset.rdtype))

    def serialize(self, consolidate_clients=True, loglevel=logging.DEBUG, html_format=False, map_ip_to_ns_name=None):
        d = OrderedDict()

        erroneous_status = self.validation_status not in (RRSIG_STATUS_VALID, RRSIG_STATUS_INDETERMINATE_NO_DNSKEY, RRSIG_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM)

        show_id = loglevel <= logging.INFO or \
                (self.warnings and loglevel <= logging.WARNING) or \
                (self.errors and loglevel <= logging.ERROR) or \
                erroneous_status

        if html_format:
            formatter = lambda x: escape(x, True)
        else:
            formatter = lambda x: x

        if show_id:
            d['id'] = '%s/%d/%d' % (lb2s(self.rrsig.signer.canonicalize().to_text()), self.rrsig.algorithm, self.rrsig.key_tag)

        if loglevel <= logging.DEBUG:
            d.update((
                ('description', formatter(str(self))),
                ('signer', formatter(lb2s(self.rrsig.signer.canonicalize().to_text()))),
                ('algorithm', self.rrsig.algorithm),
                ('key_tag', self.rrsig.key_tag),
                ('original_ttl', self.rrsig.original_ttl),
                ('labels', self.rrsig.labels),
                ('inception', fmt.timestamp_to_str(self.rrsig.inception)),
                ('expiration', fmt.timestamp_to_str(self.rrsig.expiration)),
                ('signature', lb2s(base64.b64encode(self.rrsig.signature))),
                ('ttl', self.rrset.rrsig_info[self.rrsig].ttl),
            ))

            if html_format:
                d['algorithm'] = '%d (%s)' % (self.rrsig.algorithm, fmt.DNSKEY_ALGORITHMS.get(self.rrsig.algorithm, self.rrsig.algorithm))
                d['original_ttl'] = '%d (%s)' % (self.rrsig.original_ttl, fmt.humanize_time(self.rrsig.original_ttl))
                if self.rrset.is_wildcard(self.rrsig):
                    d['labels'] = '%d (wildcard)' % (self.rrsig.labels)
                else:
                    d['labels'] = '%d (no wildcard)' % (self.rrsig.labels)
                d['inception'] += ' (%s)' % (fmt.format_diff(fmt.timestamp_to_datetime(self.reference_ts), fmt.timestamp_to_datetime(self.rrsig.inception)))
                d['expiration'] += ' (%s)' % (fmt.format_diff(fmt.timestamp_to_datetime(self.reference_ts), fmt.timestamp_to_datetime(self.rrsig.expiration)))
                d['ttl'] = '%d (%s)' % (self.rrset.rrsig_info[self.rrsig].ttl, fmt.humanize_time(self.rrset.rrsig_info[self.rrsig].ttl))

        if loglevel <= logging.INFO or erroneous_status:
            d['status'] = rrsig_status_mapping[self.validation_status]

        if loglevel <= logging.INFO:
            servers = tuple_to_dict(self.rrset.rrsig_info[self.rrsig].servers_clients)
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
            for server,client in self.rrset.rrsig_info[self.rrsig].servers_clients:
                for response in self.rrset.rrsig_info[self.rrsig].servers_clients[(server, client)]:
                    if response is not None:
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

class DSStatus(object):
    def __init__(self, ds, ds_meta, dnskey, supported_digest_algs):
        self.ds = ds
        self.ds_meta = ds_meta
        self.dnskey = dnskey
        self.warnings = []
        self.errors = []

        if self.dnskey is None:
            self.digest_valid = None
        else:
            self.digest_valid = crypto.validate_ds_digest(ds.digest_type, ds.digest, dnskey.message_for_ds())

        self.validation_status = DS_STATUS_VALID
        if self.digest_valid is None or self.ds.digest_type not in supported_digest_algs:
            # Either we cannot reproduce a digest with this type, or we are
            # explicitly directed to ignore the digest type.
            if self.dnskey is None:
                # In this case, there is no corresponding DNSKEY, so we make
                # the status "INDETERMINATE".
                if self.validation_status == DS_STATUS_VALID:
                    self.validation_status = DS_STATUS_INDETERMINATE_NO_DNSKEY
            else:
                # If there is a DNSKEY, then we look at *why* we are ignoring
                # the digest of the DNSKEY.
                if self.ds.digest_type in DS_DIGEST_ALGS_VALIDATION_PROHIBITED:
                    # In this case, specification dictates that the algorithm
                    # MUST NOT be validated, so we mark it as ignored.
                    if self.validation_status == DS_STATUS_VALID:
                        self.validation_status = DS_STATUS_ALGORITHM_IGNORED
                else:
                    # In this case, we can't validate this particular
                    # digest type, either because the code doesn't support it,
                    # or because we have been explicitly directed to ignore it.
                    # In either case, mark it as "UNKNOWN", and warn that it is
                    # not supported.
                    if self.validation_status == DS_STATUS_VALID:
                        self.validation_status = DS_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM
                    self.warnings.append(Errors.DigestAlgorithmNotSupported(algorithm=self.ds.digest_type))

        # Independent of whether or not we considered the digest for
        # validation, issue a warning if we are using a digest type for which
        # validation or signing has been prohibited.
        #
        # Signing is prohibited
        if self.ds.digest_type in DS_DIGEST_ALGS_VALIDATION_PROHIBITED:
            self.warnings.append(Errors.DigestAlgorithmValidationProhibited(algorithm=self.ds.digest_type))
        # Validation is prohibited or, at least, not recommended
        if self.ds.digest_type in DS_DIGEST_ALGS_PROHIBITED:
            self.warnings.append(Errors.DigestAlgorithmProhibited(algorithm=self.ds.digest_type))
        elif self.ds.digest_type in DS_DIGEST_ALGS_NOT_RECOMMENDED:
            self.warnings.append(Errors.DigestAlgorithmNotRecommended(algorithm=self.ds.digest_type))

        if self.dnskey is not None and \
                self.dnskey.rdata.flags & fmt.DNSKEY_FLAGS['revoke']:
            if self.dnskey.key_tag != self.ds.key_tag:
                if self.validation_status == DS_STATUS_VALID:
                    self.validation_status = DS_STATUS_INDETERMINATE_MATCH_PRE_REVOKE
            else:
                self.errors.append(Errors.DNSKEYRevokedDS())
                if self.validation_status == DS_STATUS_VALID:
                    self.validation_status = DS_STATUS_INVALID

        if self.digest_valid == False and self.ds.digest_type in supported_digest_algs:
            # only report this if we're not referring to a key revoked post-DS
            if self.dnskey.key_tag == self.ds.key_tag:
                if self.validation_status == DS_STATUS_VALID:
                    self.validation_status = DS_STATUS_INVALID_DIGEST
                self.errors.append(Errors.DigestInvalid())

        # RFC 4509
        if self.ds.digest_type == 1:
            stronger_algs_all_ds = set()
            # Cycle through all other DS records in the DS RRset, and
            # create a list of digest types that are stronger than SHA1
            # and are being used by DS records across the *entire* DS.
            for ds_rdata in self.ds_meta.rrset:
                if ds_rdata.digest_type in DS_DIGEST_ALGS_STRONGER_THAN_SHA1:
                    stronger_algs_all_ds.add(ds_rdata.digest_type)

            # Consider only digest types that we actually support
            stronger_algs_all_ds.intersection_update(supported_digest_algs)

            if stronger_algs_all_ds:
                # If there are DS records in the DS RRset with digest type
                # stronger than SHA1, then this one MUST be ignored by
                # validators (RFC 4509).
                for digest_alg in stronger_algs_all_ds:
                    if digest_alg in DS_DIGEST_ALGS_IGNORING_SHA1:
                        if self.validation_status == DS_STATUS_VALID:
                            self.validation_status = DS_STATUS_ALGORITHM_IGNORED
                        self.warnings.append(Errors.DSDigestAlgorithmIgnored(algorithm=1, new_algorithm=digest_alg))
                    else:
                        self.warnings.append(Errors.DSDigestAlgorithmMaybeIgnored(algorithm=1, new_algorithm=digest_alg))

    def __str__(self):
        return '%s record(s) corresponding to DNSKEY for %s (algorithm %d (%s), key tag %d)' % (dns.rdatatype.to_text(self.ds_meta.rrset.rdtype), fmt.humanize_name(self.ds_meta.rrset.name), self.ds.algorithm, fmt.DNSKEY_ALGORITHMS.get(self.ds.algorithm, self.ds.algorithm), self.ds.key_tag)

    def serialize(self, consolidate_clients=True, loglevel=logging.DEBUG, html_format=False, map_ip_to_ns_name=True):
        d = OrderedDict()

        erroneous_status = self.validation_status not in (DS_STATUS_VALID, DS_STATUS_INDETERMINATE_NO_DNSKEY, DS_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM)

        show_id = loglevel <= logging.INFO or \
                (self.warnings and loglevel <= logging.WARNING) or \
                (self.errors and loglevel <= logging.ERROR) or \
                erroneous_status

        if html_format:
            formatter = lambda x: escape(x, True)
        else:
            formatter = lambda x: x

        if show_id:
            d['id'] = '%d/%d/%d' % (self.ds.algorithm, self.ds.key_tag, self.ds.digest_type)

        if loglevel <= logging.DEBUG:
            d.update((
                ('description', formatter(str(self))),
                ('algorithm', self.ds.algorithm),
                ('key_tag', self.ds.key_tag),
                ('digest_type', self.ds.digest_type),
                ('digest', lb2s(base64.b64encode(self.ds.digest))),
            ))

            if html_format:
                d['algorithm'] = '%d (%s)' % (self.ds.algorithm, fmt.DNSKEY_ALGORITHMS.get(self.ds.algorithm, self.ds.algorithm))
                d['digest_type'] = '%d (%s)' % (self.ds.digest_type, fmt.DS_DIGEST_TYPES.get(self.ds.digest_type, self.ds.digest_type))

            d['ttl'] = self.ds_meta.rrset.ttl
            if html_format:
                d['ttl'] = '%d (%s)' % (self.ds_meta.rrset.ttl, fmt.humanize_time(self.ds_meta.rrset.ttl))

        if loglevel <= logging.INFO or erroneous_status:
            d['status'] = ds_status_mapping[self.validation_status]

        if loglevel <= logging.INFO:
            servers = tuple_to_dict(self.ds_meta.servers_clients)
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
            for server,client in self.ds_meta.servers_clients:
                for response in self.ds_meta.servers_clients[(server, client)]:
                    if response is not None:
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

class NSECStatus(object):
    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, self.qname)

    def _get_wildcard(self, qname, nsec_rrset):
        covering_name = nsec_rrset.name
        next_name = nsec_rrset[0].next
        for i in range(len(qname)):
            j = -(i + 1)
            if i < len(covering_name) and covering_name[j].lower() == qname[j].lower():
                continue
            elif i < len(next_name) and next_name[j].lower() == qname[j].lower():
                continue
            else:
                break
        return dns.name.Name(('*',) + qname[-i:])

class NSECStatusNXDOMAIN(NSECStatus):
    def __init__(self, qname, rdtype, origin, is_zone, nsec_set_info):
        self.qname = qname
        self.origin = origin
        self.is_zone = is_zone
        self.warnings = []
        self.errors = []

        self.wildcard_name = None

        self.nsec_names_covering_qname = {}
        covering_names = nsec_set_info.nsec_covering_name(self.qname)
        self.opt_out = None

        if covering_names:
            self.nsec_names_covering_qname[self.qname] = covering_names

            covering_name = list(covering_names)[0]
            self.wildcard_name = self._get_wildcard(qname, nsec_set_info.rrsets[covering_name].rrset)

        self.nsec_names_covering_wildcard = {}
        if self.wildcard_name is not None:
            covering_names = nsec_set_info.nsec_covering_name(self.wildcard_name)
            if covering_names:
                self.nsec_names_covering_wildcard[self.wildcard_name] = covering_names

        # check for covering of the origin
        self.nsec_names_covering_origin = {}
        covering_names = nsec_set_info.nsec_covering_name(self.origin)
        if covering_names:
            self.nsec_names_covering_origin[self.origin] = covering_names

        self._set_validation_status(nsec_set_info)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                self.qname == other.qname and self.origin == other.origin and self.nsec_set_info == other.nsec_set_info

    def __hash__(self):
        return hash(id(self))

    def _set_validation_status(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        if not self.nsec_names_covering_qname:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(Errors.SnameNotCoveredNameError(sname=fmt.humanize_name(self.qname)))
        if not self.nsec_names_covering_wildcard and self.wildcard_name is not None:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(Errors.WildcardNotCoveredNSEC(wildcard=fmt.humanize_name(self.wildcard_name)))
        if self.nsec_names_covering_origin:
            self.validation_status = NSEC_STATUS_INVALID
            qname, nsec_names = list(self.nsec_names_covering_origin.items())[0]
            nsec_rrset = nsec_set_info.rrsets[list(nsec_names)[0]].rrset
            self.errors.append(Errors.LastNSECNextNotZone(nsec_owner=fmt.humanize_name(nsec_rrset.name), next_name=fmt.humanize_name(nsec_rrset[0].next), zone_name=fmt.humanize_name(self.origin)))

        # if it validation_status, we project out just the pertinent NSEC records
        # otherwise clone it by projecting them all
        if self.validation_status == NSEC_STATUS_VALID:
            covering_names = set()
            for names in list(self.nsec_names_covering_qname.values()) + list(self.nsec_names_covering_wildcard.values()):
                covering_names.update(names)
            self.nsec_set_info = nsec_set_info.project(*list(covering_names))
        else:
            self.nsec_set_info = nsec_set_info.project(*list(nsec_set_info.rrsets))

    def __str__(self):
        return 'NSEC record(s) proving the non-existence (NXDOMAIN) of %s' % (fmt.humanize_name(self.qname))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG, html_format=False, map_ip_to_ns_name=None):
        d = OrderedDict()

        nsec_list = []
        for nsec_rrset in self.nsec_set_info.rrsets.values():
            if rrset_info_serializer is not None:
                nsec_serialized = rrset_info_serializer(nsec_rrset, consolidate_clients=consolidate_clients, show_servers=False, loglevel=loglevel, html_format=html_format)
                if nsec_serialized:
                    nsec_list.append(nsec_serialized)
            elif loglevel <= logging.DEBUG:
                nsec_list.append(nsec_rrset.serialize(consolidate_clients=consolidate_clients, html_format=html_format))

        erroneous_status = self.validation_status != STATUS_VALID

        show_id = loglevel <= logging.INFO or \
                (self.warnings and loglevel <= logging.WARNING) or \
                (self.errors and loglevel <= logging.ERROR) or \
                (erroneous_status or nsec_list)

        if html_format:
            formatter = lambda x: escape(x, True)
        else:
            formatter = lambda x: x

        if show_id:
            d['id'] = 'NSEC'

        if loglevel <= logging.DEBUG:
            d['description'] = formatter(str(self))

        if nsec_list:
            d['nsec'] = nsec_list

        if loglevel <= logging.DEBUG:
            if self.nsec_names_covering_qname:
                qname, nsec_names = list(self.nsec_names_covering_qname.items())[0]
                nsec_name = list(nsec_names)[0]
                nsec_rr = self.nsec_set_info.rrsets[nsec_name].rrset[0]
                d['sname_covering'] = OrderedDict((
                    ('covered_name', formatter(lb2s(qname.canonicalize().to_text()))),
                    ('nsec_owner', formatter(lb2s(nsec_name.canonicalize().to_text()))),
                    ('nsec_next', formatter(lb2s(nsec_rr.next.canonicalize().to_text())))
                ))
                if self.nsec_names_covering_wildcard:
                    wildcard, nsec_names = list(self.nsec_names_covering_wildcard.items())[0]
                    nsec_name = list(nsec_names)[0]
                    nsec_rr = self.nsec_set_info.rrsets[nsec_name].rrset[0]
                    d['wildcard_covering'] = OrderedDict((
                        ('covered_name', formatter(lb2s(wildcard.canonicalize().to_text()))),
                        ('nsec_owner', formatter(lb2s(nsec_name.canonicalize().to_text()))),
                        ('nsec_next', formatter(lb2s(nsec_rr.next.canonicalize().to_text())))
                    ))

        if loglevel <= logging.INFO or erroneous_status:
            d['status'] = nsec_status_mapping[self.validation_status]

        if loglevel <= logging.INFO:
            servers = tuple_to_dict(self.nsec_set_info.servers_clients)
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
            for server,client in self.nsec_set_info.servers_clients:
                for response in self.nsec_set_info.servers_clients[(server, client)]:
                    if response is not None:
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

class NSECStatusWildcard(NSECStatusNXDOMAIN):
    def __init__(self, qname, wildcard_name, rdtype, origin, is_zone, nsec_set_info):
        self.wildcard_name_from_rrsig = wildcard_name
        super(NSECStatusWildcard, self).__init__(qname, rdtype, origin, is_zone, nsec_set_info)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                super(NSECStatusWildcard, self).__eq__(other) and self.wildcard_name_from_rrsig == other.wildcard_name_from_rrsig

    def __hash__(self):
        return hash(id(self))

    def _next_closest_encloser(self):
        return dns.name.Name(self.qname.labels[-len(self.wildcard_name):])

    def _set_validation_status(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        if self.nsec_names_covering_qname:
            next_closest_encloser = self._next_closest_encloser()
            nsec_covering_next_closest_encloser = nsec_set_info.nsec_covering_name(next_closest_encloser)
            if not nsec_covering_next_closest_encloser:
                self.validation_status = NSEC_STATUS_INVALID
                self.errors.append(Errors.WildcardExpansionInvalid(sname=fmt.humanize_name(self.qname), wildcard=fmt.humanize_name(self.wildcard_name), next_closest_encloser=fmt.humanize_name(next_closest_encloser)))
        else:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(Errors.SnameNotCoveredWildcardAnswer(sname=fmt.humanize_name(self.qname)))

        if self.nsec_names_covering_wildcard:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(Errors.WildcardCoveredAnswerNSEC(wildcard=fmt.humanize_name(self.wildcard_name)))

        if self.nsec_names_covering_origin:
            self.validation_status = NSEC_STATUS_INVALID
            qname, nsec_names = list(self.nsec_names_covering_origin.items())[0]
            nsec_rrset = nsec_set_info.rrsets[list(nsec_names)[0]].rrset
            self.errors.append(Errors.LastNSECNextNotZone(nsec_owner=fmt.humanize_name(nsec_rrset.name), next_name=fmt.humanize_name(nsec_rrset[0].next), zone_name=fmt.humanize_name(self.origin)))

        # if it validation_status, we project out just the pertinent NSEC records
        # otherwise clone it by projecting them all
        if self.validation_status == NSEC_STATUS_VALID:
            covering_names = set()
            for names in self.nsec_names_covering_qname.values():
                covering_names.update(names)
            self.nsec_set_info = nsec_set_info.project(*list(covering_names))
        else:
            self.nsec_set_info = nsec_set_info.project(*list(nsec_set_info.rrsets))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG, html_format=False, map_ip_to_ns_name=None):
        d = super(NSECStatusWildcard, self).serialize(rrset_info_serializer, consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format, map_ip_to_ns_name=map_ip_to_ns_name)
        try:
            del d['wildcard']
        except KeyError:
            pass
        return d

class NSECStatusNODATA(NSECStatus):
    def __init__(self, qname, rdtype, origin, is_zone, nsec_set_info, sname_must_match=False):
        self.qname = qname
        self.rdtype = rdtype
        self.origin = origin
        self.is_zone = is_zone
        self.referral = nsec_set_info.referral
        self.warnings = []
        self.errors = []

        self.wildcard_name = None

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

            if not sname_must_match:
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

            covering_name = list(covering_names)[0]
            self.wildcard_name = self._get_wildcard(qname, nsec_set_info.rrsets[covering_name].rrset)

        self.nsec_for_wildcard_name = None
        self.wildcard_has_rdtype = None
        if self.wildcard_name is not None:
            try:
                self.nsec_for_wildcard_name = nsec_set_info.rrsets[self.wildcard_name]
                self.wildcard_has_rdtype = nsec_set_info.rdtype_exists_in_bitmap(self.wildcard_name, self.rdtype)
            except KeyError:
                pass

        # check for covering of the origin
        self.nsec_names_covering_origin = {}
        covering_names = nsec_set_info.nsec_covering_name(self.origin)
        if covering_names:
            self.nsec_names_covering_origin[self.origin] = covering_names

        self.opt_out = None

        self._set_validation_status(nsec_set_info)

    def __str__(self):
        return 'NSEC record(s) proving non-existence (NODATA) of %s/%s' % (fmt.humanize_name(self.qname), dns.rdatatype.to_text(self.rdtype))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                self.qname == other.qname and self.rdtype == other.rdtype and self.origin == other.origin and self.referral == other.referral and self.nsec_set_info == other.nsec_set_info

    def __hash__(self):
        return hash(id(self))

    def _set_validation_status(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        if self.nsec_for_qname is not None:
            # RFC 4034 5.2, 6840 4.4
            if self.rdtype == dns.rdatatype.DS or self.referral:
                if self.is_zone and not self.has_ns:
                    self.errors.append(Errors.ReferralWithoutNSBitNSEC(sname=fmt.humanize_name(self.qname)))
                    self.validation_status = NSEC_STATUS_INVALID
                if self.has_ds:
                    self.errors.append(Errors.ReferralWithDSBitNSEC(sname=fmt.humanize_name(self.qname)))
                    self.validation_status = NSEC_STATUS_INVALID
                if self.has_soa:
                    self.errors.append(Errors.ReferralWithSOABitNSEC(sname=fmt.humanize_name(self.qname)))
                    self.validation_status = NSEC_STATUS_INVALID
            else:
                if self.has_rdtype:
                    self.errors.append(Errors.StypeInBitmapNODATANSEC(sname=fmt.humanize_name(self.qname), stype=dns.rdatatype.to_text(self.rdtype)))
                    self.validation_status = NSEC_STATUS_INVALID
            if self.nsec_names_covering_qname:
                self.errors.append(Errors.SnameCoveredNODATANSEC(sname=fmt.humanize_name(self.qname)))
                self.validation_status = NSEC_STATUS_INVALID
        elif self.nsec_for_wildcard_name: # implies wildcard_name, which implies nsec_names_covering_qname
            if self.wildcard_has_rdtype:
                self.validation_status = NSEC_STATUS_INVALID
                self.errors.append(Errors.StypeInBitmapNODATANSEC(sname=fmt.humanize_name(self.wildcard_name), stype=dns.rdatatype.to_text(self.rdtype)))
            if self.nsec_names_covering_origin:
                self.validation_status = NSEC_STATUS_INVALID
                qname, nsec_names = list(self.nsec_names_covering_origin.items())[0]
                nsec_rrset = nsec_set_info.rrsets[list(nsec_names)[0]].rrset
                self.errors.append(Errors.LastNSECNextNotZone(nsec_owner=fmt.humanize_name(nsec_rrset.name), next_name=fmt.humanize_name(nsec_rrset[0].next), zone_name=fmt.humanize_name(self.origin)))
        else:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(Errors.NoNSECMatchingSnameNODATA(sname=fmt.humanize_name(self.qname)))

        # if it validation_status, we project out just the pertinent NSEC records
        # otherwise clone it by projecting them all
        if self.validation_status == NSEC_STATUS_VALID:
            covering_names = set()
            if self.nsec_for_qname is not None:
                covering_names.add(self.nsec_for_qname.rrset.name)
            if self.nsec_names_covering_qname:
                for names in self.nsec_names_covering_qname.values():
                    covering_names.update(names)
            if self.nsec_for_wildcard_name is not None:
                covering_names.add(self.wildcard_name)
            self.nsec_set_info = nsec_set_info.project(*list(covering_names))
        else:
            self.nsec_set_info = nsec_set_info.project(*list(nsec_set_info.rrsets))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG, html_format=False, map_ip_to_ns_name=None):
        d = OrderedDict()

        nsec_list = []
        for nsec_rrset in self.nsec_set_info.rrsets.values():
            if rrset_info_serializer is not None:
                nsec_serialized = rrset_info_serializer(nsec_rrset, consolidate_clients=consolidate_clients, show_servers=False, loglevel=loglevel, html_format=html_format)
                if nsec_serialized:
                    nsec_list.append(nsec_serialized)
            elif loglevel <= logging.DEBUG:
                nsec_list.append(nsec_rrset.serialize(consolidate_clients=consolidate_clients, html_format=html_format))

        erroneous_status = self.validation_status != STATUS_VALID

        show_id = loglevel <= logging.INFO or \
                (self.warnings and loglevel <= logging.WARNING) or \
                (self.errors and loglevel <= logging.ERROR) or \
                (erroneous_status or nsec_list)

        if html_format:
            formatter = lambda x: escape(x, True)
        else:
            formatter = lambda x: x

        if show_id:
            d['id'] = 'NSEC'

        if loglevel <= logging.DEBUG:
            d['description'] = formatter(str(self))

        if nsec_list:
            d['nsec'] = nsec_list

        if loglevel <= logging.DEBUG:
            if self.nsec_for_qname is not None:
                d['sname_nsec_match'] = formatter(lb2s(self.nsec_for_qname.rrset.name.canonicalize().to_text()))

            if self.nsec_names_covering_qname:
                qname, nsec_names = list(self.nsec_names_covering_qname.items())[0]
                nsec_name = list(nsec_names)[0]
                nsec_rr = self.nsec_set_info.rrsets[nsec_name].rrset[0]
                d['sname_covering'] = OrderedDict((
                    ('covered_name', formatter(lb2s(qname.canonicalize().to_text()))),
                    ('nsec_owner', formatter(lb2s(nsec_name.canonicalize().to_text()))),
                    ('nsec_next', formatter(lb2s(nsec_rr.next.canonicalize().to_text())))
                ))

                if self.nsec_for_wildcard_name is not None:
                    d['wildcard_nsec_match'] = formatter(lb2s(self.wildcard_name.canonicalize().to_text()))

        if loglevel <= logging.INFO or erroneous_status:
            d['status'] = nsec_status_mapping[self.validation_status]

        if loglevel <= logging.INFO:
            servers = tuple_to_dict(self.nsec_set_info.servers_clients)
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
            for server,client in self.nsec_set_info.servers_clients:
                for response in self.nsec_set_info.servers_clients[(server, client)]:
                    if response is not None:
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

class NSEC3Status(object):
    def __repr__(self):
        return '<%s: "%s">' % (self.__class__.__name__, self.qname)

    def _get_next_closest_encloser(self, encloser):
        return dns.name.Name(self.qname.labels[-(len(encloser)+1):])

    def get_next_closest_encloser(self):
        if self.closest_encloser:
            encloser_name, nsec_names = list(self.closest_encloser.items())[0]
            return self._get_next_closest_encloser(encloser_name)
        return None

    def _get_wildcard(self, encloser):
        return dns.name.from_text('*', encloser)

    def get_wildcard(self):
        if self.closest_encloser:
            encloser_name, nsec_names = list(self.closest_encloser.items())[0]
            return self._get_wildcard(encloser_name)
        return None

class NSEC3StatusNXDOMAIN(NSEC3Status):
    def __init__(self, qname, rdtype, origin, is_zone, nsec_set_info):
        self.qname = qname
        self.origin = origin
        self.is_zone = is_zone
        self.warnings = []
        self.errors = []

        self.name_digest_map = {}

        self._set_closest_encloser(nsec_set_info)

        self.nsec_names_covering_qname = {}
        self.nsec_names_covering_wildcard = {}
        self.opt_out = None

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

                if digest_name is not None:
                    covering_names = nsec_set_info.nsec3_covering_name(digest_name, salt, alg, iterations)
                    if covering_names:
                        self.nsec_names_covering_qname[digest_name] = covering_names
                        self.opt_out = False
                        for nsec_name in covering_names:
                            if nsec_set_info.rrsets[nsec_name].rrset[0].flags & 0x01:
                                self.opt_out = True

                if next_closest_encloser not in self.name_digest_map:
                    self.name_digest_map[next_closest_encloser] = {}
                self.name_digest_map[next_closest_encloser][(salt, alg, iterations)] = digest_name

                wildcard_name = self._get_wildcard(encloser)
                digest_name = nsec_set_info.get_digest_name_for_nsec3(wildcard_name, self.origin, salt, alg, iterations)

                if digest_name is not None:
                    covering_names = nsec_set_info.nsec3_covering_name(digest_name, salt, alg, iterations)
                    if covering_names:
                        self.nsec_names_covering_wildcard[digest_name] = covering_names

                if wildcard_name not in self.name_digest_map:
                    self.name_digest_map[wildcard_name] = {}
                self.name_digest_map[wildcard_name][(salt, alg, iterations)] = digest_name

        self._set_validation_status(nsec_set_info)

    def __str__(self):
        return 'NSEC3 record(s) proving the non-existence (NXDOMAIN) of %s' % (fmt.humanize_name(self.qname))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                self.qname == other.qname and self.origin == other.origin and self.nsec_set_info == other.nsec_set_info

    def __hash__(self):
        return hash(id(self))

    def _set_closest_encloser(self, nsec_set_info):
        self.closest_encloser = nsec_set_info.get_closest_encloser(self.qname, self.origin)

    def _set_validation_status(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        valid_algs, invalid_algs = nsec_set_info.get_algorithm_support()
        if invalid_algs:
            invalid_alg_err = Errors.UnsupportedNSEC3Algorithm(algorithm=list(invalid_algs)[0])
        else:
            invalid_alg_err = None
        if not self.closest_encloser:
            self.validation_status = NSEC_STATUS_INVALID
            if valid_algs:
                self.errors.append(Errors.NoClosestEncloserNameError(sname=fmt.humanize_name(self.qname)))
            if invalid_algs:
                self.errors.append(invalid_alg_err)
        else:
            if not self.nsec_names_covering_qname:
                self.validation_status = NSEC_STATUS_INVALID
                if valid_algs:
                    next_closest_encloser = self.get_next_closest_encloser()
                    self.errors.append(Errors.NextClosestEncloserNotCoveredNameError(next_closest_encloser=fmt.humanize_name(next_closest_encloser)))
                if invalid_algs:
                    self.errors.append(invalid_alg_err)
            if not self.nsec_names_covering_wildcard:
                self.validation_status = NSEC_STATUS_INVALID
                if valid_algs:
                    wildcard_name = self.get_wildcard()
                    self.errors.append(Errors.WildcardNotCoveredNSEC3(wildcard=fmt.humanize_name(wildcard_name)))
                if invalid_algs and invalid_alg_err not in self.errors:
                    self.errors.append(invalid_alg_err)

        # if it validation_status, we project out just the pertinent NSEC records
        # otherwise clone it by projecting them all
        if self.validation_status == NSEC_STATUS_VALID:
            covering_names = set()
            for names in list(self.closest_encloser.values()) + list(self.nsec_names_covering_qname.values()) + list(self.nsec_names_covering_wildcard.values()):
                covering_names.update(names)
            self.nsec_set_info = nsec_set_info.project(*list(covering_names))
        else:
            self.nsec_set_info = nsec_set_info.project(*list(nsec_set_info.rrsets))

        # Report errors with NSEC3 owner names
        for name in self.nsec_set_info.invalid_nsec3_owner:
            self.errors.append(Errors.InvalidNSEC3OwnerName(name=fmt.format_nsec3_name(name)))
        for name in self.nsec_set_info.invalid_nsec3_hash:
            self.errors.append(Errors.InvalidNSEC3Hash(name=fmt.format_nsec3_name(name), nsec3_hash=lb2s(base32.b32encode(self.nsec_set_info.rrsets[name].rrset[0].next))))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG, html_format=False, map_ip_to_ns_name=None):
        d = OrderedDict()

        nsec3_list = []
        for nsec_rrset in self.nsec_set_info.rrsets.values():
            if rrset_info_serializer is not None:
                nsec_serialized = rrset_info_serializer(nsec_rrset, consolidate_clients=consolidate_clients, show_servers=False, loglevel=loglevel, html_format=html_format)
                if nsec_serialized:
                    nsec3_list.append(nsec_serialized)
            elif loglevel <= logging.DEBUG:
                nsec3_list.append(nsec_rrset.serialize(consolidate_clients=consolidate_clients, html_format=html_format))

        erroneous_status = self.validation_status != STATUS_VALID

        show_id = loglevel <= logging.INFO or \
                (self.warnings and loglevel <= logging.WARNING) or \
                (self.errors and loglevel <= logging.ERROR) or \
                (erroneous_status or nsec3_list)

        if html_format:
            formatter = lambda x: escape(x, True)
        else:
            formatter = lambda x: x

        if show_id:
            d['id'] = 'NSEC3'

        if loglevel <= logging.DEBUG:
            d['description'] = formatter(str(self))

        if nsec3_list:
            d['nsec3'] = nsec3_list

        if loglevel <= logging.DEBUG:
            if self.opt_out is not None:
                d['opt_out'] = self.opt_out

            if self.closest_encloser:
                encloser_name, nsec_names = list(self.closest_encloser.items())[0]
                nsec_name = list(nsec_names)[0]
                d['closest_encloser'] = formatter(lb2s(encloser_name.canonicalize().to_text()))
                # could be inferred from wildcard
                if nsec_name is not None:
                    d['closest_encloser_hash'] = formatter(fmt.format_nsec3_name(nsec_name))

                next_closest_encloser = self._get_next_closest_encloser(encloser_name)
                d['next_closest_encloser'] = formatter(lb2s(next_closest_encloser.canonicalize().to_text()))
                digest_name = list(self.name_digest_map[next_closest_encloser].items())[0][1]
                if digest_name is not None:
                    d['next_closest_encloser_hash'] = formatter(fmt.format_nsec3_name(digest_name))
                else:
                    d['next_closest_encloser_hash'] = None

                if self.nsec_names_covering_qname:
                    qname, nsec_names = list(self.nsec_names_covering_qname.items())[0]
                    nsec_name = list(nsec_names)[0]
                    next_name = self.nsec_set_info.name_for_nsec3_next(nsec_name)
                    d['next_closest_encloser_covering'] = OrderedDict((
                        ('covered_name', formatter(fmt.format_nsec3_name(qname))),
                        ('nsec_owner', formatter(fmt.format_nsec3_name(nsec_name))),
                        ('nsec_next', formatter(fmt.format_nsec3_name(next_name))),
                    ))

                wildcard_name = self._get_wildcard(encloser_name)
                wildcard_digest = list(self.name_digest_map[wildcard_name].items())[0][1]
                d['wildcard'] = formatter(lb2s(wildcard_name.canonicalize().to_text()))
                if wildcard_digest is not None:
                    d['wildcard_hash'] = formatter(fmt.format_nsec3_name(wildcard_digest))
                else:
                    d['wildcard_hash'] = None
                if self.nsec_names_covering_wildcard:
                    wildcard, nsec_names = list(self.nsec_names_covering_wildcard.items())[0]
                    nsec_name = list(nsec_names)[0]
                    next_name = self.nsec_set_info.name_for_nsec3_next(nsec_name)
                    d['wildcard_covering'] = OrderedDict((
                        ('covered_name', formatter(fmt.format_nsec3_name(wildcard))),
                        ('nsec3_owner', formatter(fmt.format_nsec3_name(nsec_name))),
                        ('nsec3_next', formatter(fmt.format_nsec3_name(next_name))),
                    ))

            else:
                digest_name = list(self.name_digest_map[self.qname].items())[0][1]
                if digest_name is not None:
                    d['sname_hash'] = formatter(fmt.format_nsec3_name(digest_name))
                else:
                    d['sname_hash'] = None

        if loglevel <= logging.INFO or erroneous_status:
            d['status'] = nsec_status_mapping[self.validation_status]

        if loglevel <= logging.INFO:
            servers = tuple_to_dict(self.nsec_set_info.servers_clients)
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
            for server,client in self.nsec_set_info.servers_clients:
                for response in self.nsec_set_info.servers_clients[(server, client)]:
                    if response is not None:
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

class NSEC3StatusWildcard(NSEC3StatusNXDOMAIN):
    def __init__(self, qname, wildcard_name, rdtype, origin, is_zone, nsec_set_info):
        self.wildcard_name = wildcard_name
        super(NSEC3StatusWildcard, self).__init__(qname, rdtype, origin, is_zone, nsec_set_info)

    def _set_closest_encloser(self, nsec_set_info):
        super(NSEC3StatusWildcard, self)._set_closest_encloser(nsec_set_info)

        if not self.closest_encloser:
            self.closest_encloser = { self.wildcard_name.parent(): set([None]) }
            # fill in a dummy value for wildcard_name_digest_map
            self.name_digest_map[self.wildcard_name] = { None: self.wildcard_name }

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                super(NSEC3StatusWildcard, self).__eq__(other) and self.wildcard_name == other.wildcard_name

    def __hash__(self):
        return hash(id(self))

    def _set_validation_status(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        if not self.nsec_names_covering_qname:
            self.validation_status = NSEC_STATUS_INVALID
            valid_algs, invalid_algs = nsec_set_info.get_algorithm_support()
            if invalid_algs:
                invalid_alg_err = Errors.UnsupportedNSEC3Algorithm(algorithm=list(invalid_algs)[0])
            else:
                invalid_alg_err = None
            if valid_algs:
                next_closest_encloser = self.get_next_closest_encloser()
                self.errors.append(Errors.NextClosestEncloserNotCoveredWildcardAnswer(next_closest_encloser=fmt.humanize_name(next_closest_encloser)))
            if invalid_algs:
                self.errors.append(invalid_alg_err)

        if self.nsec_names_covering_wildcard:
            self.validation_status = NSEC_STATUS_INVALID
            self.errors.append(Errors.WildcardCoveredAnswerNSEC3(wildcard=fmt.humanize_name(self.wildcard_name)))

        # if it validation_status, we project out just the pertinent NSEC records
        # otherwise clone it by projecting them all
        if self.validation_status == NSEC_STATUS_VALID:
            covering_names = set()
            for names in list(self.closest_encloser.values()) + list(self.nsec_names_covering_qname.values()):
                covering_names.update(names)
            self.nsec_set_info = nsec_set_info.project(*[x for x in covering_names if x is not None])
        else:
            self.nsec_set_info = nsec_set_info.project(*list(nsec_set_info.rrsets))

        # Report errors with NSEC3 owner names
        for name in self.nsec_set_info.invalid_nsec3_owner:
            self.errors.append(Errors.InvalidNSEC3OwnerName(name=fmt.format_nsec3_name(name)))
        for name in self.nsec_set_info.invalid_nsec3_hash:
            self.errors.append(Errors.InvalidNSEC3Hash(name=fmt.format_nsec3_name(name), nsec3_hash=lb2s(base32.b32encode(self.nsec_set_info.rrsets[name].rrset[0].next))))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG, html_format=False, map_ip_to_ns_name=None):
        d = super(NSEC3StatusWildcard, self).serialize(rrset_info_serializer, consolidate_clients=consolidate_clients, loglevel=loglevel, html_format=html_format, map_ip_to_ns_name=map_ip_to_ns_name)
        try:
            del d['wildcard']
        except KeyError:
            pass
        try:
            del d['wildcard_digest']
        except KeyError:
            pass
        if loglevel <= logging.DEBUG:
            if [x for x in list(self.closest_encloser.values())[0] if x is not None]:
                d['superfluous_closest_encloser'] = True
        return d

class NSEC3StatusNODATA(NSEC3Status):
    def __init__(self, qname, rdtype, origin, is_zone, nsec_set_info):
        self.qname = qname
        self.rdtype = rdtype
        self.origin = origin
        self.is_zone = is_zone
        self.referral = nsec_set_info.referral
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
        self.opt_out = None
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

                    if digest_name is not None:
                        covering_names = nsec_set_info.nsec3_covering_name(digest_name, salt, alg, iterations)
                        if covering_names:
                            self.nsec_names_covering_qname[digest_name] = covering_names
                            self.opt_out = False
                            for nsec_name in covering_names:
                                if nsec_set_info.rrsets[nsec_name].rrset[0].flags & 0x01:
                                    self.opt_out = True

        self._set_validation_status(nsec_set_info)

    def __str__(self):
        return 'NSEC3 record(s) proving non-existence (NODATA) of %s/%s' % (fmt.humanize_name(self.qname), dns.rdatatype.to_text(self.rdtype))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
                self.qname == other.qname and self.rdtype == other.rdtype and self.origin == other.origin and self.referral == other.referral and self.nsec_set_info == other.nsec_set_info

    def __hash__(self):
        return hash(id(self))

    def _set_validation_status(self, nsec_set_info):
        self.validation_status = NSEC_STATUS_VALID
        valid_algs, invalid_algs = nsec_set_info.get_algorithm_support()
        if invalid_algs:
            invalid_alg_err = Errors.UnsupportedNSEC3Algorithm(algorithm=list(invalid_algs)[0])
        else:
            invalid_alg_err = None
        if self.nsec_for_qname:
            # RFC 4035 5.2, 6840 4.4
            if self.rdtype == dns.rdatatype.DS or self.referral:
                if self.is_zone and not self.has_ns:
                    self.errors.append(Errors.ReferralWithoutNSBitNSEC3(sname=fmt.humanize_name(self.qname)))
                    self.validation_status = NSEC_STATUS_INVALID
                if self.has_ds:
                    self.errors.append(Errors.ReferralWithDSBitNSEC3(sname=fmt.humanize_name(self.qname)))
                    self.validation_status = NSEC_STATUS_INVALID
                if self.has_soa:
                    self.errors.append(Errors.ReferralWithSOABitNSEC3(sname=fmt.humanize_name(self.qname)))
                    self.validation_status = NSEC_STATUS_INVALID
            # RFC 5155, section 8.5, 8.6
            else:
                if self.has_rdtype:
                    self.errors.append(Errors.StypeInBitmapNODATANSEC3(sname=fmt.humanize_name(self.qname), stype=dns.rdatatype.to_text(self.rdtype)))
                    self.validation_status = NSEC_STATUS_INVALID
                if self.has_cname:
                    self.errors.append(Errors.StypeInBitmapNODATANSEC3(sname=fmt.humanize_name(self.qname), stype=dns.rdatatype.to_text(dns.rdatatype.CNAME)))
                    self.validation_status = NSEC_STATUS_INVALID
        elif self.nsec_for_wildcard_name:
            if not self.nsec_names_covering_qname:
                self.validation_status = NSEC_STATUS_INVALID
                if valid_algs:
                    self.errors.append(Errors.NextClosestEncloserNotCoveredWildcardNODATA(next_closest_encloser=fmt.humanize_name(next_closest_encloser)))
                if invalid_algs:
                    self.errors.append(invalid_alg_err)
            if self.wildcard_has_rdtype:
                self.validation_status = NSEC_STATUS_INVALID
                self.errors.append(Errors.StypeInBitmapWildcardNODATANSEC3(sname=fmt.humanize_name(self.get_wildcard()), stype=dns.rdatatype.to_text(self.rdtype)))
        elif self.nsec_names_covering_qname:
            if not self.opt_out:
                self.validation_status = NSEC_STATUS_INVALID
                if valid_algs:
                    if self.rdtype == dns.rdatatype.DS:
                        cls = Errors.OptOutFlagNotSetNODATADS
                    else:
                        cls = Errors.OptOutFlagNotSetNODATA
                    next_closest_encloser = self.get_next_closest_encloser()
                    self.errors.append(cls(next_closest_encloser=fmt.humanize_name(next_closest_encloser)))
                if invalid_algs:
                    self.errors.append(invalid_alg_err)
        else:
            self.validation_status = NSEC_STATUS_INVALID
            if valid_algs:
                if self.rdtype == dns.rdatatype.DS:
                    cls = Errors.NoNSEC3MatchingSnameDSNODATA
                else:
                    cls = Errors.NoNSEC3MatchingSnameNODATA
                self.errors.append(cls(sname=fmt.humanize_name(self.qname)))
            if invalid_algs:
                self.errors.append(invalid_alg_err)

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

        # Report errors with NSEC3 owner names
        for name in self.nsec_set_info.invalid_nsec3_owner:
            self.errors.append(Errors.InvalidNSEC3OwnerName(name=fmt.format_nsec3_name(name)))
        for name in self.nsec_set_info.invalid_nsec3_hash:
            self.errors.append(Errors.InvalidNSEC3Hash(name=fmt.format_nsec3_name(name), nsec3_hash=lb2s(base32.b32encode(self.nsec_set_info.rrsets[name].rrset[0].next))))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG, html_format=False, map_ip_to_ns_name=None):
        d = OrderedDict()

        nsec3_list = []
        for nsec_rrset in self.nsec_set_info.rrsets.values():
            if rrset_info_serializer is not None:
                nsec_serialized = rrset_info_serializer(nsec_rrset, consolidate_clients=consolidate_clients, show_servers=False, loglevel=loglevel, html_format=html_format)
                if nsec_serialized:
                    nsec3_list.append(nsec_serialized)
            elif loglevel <= logging.DEBUG:
                nsec3_list.append(nsec_rrset.serialize(consolidate_clients=consolidate_clients, html_format=html_format))

        erroneous_status = self.validation_status != STATUS_VALID

        show_id = loglevel <= logging.INFO or \
                (self.warnings and loglevel <= logging.WARNING) or \
                (self.errors and loglevel <= logging.ERROR) or \
                (erroneous_status or nsec3_list)

        if html_format:
            formatter = lambda x: escape(x, True)
        else:
            formatter = lambda x: x

        if show_id:
            d['id'] = 'NSEC3'

        if loglevel <= logging.DEBUG:
            d['description'] = formatter(str(self))

        if nsec3_list:
            d['nsec3'] = nsec3_list

        if loglevel <= logging.DEBUG:
            if self.opt_out is not None:
                d['opt_out'] = self.opt_out

            if self.nsec_for_qname:
                digest_name = list(self.name_digest_map[self.qname].items())[0][1]
                if digest_name is not None:
                    d['sname_hash'] = formatter(fmt.format_nsec3_name(digest_name))
                else:
                    d['sname_hash'] = None
                d['sname_nsec_match'] = formatter(fmt.format_nsec3_name(list(self.nsec_for_qname)[0]))

            if self.closest_encloser:
                encloser_name, nsec_names = list(self.closest_encloser.items())[0]
                nsec_name = list(nsec_names)[0]
                d['closest_encloser'] = formatter(lb2s(encloser_name.canonicalize().to_text()))
                d['closest_encloser_digest'] = formatter(fmt.format_nsec3_name(nsec_name))

                next_closest_encloser = self._get_next_closest_encloser(encloser_name)
                d['next_closest_encloser'] = formatter(lb2s(next_closest_encloser.canonicalize().to_text()))
                digest_name = list(self.name_digest_map[next_closest_encloser].items())[0][1]
                if digest_name is not None:
                    d['next_closest_encloser_hash'] = formatter(fmt.format_nsec3_name(digest_name))
                else:
                    d['next_closest_encloser_hash'] = None

                if self.nsec_names_covering_qname:
                    qname, nsec_names = list(self.nsec_names_covering_qname.items())[0]
                    nsec_name = list(nsec_names)[0]
                    next_name = self.nsec_set_info.name_for_nsec3_next(nsec_name)
                    d['next_closest_encloser_covering'] = OrderedDict((
                        ('covered_name', formatter(fmt.format_nsec3_name(qname))),
                        ('nsec3_owner', formatter(fmt.format_nsec3_name(nsec_name))),
                        ('nsec3_next', formatter(fmt.format_nsec3_name(next_name))),
                    ))

                wildcard_name = self._get_wildcard(encloser_name)
                wildcard_digest = list(self.name_digest_map[wildcard_name].items())[0][1]
                d['wildcard'] = formatter(lb2s(wildcard_name.canonicalize().to_text()))
                if wildcard_digest is not None:
                    d['wildcard_hash'] = formatter(fmt.format_nsec3_name(wildcard_digest))
                else:
                    d['wildcard_hash'] = None
                if self.nsec_for_wildcard_name:
                    d['wildcard_nsec_match'] = formatter(fmt.format_nsec3_name(list(self.nsec_for_wildcard_name)[0]))

            if not self.nsec_for_qname and not self.closest_encloser:
                digest_name = list(self.name_digest_map[self.qname].items())[0][1]
                if digest_name is not None:
                    d['sname_hash'] = formatter(fmt.format_nsec3_name(digest_name))
                else:
                    d['sname_hash'] = None

        if loglevel <= logging.INFO or erroneous_status:
            d['status'] = nsec_status_mapping[self.validation_status]

        if loglevel <= logging.INFO:
            servers = tuple_to_dict(self.nsec_set_info.servers_clients)
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
            for server,client in self.nsec_set_info.servers_clients:
                for response in self.nsec_set_info.servers_clients[(server, client)]:
                    if response is not None:
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

class CNAMEFromDNAMEStatus(object):
    def __init__(self, synthesized_cname, included_cname):
        self.synthesized_cname = synthesized_cname
        self.included_cname = included_cname
        self.warnings = []
        self.errors = []

        if self.included_cname is None:
            self.validation_status = DNAME_STATUS_INVALID
            self.errors.append(Errors.DNAMENoCNAME())
        else:
            self.validation_status = DNAME_STATUS_VALID
            if self.included_cname.rrset[0].target != self.synthesized_cname.rrset[0].target:
                self.errors.append(Errors.DNAMETargetMismatch(included_target=fmt.humanize_name(self.included_cname.rrset[0].target), synthesized_target=fmt.humanize_name(self.synthesized_cname.rrset[0].target)))
                self.validation_status = DNAME_STATUS_INVALID_TARGET
            if self.included_cname.rrset.ttl != self.synthesized_cname.rrset.ttl:
                if self.included_cname.rrset.ttl == 0:
                    self.warnings.append(Errors.DNAMETTLZero())
                else:
                    self.warnings.append(Errors.DNAMETTLMismatch(cname_ttl=self.included_cname.rrset.ttl, dname_ttl=self.synthesized_cname.rrset.ttl))

    def __str__(self):
        return 'CNAME synthesis for %s from %s/%s' % (fmt.humanize_name(self.synthesized_cname.rrset.name), fmt.humanize_name(self.synthesized_cname.dname_info.rrset.name), dns.rdatatype.to_text(self.synthesized_cname.dname_info.rrset.rdtype))

    def serialize(self, rrset_info_serializer=None, consolidate_clients=True, loglevel=logging.DEBUG, html_format=False, map_ip_to_ns_name=None):
        values = []
        d = OrderedDict()

        dname_serialized = None
        if rrset_info_serializer is not None:
            dname_serialized = rrset_info_serializer(self.synthesized_cname.dname_info, consolidate_clients=consolidate_clients, show_servers=False, loglevel=loglevel, html_format=html_format)
        elif loglevel <= logging.DEBUG:
            dname_serialized = self.synthesized_cname.dname_info.serialize(consolidate_clients=consolidate_clients, html_format=html_format)

        erroneous_status = self.validation_status != STATUS_VALID

        show_id = loglevel <= logging.INFO or \
                (self.warnings and loglevel <= logging.WARNING) or \
                (self.errors and loglevel <= logging.ERROR) or \
                (erroneous_status or dname_serialized)

        if html_format:
            formatter = lambda x: escape(x, True)
        else:
            formatter = lambda x: x

        if show_id:
            d['id'] = lb2s(self.synthesized_cname.dname_info.rrset.name.canonicalize().to_text())

        if loglevel <= logging.DEBUG:
            d['description'] = formatter(str(self))

        if dname_serialized:
            d['dname'] = dname_serialized

        if loglevel <= logging.DEBUG:
            if self.included_cname is not None:
                d['cname_owner'] = formatter(lb2s(self.included_cname.rrset.name.canonicalize().to_text()))
                d['cname_target'] = formatter(lb2s(self.included_cname.rrset[0].target.canonicalize().to_text()))

        if loglevel <= logging.INFO or erroneous_status:
            d['status'] = dname_status_mapping[self.validation_status]

        if loglevel <= logging.INFO:
            servers = tuple_to_dict(self.synthesized_cname.dname_info.servers_clients)
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
            for server,client in self.synthesized_cname.dname_info.servers_clients:
                for response in self.synthesized_cname.dname_info.servers_clients[(server, client)]:
                    if response is not None:
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
