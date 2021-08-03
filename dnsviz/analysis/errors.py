#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2015-2016 VeriSign, Inc.
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

import datetime

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

import dns.dnssec

import dnsviz.format as fmt
from dnsviz.util import tuple_to_dict

class DomainNameAnalysisError(object):
    _abstract = True
    code = None
    description_template = '%(code)s'
    terse_description_template = '%(code)s'
    references = []
    required_params = []
    use_effective_query_tag = True

    def __init__(self, **kwargs):
        if self._abstract:
            raise TypeError('Only subclasses may be instantiated.')

        self.template_kwargs = { 'code': self.code }
        self.servers_clients = {}
        for param in self.required_params:
            try:
                self.template_kwargs[param] = kwargs[param]
            except KeyError:
                raise TypeError('The "%s" keyword argument is required for instantiation.' % param)

    def __hash__(self):
        return id(self)

    def __str__(self):
        return self.code

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.args == other.args

    def copy(self):
        return self.__class__(**dict(list(zip(self.required_params, self.args))))

    @property
    def args(self):
        if not hasattr(self, '_args') or self._args is None:
            self._args = [self.template_kwargs[p] for p in self.required_params]
        return self._args

    @property
    def description(self):
        return self.description_template % self.template_kwargs

    @property
    def terse_description(self):
        return self.terse_description_template % self.template_kwargs

    @property
    def html_description(self):
        description_template_escaped = escape(self.description_template, True)
        template_kwargs_escaped = {}
        for n, v in self.template_kwargs.items():
            if isinstance(v, int):
                template_kwargs_escaped[n] = v
            else:
                if isinstance(v, str):
                    template_kwargs_escaped[n] = escape(v)
                else:
                    template_kwargs_escaped[n] = escape(str(v))
        return description_template_escaped % template_kwargs_escaped

    def add_server_client(self, server, client, response):
        if (server, client) not in self.servers_clients:
            self.servers_clients[(server, client)] = []
        if response not in self.servers_clients[(server, client)]:
            self.servers_clients[(server, client)].append(response)

    def remove_server_client(self, server, client, response):
        if (server, client) in self.servers_clients:
            try:
                self.servers_clients[(server, client)].remove(response)
            except ValueError:
                pass
            else:
                if not self.servers_clients[(server, client)]:
                    del self.servers_clients[(server, client)]

    def serialize(self, consolidate_clients=False, html_format=False):
        d = OrderedDict()

        if html_format:
            d['description'] = self.html_description
        else:
            d['description'] = self.description

        d['code'] = self.code
        if self.servers_clients:
            servers = tuple_to_dict(self.servers_clients)
            if consolidate_clients:
                servers = list(servers)
                servers.sort()
            d['servers'] = servers

            tags = set()
            for server,client in self.servers_clients:
                for response in self.servers_clients[(server,client)]:
                    # some errors are not in conjunction with responses, per
                    # se, only servers, in which case, the response value is
                    # None.
                    if response is not None:
                        if self.use_effective_query_tag:
                            tag = response.effective_query_tag()
                        else:
                            tag = response.initial_query_tag()
                        tags.add(tag)
            if tags:
                d['query_options'] = list(tags)
                d['query_options'].sort()

        return d

    @classmethod
    def insert_into_list(cls, error, error_list, server, client, response):
        try:
            index = error_list.index(error)
        except ValueError:
            error_list.append(error)
        else:
            error = error_list[index]
        if server is not None and client is not None:
            error.add_server_client(server, client, response)
        return error

class RRSIGError(DomainNameAnalysisError):
    pass

class SignerNotZone(RRSIGError):
    '''
    >>> e = SignerNotZone(zone_name='foo.', signer_name='bar.')
    >>> e.args
    ['foo.', 'bar.']
    >>> e.description
    "The Signer's Name field of the RRSIG RR (bar.) does not match the name of the zone containing the RRset (foo.)."
    '''

    _abstract = False
    code = 'SIGNER_NOT_ZONE'
    description_template = "The Signer's Name field of the RRSIG RR (%(signer_name)s) does not match the name of the zone containing the RRset (%(zone_name)s)."
    references = ['RFC 4035, Sec. 5.3.1']
    required_params = ['zone_name', 'signer_name']

class RRsetTTLMismatch(RRSIGError):
    '''
    >>> e = RRsetTTLMismatch(rrset_ttl=50, rrsig_ttl=10)
    >>> e.args
    [50, 10]
    >>> e.description
    'The TTL of the RRSIG RR (10) does not match the TTL of the RRset it covers (50).'
    '''

    _abstract = False
    code = 'RRSET_TTL_MISMATCH'
    description_template = 'The TTL of the RRSIG RR (%(rrsig_ttl)d) does not match the TTL of the RRset it covers (%(rrset_ttl)d).'
    references = ['RFC 4035, Sec. 2.2']
    required_params = ['rrset_ttl', 'rrsig_ttl']

class OriginalTTLExceeded(RRSIGError):
    '''
    >>> e = OriginalTTLExceeded(original_ttl=10, rrset_ttl=50)
    >>> e.args
    [10, 50]
    >>> e.description
    'The TTL of the RRset (50) exceeds the value of the Original TTL field of the RRSIG RR covering it (10).'
    '''

    _abstract = False
    code = 'ORIGINAL_TTL_EXCEEDED'
    description_template = 'The TTL of the RRset (%(rrset_ttl)d) exceeds the value of the Original TTL field of the RRSIG RR covering it (%(original_ttl)d).'
    references = ['RFC 4035, Sec. 2.2']
    required_params = ['original_ttl', 'rrset_ttl']

class TTLBeyondExpiration(RRSIGError):
    '''
    >>> e = TTLBeyondExpiration(expiration=datetime.datetime(2015,1,10), rrsig_ttl=86401, reference_time=datetime.datetime(2015,1,9))
    >>> e.args
    [datetime.datetime(2015, 1, 10, 0, 0), 86401, datetime.datetime(2015, 1, 9, 0, 0)]
    >>> e.description
    'With a TTL of 86401 the RRSIG RR can be in the cache of a non-validating resolver until 1 second after it expires at 2015-01-10 00:00:00.'
    '''

    _abstract = False
    code = 'TTL_BEYOND_EXPIRATION'
    description_template = "With a TTL of %(rrsig_ttl)d the RRSIG RR can be in the cache of a non-validating resolver until %(difference)s after it expires at %(expiration)s."
    references = ['RFC 4035, Sec. 5.3.3']
    required_params = ['expiration', 'rrsig_ttl', 'reference_time']

    def __init__(self, **kwargs):
        super(TTLBeyondExpiration, self).__init__(**kwargs)
        diff = self.template_kwargs['reference_time'] + datetime.timedelta(seconds=self.template_kwargs['rrsig_ttl']) - self.template_kwargs['expiration']
        self.template_kwargs['difference'] = fmt.humanize_time(diff.seconds, diff.days)

class AlgorithmNotSupported(RRSIGError):
    '''
    >>> e = AlgorithmNotSupported(algorithm=5)
    >>> e.args
    [5]
    >>> e.description
    'Validation of DNSSEC algorithm 5 (RSASHA1) is not supported by this code, so the cryptographic status of this RRSIG is unknown.'
    '''

    _abstract = False
    code = 'ALGORITHM_NOT_SUPPORTED'
    description_template = "Validation of DNSSEC algorithm %(algorithm)d (%(algorithm_text)s) is not supported by this code, so the cryptographic status of this RRSIG is unknown."
    references = ['RFC 4035, Sec. 5.2']
    required_params = ['algorithm']

    def __init__(self, **kwargs):
        super(AlgorithmNotSupported, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = dns.dnssec.algorithm_to_text(self.template_kwargs['algorithm'])

class AlgorithmValidationProhibited(RRSIGError):
    '''
    >>> e = AlgorithmValidationProhibited(algorithm=5)
    >>> e.args
    [5]
    >>> e.description
    'DNSSEC specification prohibits validation of RRSIGs with DNSSEC algorithm 5 (RSASHA1).'
    '''

    _abstract = False
    code = 'ALGORITHM_VALIDATION_PROHIBITED'
    description_template = "DNSSEC specification prohibits validation of RRSIGs with DNSSEC algorithm %(algorithm)d (%(algorithm_text)s)."
    references = ['RFC 8624, Sec. 3.1']
    required_params = ['algorithm']

    def __init__(self, **kwargs):
        super(AlgorithmValidationProhibited, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = dns.dnssec.algorithm_to_text(self.template_kwargs['algorithm'])

class AlgorithmProhibited(RRSIGError):
    '''
    >>> e = AlgorithmProhibited(algorithm=5)
    >>> e.args
    [5]
    >>> e.description
    'DNSSEC specification prohibits signing with DNSSEC algorithm 5 (RSASHA1).'
    '''

    _abstract = False
    code = 'ALGORITHM_PROHIBITED'
    description_template = "DNSSEC specification prohibits signing with DNSSEC algorithm %(algorithm)d (%(algorithm_text)s)."
    references = ['RFC 8624, Sec. 3.1']
    required_params = ['algorithm']

    def __init__(self, **kwargs):
        super(AlgorithmProhibited, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = dns.dnssec.algorithm_to_text(self.template_kwargs['algorithm'])

class AlgorithmNotRecommended(RRSIGError):
    '''
    >>> e = AlgorithmNotRecommended(algorithm=5)
    >>> e.args
    [5]
    >>> e.description
    'DNSSEC specification recommends not signing with DNSSEC algorithm 5 (RSASHA1).'
    '''

    _abstract = False
    code = 'ALGORITHM_NOT_RECOMMENDED'
    description_template = "DNSSEC specification recommends not signing with DNSSEC algorithm %(algorithm)d (%(algorithm_text)s)."
    references = ['RFC 8624, Sec. 3.1']
    required_params = ['algorithm']

    def __init__(self, **kwargs):
        super(AlgorithmNotRecommended, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = dns.dnssec.algorithm_to_text(self.template_kwargs['algorithm'])

class DNSKEYRevokedRRSIG(RRSIGError):
    '''
    >>> e = DNSKEYRevokedRRSIG()
    >>> e.description
    'The DNSKEY RR corresponding to the RRSIG RR has the REVOKE bit set.  A revoked key cannot be used to validate RRSIGs.'
    '''

    _abstract = False
    code = 'DNSKEY_REVOKED_RRSIG'
    description_template = "The DNSKEY RR corresponding to the RRSIG RR has the REVOKE bit set.  A revoked key cannot be used to validate RRSIGs."
    references = ['RFC 5011, Sec. 2.1']
    required_params = []

class InceptionInFuture(RRSIGError):
    '''
    >>> e = InceptionInFuture(inception=datetime.datetime(2015,1,10), reference_time=datetime.datetime(2015,1,9))
    >>> e.args
    [datetime.datetime(2015, 1, 10, 0, 0), datetime.datetime(2015, 1, 9, 0, 0)]
    >>> e.description
    'The Signature Inception field of the RRSIG RR (2015-01-10 00:00:00) is 1 day in the future.'
    '''

    _abstract = False
    code = 'INCEPTION_IN_FUTURE'
    description_template = "The Signature Inception field of the RRSIG RR (%(inception)s) is %(premature_time)s in the future."
    references = ['RFC 4035, Sec. 5.3.1']
    required_params = ['inception', 'reference_time']

    def __init__(self, **kwargs):
        super(InceptionInFuture, self).__init__(**kwargs)
        diff = self.template_kwargs['inception'] - self.template_kwargs['reference_time']
        self.template_kwargs['premature_time'] = fmt.humanize_time(diff.seconds, diff.days)

class ExpirationInPast(RRSIGError):
    '''
    >>> e = ExpirationInPast(expiration=datetime.datetime(2015,1,10), reference_time=datetime.datetime(2015,1,11))
    >>> e.args
    [datetime.datetime(2015, 1, 10, 0, 0), datetime.datetime(2015, 1, 11, 0, 0)]
    >>> e.description
    'The Signature Expiration field of the RRSIG RR (2015-01-10 00:00:00) is 1 day in the past.'
    '''

    _abstract = False
    code = 'EXPIRATION_IN_PAST'
    description_template = "The Signature Expiration field of the RRSIG RR (%(expiration)s) is %(expired_time)s in the past."
    references = ['RFC 4035, Sec. 5.3.1']
    required_params = ['expiration', 'reference_time']

    def __init__(self, **kwargs):
        super(ExpirationInPast, self).__init__(**kwargs)
        diff = self.template_kwargs['reference_time'] - self.template_kwargs['expiration']
        self.template_kwargs['expired_time'] = fmt.humanize_time(diff.seconds, diff.days)

class InceptionWithinClockSkew(RRSIGError):
    '''
    >>> e = InceptionWithinClockSkew(inception=datetime.datetime(2015,1,10,0,0,0), reference_time=datetime.datetime(2015,1,10,0,0,1))
    >>> e.description
    'The value of the Signature Inception field of the RRSIG RR (2015-01-10 00:00:00) is within possible clock skew range (1 second) of the current time (2015-01-10 00:00:01).'
    '''

    _abstract = False
    code = 'INCEPTION_WITHIN_CLOCK_SKEW'
    description_template = "The value of the Signature Inception field of the RRSIG RR (%(inception)s) is within possible clock skew range (%(difference)s) of the current time (%(reference_time)s)."
    references = ['RFC 4035, Sec. 5.3.1']
    required_params = ['inception', 'reference_time']

    def __init__(self, **kwargs):
        super(InceptionWithinClockSkew, self).__init__(**kwargs)
        diff = self.template_kwargs['reference_time'] - self.template_kwargs['inception']
        self.template_kwargs['difference'] = fmt.humanize_time(diff.seconds, diff.days)

class ExpirationWithinClockSkew(RRSIGError):
    '''
    >>> e = ExpirationWithinClockSkew(expiration=datetime.datetime(2015,1,10,0,0,1), reference_time=datetime.datetime(2015,1,10,0,0,0))
    >>> e.description
    'The value of the Signature Expiration field of the RRSIG RR (2015-01-10 00:00:01) is within possible clock skew range (1 second) of the current time (2015-01-10 00:00:00).'
    '''

    _abstract = False
    code = 'EXPIRATION_WITHIN_CLOCK_SKEW'
    description_template = "The value of the Signature Expiration field of the RRSIG RR (%(expiration)s) is within possible clock skew range (%(difference)s) of the current time (%(reference_time)s)."
    references = ['RFC 4035, Sec. 5.3.1']
    required_params = ['expiration', 'reference_time']

    def __init__(self, **kwargs):
        super(ExpirationWithinClockSkew, self).__init__(**kwargs)
        diff = self.template_kwargs['expiration'] - self.template_kwargs['reference_time']
        self.template_kwargs['difference'] = fmt.humanize_time(diff.seconds, diff.days)

class SignatureInvalid(RRSIGError):
    '''
    >>> e = SignatureInvalid()
    >>> e.description
    'The cryptographic signature of the RRSIG RR does not properly validate.'
    '''

    _abstract = False
    code = 'SIGNATURE_INVALID'
    description_template = "The cryptographic signature of the RRSIG RR does not properly validate."
    references = ['RFC 4035, Sec. 5.3.3']
    required_params = []

class RRSIGBadLength(RRSIGError):
    pass

class RRSIGBadLengthGOST(RRSIGBadLength):
    '''
    >>> e = RRSIGBadLengthGOST(length=500)
    >>> e.description
    'The length of the signature is 500 bits, but a GOST signature (DNSSEC algorithm 12) must be 512 bits long.'
    '''
    _abstract = False
    description_template = 'The length of the signature is %(length)d bits, but a GOST signature (DNSSEC algorithm 12) must be 512 bits long.'
    code = 'RRSIG_BAD_LENGTH_GOST'
    references = ['RFC 5933, Sec. 5.2']
    required_params = ['length']

class RRSIGBadLengthECDSA(RRSIGBadLength):
    curve = None
    algorithm = None
    correct_length = None
    description_template = 'The length of the signature is %(length)d bits, but an ECDSA signature made with Curve %(curve)s (DNSSEC algorithm %(algorithm)d) must be %(correct_length)d bits long.'
    references = ['RFC 6605, Sec. 4']
    required_params = ['length']

    def __init__(self, **kwargs):
        super(RRSIGBadLengthECDSA, self).__init__(**kwargs)
        self.template_kwargs['curve'] = self.curve
        self.template_kwargs['algorithm'] = self.algorithm
        self.template_kwargs['correct_length'] = self.correct_length

class RRSIGBadLengthECDSA256(RRSIGBadLengthECDSA):
    '''
    >>> e = RRSIGBadLengthECDSA256(length=500)
    >>> e.description
    'The length of the signature is 500 bits, but an ECDSA signature made with Curve P-256 (DNSSEC algorithm 13) must be 512 bits long.'
    '''
    curve = 'P-256'
    algorithm = 13
    correct_length = 512
    _abstract = False
    code = 'RRSIG_BAD_LENGTH_ECDSA256'

class RRSIGBadLengthECDSA384(RRSIGBadLengthECDSA):
    '''
    >>> e = RRSIGBadLengthECDSA384(length=500)
    >>> e.description
    'The length of the signature is 500 bits, but an ECDSA signature made with Curve P-384 (DNSSEC algorithm 14) must be 768 bits long.'
    '''
    curve = 'P-384'
    algorithm = 14
    correct_length = 768
    _abstract = False
    code = 'RRSIG_BAD_LENGTH_ECDSA384'

class RRSIGBadLengthEdDSA(RRSIGBadLength):
    curve = None
    algorithm = None
    correct_length = None
    description_template = 'The length of the signature is %(length)d bits, but an %(curve)s signature (DNSSEC algorithm %(algorithm)d) must be %(correct_length)d bits long.'
    references = ['RFC 8080, Sec. 4']
    required_params = ['length']

    def __init__(self, **kwargs):
        super(RRSIGBadLengthEdDSA, self).__init__(**kwargs)
        self.template_kwargs['curve'] = self.curve
        self.template_kwargs['algorithm'] = self.algorithm
        self.template_kwargs['correct_length'] = self.correct_length

class RRSIGBadLengthEd25519(RRSIGBadLengthEdDSA):
    '''
    >>> e = RRSIGBadLengthEd25519(length=500)
    >>> e.description
    'The length of the signature is 500 bits, but an Ed25519 signature (DNSSEC algorithm 15) must be 512 bits long.'
    '''
    curve = 'Ed25519'
    algorithm = 15
    correct_length = 512
    _abstract = False
    code = 'RRSIG_BAD_LENGTH_ED25519'

class RRSIGBadLengthEd448(RRSIGBadLengthEdDSA):
    '''
    >>> e = RRSIGBadLengthEd448(length=500)
    >>> e.description
    'The length of the signature is 500 bits, but an Ed448 signature (DNSSEC algorithm 16) must be 912 bits long.'
    '''
    curve = 'Ed448'
    algorithm = 16
    correct_length = 912
    _abstract = False
    code = 'RRSIG_BAD_LENGTH_ED448'

class DSError(DomainNameAnalysisError):
    pass

class ReferralForDSQuery(DSError):
    '''
    >>> e = ReferralForDSQuery(parent='baz.')
    >>> e.description
    'The server(s) for the parent zone (baz.) responded with a referral instead of answering authoritatively for the DS RR type.'
    '''
    _abstract = False
    code = 'REFERRAL_FOR_DS_QUERY'
    description_template = 'The server(s) for the parent zone (%(parent)s) responded with a referral instead of answering authoritatively for the DS RR type.'
    references = ['RFC 4034, Sec. 5']
    required_params = ['parent']

class DSDigestAlgorithmIgnored(DSError):
    '''
    >>> e = DSDigestAlgorithmIgnored(algorithm=1, new_algorithm=2)
    >>> e.description
    'DS records with digest type 1 (SHA-1) are ignored when DS records with digest type 2 (SHA-256) exist in the same RRset.'
    '''
    _abstract = False
    code = 'DS_DIGEST_ALGORITHM_IGNORED'
    description_template = "DS records with digest type %(algorithm)d (%(algorithm_text)s) are ignored when DS records with digest type %(new_algorithm)d (%(new_algorithm_text)s) exist in the same RRset."
    references = ['RFC 4509, Sec. 3']
    required_params = ['algorithm', 'new_algorithm']

    def __init__(self, **kwargs):
        super(DSDigestAlgorithmIgnored, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = fmt.DS_DIGEST_TYPES.get(self.template_kwargs['algorithm'], str(self.template_kwargs['algorithm']))
        self.template_kwargs['new_algorithm_text'] = fmt.DS_DIGEST_TYPES.get(self.template_kwargs['new_algorithm'], str(self.template_kwargs['algorithm']))

class DSDigestAlgorithmMaybeIgnored(DSError):
    '''
    >>> e = DSDigestAlgorithmMaybeIgnored(algorithm=1, new_algorithm=2)
    >>> e.description
    'In the spirit of RFC 4509, DS records with digest type 1 (SHA-1) might be ignored when DS records with digest type 2 (SHA-256) exist in the same RRset.'
    '''
    _abstract = False
    code = 'DS_DIGEST_ALGORITHM_MAYBE_IGNORED'
    description_template = "In the spirit of RFC 4509, DS records with digest type %(algorithm)d (%(algorithm_text)s) might be ignored when DS records with digest type %(new_algorithm)d (%(new_algorithm_text)s) exist in the same RRset."
    references = ['RFC 4509, Sec. 3']
    required_params = ['algorithm', 'new_algorithm']

    def __init__(self, **kwargs):
        super(DSDigestAlgorithmMaybeIgnored, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = fmt.DS_DIGEST_TYPES.get(self.template_kwargs['algorithm'], str(self.template_kwargs['algorithm']))
        self.template_kwargs['new_algorithm_text'] = fmt.DS_DIGEST_TYPES.get(self.template_kwargs['new_algorithm'], str(self.template_kwargs['algorithm']))

class DSDigestError(DSError):
    pass

class DigestAlgorithmNotSupported(DSDigestError):
    '''
    >>> e = DigestAlgorithmNotSupported(algorithm=5)
    >>> e.description
    'Generating cryptographic hashes using algorithm 5 (5) is not supported by this code, so the cryptographic status of the DS RR is unknown.'
    '''

    _abstract = False
    code = 'DIGEST_ALGORITHM_NOT_SUPPORTED'
    description_template = "Generating cryptographic hashes using algorithm %(algorithm)d (%(algorithm_text)s) is not supported by this code, so the cryptographic status of the DS RR is unknown."
    references = ['RFC 4035, Sec. 5.2']
    required_params = ['algorithm']

    def __init__(self, **kwargs):
        super(DigestAlgorithmNotSupported, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = fmt.DS_DIGEST_TYPES.get(self.template_kwargs['algorithm'], self.template_kwargs['algorithm'])

class DigestAlgorithmValidationProhibited(DSDigestError):
    '''
    >>> e = DigestAlgorithmValidationProhibited(algorithm=5)
    >>> e.description
    'DNSSEC specification prohibits validation of DS records that use digest algorithm 5 (5).'
    '''

    _abstract = False
    code = 'DIGEST_ALGORITHM_VALIDATION_PROHIBITED'
    description_template = "DNSSEC specification prohibits validation of DS records that use digest algorithm %(algorithm)d (%(algorithm_text)s)."
    references = ['RFC 8624, Sec. 3.2']
    required_params = ['algorithm']

    def __init__(self, **kwargs):
        super(DigestAlgorithmValidationProhibited, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = fmt.DS_DIGEST_TYPES.get(self.template_kwargs['algorithm'], self.template_kwargs['algorithm'])

class DigestAlgorithmProhibited(DSDigestError):
    '''
    >>> e = DigestAlgorithmProhibited(algorithm=5)
    >>> e.description
    'DNSSEC specification prohibits signing with DS records that use digest algorithm 5 (5).'
    '''

    _abstract = False
    code = 'DIGEST_ALGORITHM_PROHIBITED'
    description_template = "DNSSEC specification prohibits signing with DS records that use digest algorithm %(algorithm)d (%(algorithm_text)s)."
    references = ['RFC 8624, Sec. 3.2']
    required_params = ['algorithm']

    def __init__(self, **kwargs):
        super(DigestAlgorithmProhibited, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = fmt.DS_DIGEST_TYPES.get(self.template_kwargs['algorithm'], self.template_kwargs['algorithm'])

class DigestAlgorithmNotRecommended(DSDigestError):
    '''
    >>> e = DigestAlgorithmNotRecommended(algorithm=5)
    >>> e.description
    'DNSSEC specification recommends not signing with DS records that use digest algorithm 5 (5).'
    '''

    _abstract = False
    code = 'DIGEST_ALGORITHM_NOT_RECOMMENDED'
    description_template = "DNSSEC specification recommends not signing with DS records that use digest algorithm %(algorithm)d (%(algorithm_text)s)."
    references = ['RFC 8624, Sec. 3.2']
    required_params = ['algorithm']

    def __init__(self, **kwargs):
        super(DigestAlgorithmNotRecommended, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = fmt.DS_DIGEST_TYPES.get(self.template_kwargs['algorithm'], self.template_kwargs['algorithm'])

class DNSKEYRevokedDS(DSDigestError):
    '''
    >>> e = DNSKEYRevokedDS()
    >>> e.description
    'The DNSKEY RR corresponding to the DS RR has the REVOKE bit set.  A revoked key cannot be used with DS records.'
    '''

    _abstract = False
    code = 'DNSKEY_REVOKED_DS'
    description_template = "The DNSKEY RR corresponding to the DS RR has the REVOKE bit set.  A revoked key cannot be used with DS records."
    references = ['RFC 5011, Sec. 2.1']
    required_params = []

class DigestInvalid(DSDigestError):
    '''
    >>> e = DigestInvalid()
    >>> e.description
    'The cryptographic hash in the Digest field of the DS RR does not match the computed value.'
    '''

    _abstract = False
    code = 'DIGEST_INVALID'
    description_template = "The cryptographic hash in the Digest field of the DS RR does not match the computed value."
    references = ['RFC 4035, Sec. 5.2']
    required_params = []

class NSECError(DomainNameAnalysisError):
    nsec_type = None

    def __init__(self, *args, **kwargs):
        super(NSECError, self).__init__(**kwargs)
        self.template_kwargs['nsec_type'] = self.nsec_type

class SnameNotCovered(NSECError):
    code = 'SNAME_NOT_COVERED'
    description_template = "No %(nsec_type)s RR covers the SNAME (%(sname)s)."
    required_params = ['sname']
    nsec_type = 'NSEC'

class SnameNotCoveredNameError(SnameNotCovered):
    '''
    >>> e = SnameNotCoveredNameError(sname='foo.baz.')
    >>> e.description
    'No NSEC RR covers the SNAME (foo.baz.).'
    '''

    _abstract = False
    references = ['RFC 4035, Sec. 3.1.3.2']

class SnameNotCoveredWildcardAnswer(SnameNotCovered):
    _abstract = False
    references = ['RFC 4035, Sec. 3.1.3.3']

class NextClosestEncloserNotCovered(NSECError):
    code = 'NEXT_CLOSEST_ENCLOSER_NOT_COVERED'
    description_template = "No %(nsec_type)s RR covers the next closest encloser (%(next_closest_encloser)s)."
    required_params = ['next_closest_encloser']
    nsec_type = 'NSEC3'

class NextClosestEncloserNotCoveredNameError(NextClosestEncloserNotCovered):
    '''
    >>> e = NextClosestEncloserNotCoveredNameError(next_closest_encloser='foo.baz.')
    >>> e.description
    'No NSEC3 RR covers the next closest encloser (foo.baz.).'
    '''

    _abstract = False
    references = ['RFC 5155, Sec. 8.4']

class NextClosestEncloserNotCoveredNODATADS(NextClosestEncloserNotCovered):
    _abstract = False
    references = ['RFC 5155, Sec. 8.6']

class NextClosestEncloserNotCoveredWildcardNODATA(NextClosestEncloserNotCovered):
    _abstract = False
    references = ['RFC 5155, Sec. 8.7']

class NextClosestEncloserNotCoveredWildcardAnswer(NextClosestEncloserNotCovered):
    _abstract = False
    references = ['RFC 5155, Sec. 8.8']

class WildcardNotCovered(NSECError):
    code = 'WILDCARD_NOT_COVERED'
    description_template = "No %(nsec_type)s RR covers the wildcard (%(wildcard)s)."
    required_params = ['wildcard']

class WildcardNotCoveredNSEC(WildcardNotCovered):
    '''
    >>> e = WildcardNotCoveredNSEC(wildcard='*.foo.baz.')
    >>> e.description
    'No NSEC RR covers the wildcard (*.foo.baz.).'
    '''

    _abstract = False
    references = ['RFC 4035, Sec. 3.1.3.2']
    nsec_type = 'NSEC'

class WildcardNotCoveredNSEC3(WildcardNotCovered):
    _abstract = False
    references = ['RFC 5155, Sec. 8.4']
    nsec_type = 'NSEC3'

class NoClosestEncloser(NSECError):
    code = 'NO_CLOSEST_ENCLOSER'
    description_template = "No %(nsec_type)s RR corresponds to the closest encloser of the SNAME (%(sname)s)."
    required_params = ['sname']
    nsec_type = 'NSEC3'

class NoClosestEncloserNameError(NoClosestEncloser):
    '''
    >>> e = NoClosestEncloserNameError(sname='foo.baz.')
    >>> e.description
    'No NSEC3 RR corresponds to the closest encloser of the SNAME (foo.baz.).'
    '''

    _abstract = False
    references = ['RFC 5155, Sec. 8.4']

class NoClosestEncloserNODATADS(NoClosestEncloser):
    _abstract = False
    references = ['RFC 5155, Sec. 8.6']

class NoClosestEncloserWildcardNODATA(NoClosestEncloser):
    _abstract = False
    references = ['RFC 5155, Sec. 8.7']

class NoClosestEncloserWildcardAnswer(NoClosestEncloser):
    _abstract = False
    references = ['RFC 5155, Sec. 8.8']

class OptOutFlagNotSet(NSECError):
    code = 'OPT_OUT_FLAG_NOT_SET'
    description_template = "The opt-out flag was not set in the %(nsec_type)s RR covering the next closest encloser (%(next_closest_encloser)s) but was required for the NODATA response."
    required_params = ['next_closest_encloser']
    nsec_type = 'NSEC3'

class OptOutFlagNotSetNODATA(OptOutFlagNotSet):
    '''
    >>> e = OptOutFlagNotSetNODATA(next_closest_encloser='foo.baz.')
    >>> e.description
    'The opt-out flag was not set in the NSEC3 RR covering the next closest encloser (foo.baz.) but was required for the NODATA response.'
    '''

    _abstract = False
    references = ['RFC 5155, Sec. 8.5', 'RFC Errata 3441']

class OptOutFlagNotSetNODATADS(OptOutFlagNotSet):
    _abstract = False
    references = ['RFC 5155, Sec. 8.6']

class ReferralWithSOABit(NSECError):
    code = 'REFERRAL_WITH_SOA'
    description_template = "The SOA bit was set in the bitmap of the %(nsec_type)s RR corresponding to the delegated name (%(sname)s)."
    required_params = ['sname']

class ReferralWithSOABitNSEC(ReferralWithSOABit):
    '''
    >>> e = ReferralWithSOABitNSEC(sname='foo.baz.')
    >>> e.description
    'The SOA bit was set in the bitmap of the NSEC RR corresponding to the delegated name (foo.baz.).'
    '''

    _abstract = False
    references = ['RFC 4034, Sec. 5.2']
    nsec_type = 'NSEC'

class ReferralWithSOABitNSEC3(ReferralWithSOABit):
    _abstract = False
    references = ['RFC 5155, Sec. 8.9']
    nsec_type = 'NSEC3'

class ReferralWithDSBit(NSECError):
    code = 'REFERRAL_WITH_DS'
    description_template = "The DS bit was set in the bitmap of the %(nsec_type)s RR corresponding to the delegated name (%(sname)s)."
    required_params = ['sname']

class ReferralWithDSBitNSEC(ReferralWithDSBit):
    '''
    >>> e = ReferralWithDSBitNSEC(sname='foo.baz.')
    >>> e.description
    'The DS bit was set in the bitmap of the NSEC RR corresponding to the delegated name (foo.baz.).'
    '''

    _abstract = False
    references = ['RFC 4034, Sec. 5.2']
    nsec_type = 'NSEC'

class ReferralWithDSBitNSEC3(ReferralWithDSBit):
    _abstract = False
    references = ['RFC 5155, Sec. 8.9']
    nsec_type = 'NSEC3'

class ReferralWithoutNSBit(NSECError):
    code = 'REFERRAL_WITHOUT_NS'
    description_template = "The NS bit was not set in the bitmap of the %(nsec_type)s RR corresponding to the delegated name (%(sname)s)."
    required_params = ['sname']

class ReferralWithoutNSBitNSEC(ReferralWithoutNSBit):
    '''
    >>> e = ReferralWithoutNSBitNSEC(sname='foo.baz.')
    >>> e.description
    'The NS bit was not set in the bitmap of the NSEC RR corresponding to the delegated name (foo.baz.).'
    '''

    _abstract = False
    references = ['RFC 6840, Sec. 4.4']
    nsec_type = 'NSEC'

class ReferralWithoutNSBitNSEC3(ReferralWithoutNSBit):
    _abstract = False
    references = ['RFC 5155, Sec. 8.9']
    nsec_type = 'NSEC3'

class StypeInBitmap(NSECError):
    code = 'STYPE_IN_BITMAP'
    description_template = "The %(stype)s bit was set in the bitmap of the %(nsec_type)s RR corresponding to the SNAME (%(sname)s)."
    required_params = ['stype', 'sname']

class StypeInBitmapNODATA(StypeInBitmap):
    pass

class StypeInBitmapNODATANSEC(StypeInBitmapNODATA):
    '''
    >>> e = StypeInBitmapNODATANSEC(stype='A', sname='foo.baz.')
    >>> e.description
    'The A bit was set in the bitmap of the NSEC RR corresponding to the SNAME (foo.baz.).'
    '''

    _abstract = False
    references = ['RFC 4035, Sec. 3.1.3.1']
    nsec_type = 'NSEC'

class StypeInBitmapNODATANSEC3(StypeInBitmapNODATA):
    _abstract = False
    references = ['RFC 5155, Sec. 8.5']
    nsec_type = 'NSEC3'

class StypeInBitmapNODATADSNSEC3(StypeInBitmapNODATANSEC3):
    _abstract = False
    references = ['RFC 5155, Sec. 8.6']

class StypeInBitmapWildcardNODATA(StypeInBitmap):
    pass

class StypeInBitmapWildcardNODATANSEC(StypeInBitmapWildcardNODATA):
    _abstract = False
    references = ['RFC 4035, Sec. 3.1.3.4']
    nsec_type = 'NSEC'

class StypeInBitmapWildcardNODATANSEC3(StypeInBitmapWildcardNODATA):
    _abstract = False
    references = ['RFC 5155, Sec. 8.7']
    nsec_type = 'NSEC3'

class NoNSECMatchingSname(NSECError):
    code = 'NO_NSEC_MATCHING_SNAME'
    description_template = "No %(nsec_type)s RR matches the SNAME (%(sname)s)."
    required_params = ['sname']
    nsec_type = 'NSEC'

class NoNSECMatchingSnameNODATA(NoNSECMatchingSname):
    '''
    >>> e = NoNSECMatchingSnameNODATA(sname='foo.baz.')
    >>> e.description
    'No NSEC RR matches the SNAME (foo.baz.).'
    '''

    _abstract = False
    references = ['RFC 4035, Sec. 3.1.3.1']

class NoNSECMatchingSnameWildcardNODATA(NoNSECMatchingSname):
    _abstract = False
    references = ['RFC 4035, Sec. 3.1.3.4']

class NoNSEC3MatchingSname(NSECError):
    code = 'NO_NSEC3_MATCHING_SNAME'
    description_template = "No %(nsec_type)s RR matches the SNAME (%(sname)s)."
    required_params = ['sname']
    nsec_type = 'NSEC3'

class NoNSEC3MatchingSnameNODATA(NoNSEC3MatchingSname):
    '''
    >>> e = NoNSEC3MatchingSnameNODATA(sname='foo.baz.')
    >>> e.description
    'No NSEC3 RR matches the SNAME (foo.baz.).'
    '''

    _abstract = False
    references = ['RFC 5155, Sec. 8.5']

class NoNSEC3MatchingSnameDSNODATA(NoNSEC3MatchingSname):
    _abstract = False
    references = ['RFC 5155, Sec. 8.6']

class WildcardExpansionInvalid(NSECError):
    '''
    >>> e = WildcardExpansionInvalid(sname='a.b.c.foo.baz.', wildcard='*.foo.baz.', next_closest_encloser='b.c.foo.baz.')
    >>> e.description
    'The wildcard expansion of *.foo.baz. to a.b.c.foo.baz. is invalid, as the NSEC RR indicates that the next closest encloser (b.c.foo.baz.) exists.'
    '''

    _abstract = False
    code = 'WILDCARD_EXPANSION_INVALID'
    description_template = "The wildcard expansion of %(wildcard)s to %(sname)s is invalid, as the %(nsec_type)s RR indicates that the next closest encloser (%(next_closest_encloser)s) exists."
    references = ['RFC 1034, Sec. 4.4']
    required_params = ['sname','wildcard','next_closest_encloser']
    nsec_type = 'NSEC'

class WildcardCovered(NSECError):
    code = 'WILDCARD_COVERED'
    description_template = "The %(nsec_type)s RR covers the wildcard itself (%(wildcard)s), indicating that it doesn't exist."
    required_params = ['wildcard']

class WildcardCoveredAnswer(WildcardCovered):
    pass

class WildcardCoveredAnswerNSEC(WildcardCoveredAnswer):
    '''
    >>> e = WildcardCoveredAnswerNSEC(wildcard='*.foo.baz.')
    >>> e.description
    "The NSEC RR covers the wildcard itself (*.foo.baz.), indicating that it doesn't exist."
    '''

    _abstract = False
    references = ['RFC 4035, Sec. 3.1.3.3']
    nsec_type = 'NSEC'

class WildcardCoveredAnswerNSEC3(WildcardCoveredAnswer):
    _abstract = False
    references = ['RFC 5155, Sec. 8.8']
    nsec_type = 'NSEC3'

class WildcardCoveredNODATA(WildcardCovered):
    pass

class WildcardCoveredNODATANSEC(WildcardCoveredNODATA):
    _abstract = False
    references = ['RFC 4035, Sec. 3.1.3.4']
    nsec_type = 'NSEC'

class WildcardCoveredNODATANSEC3(WildcardCoveredNODATA):
    _abstract = False
    references = ['RFC 5155, Sec. 8.7']
    nsec_type = 'NSEC3'

class ExistingNSECError(NSECError):
    required_params = ['queries']

    def __init__(self, **kwargs):
        super(ExistingNSECError, self).__init__(**kwargs)
        queries_text = ['%s/%s' % (name, rdtype) for name, rdtype in self.template_kwargs['queries']]
        self.template_kwargs['queries_text'] = ', '.join(queries_text)

class ExistingCovered(ExistingNSECError):
    description_template = 'The following queries resulted in an answer response, even though the %(nsec_type)s records indicate that the queried names don\'t exist: %(queries_text)s'
    code = 'EXISTING_NAME_COVERED'

class ExistingCoveredNSEC(ExistingCovered):
    '''
    >>> e = ExistingCoveredNSEC(queries=[('www.foo.baz.', 'A'), ('www1.foo.baz.', 'TXT')])
    >>> e.description
    "The following queries resulted in an answer response, even though the NSEC records indicate that the queried names don't exist: www.foo.baz./A, www1.foo.baz./TXT"
    '''

    _abstract = False
    references = ['RFC 4035, Sec. 3.1.3.2']
    nsec_type = 'NSEC'

class ExistingCoveredNSEC3(ExistingCovered):
    '''
    >>> e = ExistingCoveredNSEC3(queries=[('www.foo.baz.', 'A'), ('www1.foo.baz.', 'TXT')])
    >>> e.description
    "The following queries resulted in an answer response, even though the NSEC3 records indicate that the queried names don't exist: www.foo.baz./A, www1.foo.baz./TXT"
    '''

    _abstract = False
    references = ['RFC 5155, Sec. 8.4']
    nsec_type = 'NSEC3'

class ExistingTypeNotInBitmap(ExistingNSECError):
    description_template = 'The following queries resulted in an answer response, even though the bitmap in the %(nsec_type)s RR indicates that the queried records don\'t exist: %(queries_text)s'
    code = 'EXISTING_TYPE_NOT_IN_BITMAP'

class ExistingTypeNotInBitmapNSEC(ExistingTypeNotInBitmap):
    '''
    >>> e = ExistingTypeNotInBitmapNSEC(queries=[('www.foo.baz.', 'A'), ('www.foo.baz.', 'TXT')])
    >>> e.description
    "The following queries resulted in an answer response, even though the bitmap in the NSEC RR indicates that the queried records don't exist: www.foo.baz./A, www.foo.baz./TXT"
    '''

    _abstract = False
    references = ['RFC 4035, Sec. 3.1.3.1']
    nsec_type = 'NSEC'

class ExistingTypeNotInBitmapNSEC3(ExistingTypeNotInBitmap):
    '''
    >>> e = ExistingTypeNotInBitmapNSEC3(queries=[('www.foo.baz.', 'A'), ('www.foo.baz.', 'TXT')])
    >>> e.description
    "The following queries resulted in an answer response, even though the bitmap in the NSEC3 RR indicates that the queried records don't exist: www.foo.baz./A, www.foo.baz./TXT"
    '''

    _abstract = False
    references = ['RFC 5155, Sec. 8.5']
    nsec_type = 'NSEC3'

class SnameCoveredNODATANSEC(NSECError):
    '''
    >>> e = SnameCoveredNODATANSEC(sname='foo.baz.')
    >>> e.description
    "The NSEC RR covers the SNAME (foo.baz.), indicating that it doesn't exist."
    '''

    _abstract = False
    code = 'SNAME_COVERED'
    description_template = "The %(nsec_type)s RR covers the SNAME (%(sname)s), indicating that it doesn't exist."
    references = ['RFC 4035, Sec. 3.1.3.1']
    required_params = ['sname']
    nsec_type = 'NSEC'


class LastNSECNextNotZone(NSECError):
    '''
    >>> e = LastNSECNextNotZone(nsec_owner='z.foo.baz.', next_name='a.foo.baz.', zone_name='foo.baz.')
    >>> e.description
    'The value of the Next Domain Name field in the NSEC RR with owner name z.foo.baz. indicates that it is the last NSEC RR in the zone, but the value (a.foo.baz.) did not match the name of the zone apex (foo.baz.).'
    '''

    _abstract = False
    code = 'LAST_NSEC_NEXT_NOT_ZONE'
    description_template = "The value of the Next Domain Name field in the %(nsec_type)s RR with owner name %(nsec_owner)s indicates that it is the last %(nsec_type)s RR in the zone, but the value (%(next_name)s) did not match the name of the zone apex (%(zone_name)s)."
    references = ['RFC 4034, Sec. 4.1.1']
    required_params = ['nsec_owner','next_name','zone_name']
    nsec_type = 'NSEC'

class UnsupportedNSEC3Algorithm(NSECError):
    '''
    >>> e = UnsupportedNSEC3Algorithm(algorithm=2)
    >>> e.description
    'Generating NSEC3 hashes using algorithm 2 is not supported by this code.'
    '''

    _abstract = False
    code = 'UNSUPPORTED_NSEC3_ALGORITHM'
    description_template = "Generating %(nsec_type)s hashes using algorithm %(algorithm)d is not supported by this code."
    references = ['RFC 5155, Sec. 8.1']
    required_params = ['algorithm']
    nsec_type = 'NSEC3'

class InvalidNSEC3OwnerName(NSECError):
    '''
    >>> e = InvalidNSEC3OwnerName(name='foo.com.')
    >>> e.description
    'The NSEC3 owner name (foo.com.) is invalid; it does not appear to be the Base32 Hex encoding of a hashed owner name.'
    '''

    _abstract = False
    code = 'INVALID_NSEC3_OWNER_NAME'
    description_template = "The %(nsec_type)s owner name (%(name)s) is invalid; it does not appear to be the Base32 Hex encoding of a hashed owner name."
    references = ['RFC 5155, Sec. 3']
    required_params = ['name']
    nsec_type = 'NSEC3'

class InvalidNSEC3Hash(NSECError):
    '''
    >>> e = InvalidNSEC3Hash(name='foo', nsec3_hash='foo===')
    >>> e.description
    'The NSEC3 record for foo is invalid; the value of the Next Hashed Owner Name field (foo===) does not appear to be a valid hash.'
    '''

    _abstract = False
    code = 'INVALID_NSEC3_HASH'
    description_template = 'The NSEC3 record for %(name)s is invalid; the value of the Next Hashed Owner Name field (%(nsec3_hash)s) does not appear to be a valid hash.'
    references = ['RFC 5155, Sec. 3.1.7']
    required_params = ['name', 'nsec3_hash']
    nsec_type = 'NSEC3'

class ResponseError(DomainNameAnalysisError):
    pass

class InvalidResponseError(ResponseError):
    required_params = ['tcp']

    def __init__(self, *args, **kwargs):
        super(ResponseError, self).__init__(**kwargs)
        if self.template_kwargs['tcp']:
            self.template_kwargs['proto'] = 'TCP'
        else:
            self.template_kwargs['proto'] = 'UDP'

class NetworkError(InvalidResponseError):
    '''
    >>> e = NetworkError(tcp=False, errno='EHOSTUNREACH')
    >>> e.description
    'The server was not reachable over UDP (EHOSTUNREACH).'
    >>> e = NetworkError(tcp=False, errno='ECONNREFUSED')
    >>> e.description
    'The UDP connection was refused (ECONNREFUSED).'
    >>> e.terse_description
    'NETWORK_ERROR:ECONNREFUSED'
    '''

    _abstract = False
    code = 'NETWORK_ERROR'
    description_template = '%(description)s'
    terse_description_template = '%(code)s:%(errno)s'
    required_params = InvalidResponseError.required_params + ['errno']

    def __init__(self, *args, **kwargs):
        super(NetworkError, self).__init__(**kwargs)
        if self.template_kwargs['errno'] == 'ECONNRESET':
            self.template_kwargs['description'] = 'The %s connection was interrupted (%s).' % (self.template_kwargs['proto'], self.template_kwargs['errno'])
        elif self.template_kwargs['errno'] == 'ECONNREFUSED':
            self.template_kwargs['description'] = 'The %s connection was refused (%s).' % (self.template_kwargs['proto'], self.template_kwargs['errno'])
        elif self.template_kwargs['errno'] == 'EHOSTUNREACH':
            self.template_kwargs['description'] = 'The server was not reachable over %s (%s).' % (self.template_kwargs['proto'], self.template_kwargs['errno'])
        else:
            self.template_kwargs['description'] = 'There was an error communicating with the server over %s (%s).' % (self.template_kwargs['proto'], self.template_kwargs['errno'])

class FormError(InvalidResponseError):
    '''
    >>> e = FormError(tcp=False, msg_size=30)
    >>> e.description
    'The response (30 bytes) was malformed.'
    '''

    _abstract = False
    code = 'FORMERR'
    description_template = "The response (%(msg_size)d bytes) was malformed."
    required_params = InvalidResponseError.required_params + ['msg_size']

class Timeout(InvalidResponseError):
    '''
    >>> e = Timeout(tcp=False, attempts=3)
    >>> e.description
    'No response was received from the server over UDP (tried 3 times).'
    '''

    _abstract = False
    code = 'TIMEOUT'
    description_template = "No response was received from the server over %(proto)s (tried %(attempts)d times)."
    required_params = InvalidResponseError.required_params + ['attempts']

class UnknownResponseError(InvalidResponseError):
    '''
    >>> e = UnknownResponseError(tcp=False)
    >>> e.description
    'An invalid response was received from the server over UDP.'
    '''

    _abstract = False
    code = 'RESPONSE_ERROR'
    description_template = "An invalid response was received from the server over %(proto)s."

    def __init__(self, *args, **kwargs):
        super(UnknownResponseError, self).__init__(**kwargs)
        self.template_kwargs['description'] = "An invalid response was received from the server over %s" % (self.template_kwargs['proto'])

class InvalidRcode(InvalidResponseError):
    '''
    >>> e = InvalidRcode(tcp=False, rcode='SERVFAIL')
    >>> e.description
    'The response had an invalid RCODE (SERVFAIL).'
    >>> e.terse_description
    'INVALID_RCODE:SERVFAIL'
    '''

    _abstract = False
    code = 'INVALID_RCODE'
    description_template = "The response had an invalid RCODE (%(rcode)s)."
    terse_description_template = '%(code)s:%(rcode)s'
    required_params = InvalidResponseError.required_params + ['rcode']

class NotAuthoritative(ResponseError):
    '''
    >>> e = NotAuthoritative()
    >>> e.description
    'The Authoritative Answer (AA) flag was not set in the response.'
    '''

    _abstract = False
    code = 'NOT_AUTHORITATVE'
    description_template = "The Authoritative Answer (AA) flag was not set in the response."
    references = ['RFC 1035, Sec. 4.1.1']
    required_params = []

class AuthoritativeReferral(ResponseError):
    '''
    >>> e = AuthoritativeReferral()
    >>> e.description
    'The Authoritative Answer (AA) flag was set in the referral response.'
    '''

    _abstract = False
    code = 'AUTHORITATIVE_REFERRAL'
    description_template = "The Authoritative Answer (AA) flag was set in the referral response."
    references = ['RFC 1035, Sec. 4.1.1']
    required_params = []

class RecursionNotAvailable(ResponseError):
    '''
    >>> e = RecursionNotAvailable()
    >>> e.description
    'Recursion was desired, but the Recursion Available (RA) flag was not set in the response.'
    '''

    _abstract = False
    code = 'RECURSION_NOT_AVAILABLE'
    description_template = "Recursion was desired, but the Recursion Available (RA) flag was not set in the response."
    references = ['RFC 1035, Sec. 4.1.1']
    required_params = []

class ResponseErrorWithCondition(ResponseError):
    description_template = "%(response_error_description)s until %(change)s%(query_specific_text)s."
    required_params = ['response_error', 'query_specific']
    use_effective_query_tag = False

    def __init__(self, *args, **kwargs):
        super(ResponseErrorWithCondition, self).__init__(**kwargs)
        self.template_kwargs['response_error_description'] = self.template_kwargs['response_error'].description[:-1]
        if self.template_kwargs['query_specific']:
            self.template_kwargs['query_specific_text'] = ' (however, this server appeared to respond legitimately to other queries with %s)' % (self.precondition % self.template_kwargs)
        else:
            self.template_kwargs['query_specific_text'] = ''

class ResponseErrorWithRequestFlag(ResponseErrorWithCondition):
    '''
    >>> e = ResponseErrorWithRequestFlag(response_error=Timeout(tcp=False, attempts=3), flag='RD', query_specific=False)
    >>> e.description
    'No response was received from the server over UDP (tried 3 times) until the RD flag was cleared.'
    '''

    _abstract = False
    code = 'ERROR_WITH_REQUEST_FLAG'
    references = ['RFC 1035, Sec. 4.1.1']
    required_params = ResponseErrorWithCondition.required_params + ['flag']

    def __init__(self, *args, **kwargs):
        self.precondition = 'the %(flag)s flag set'
        super(ResponseErrorWithRequestFlag, self).__init__(**kwargs)
        self.template_kwargs['change'] = 'the %s flag was cleared' % (self.template_kwargs['flag'])

class ResponseErrorWithoutRequestFlag(ResponseErrorWithCondition):
    '''
    >>> e = ResponseErrorWithoutRequestFlag(response_error=Timeout(tcp=False, attempts=3), flag='RD', query_specific=False)
    >>> e.description
    'No response was received from the server over UDP (tried 3 times) until the RD flag was set.'
    '''

    _abstract = False
    code = 'ERROR_WITHOUT_REQUEST_FLAG'
    references = ['RFC 1035, Sec. 4.1.1']
    required_params = ResponseErrorWithCondition.required_params + ['flag']

    def __init__(self, *args, **kwargs):
        self.precondition = 'the %(flag)s flag cleared'
        super(ResponseErrorWithoutRequestFlag, self).__init__(**kwargs)
        self.template_kwargs['change'] = 'the %s flag was set' % (self.template_kwargs['flag'])

class ResponseErrorWithEDNS(ResponseErrorWithCondition):
    '''
    >>> e = ResponseErrorWithEDNS(response_error=Timeout(tcp=False, attempts=3), query_specific=False)
    >>> e.description
    'No response was received from the server over UDP (tried 3 times) until EDNS was disabled.'
    '''

    _abstract = False
    code = 'ERROR_WITH_EDNS'
    references = ['RFC 6891, Sec. 6.2.6']

    def __init__(self, *args, **kwargs):
        self.precondition = 'EDNS enabled'
        super(ResponseErrorWithEDNS, self).__init__(**kwargs)
        self.template_kwargs['change'] = 'EDNS was disabled'

class ResponseErrorWithEDNSVersion(ResponseErrorWithCondition):
    '''
    >>> e = ResponseErrorWithEDNSVersion(response_error=Timeout(tcp=False, attempts=3), edns_old=3, edns_new=0, query_specific=False)
    >>> e.description
    'No response was received from the server over UDP (tried 3 times) until the version of EDNS was changed from 3 to 0.'
    '''

    _abstract = False
    code = 'ERROR_WITH_EDNS_VERSION'
    references = ['RFC 6891, Sec. 6.1.3']
    required_params = ResponseErrorWithCondition.required_params + ['edns_old', 'edns_new']

    def __init__(self, *args, **kwargs):
        self.precondition = 'EDNS version %(edns_old)d'
        super(ResponseErrorWithEDNSVersion, self).__init__(**kwargs)
        self.template_kwargs['change'] = 'the version of EDNS was changed from %d to %d' % \
                (self.template_kwargs['edns_old'], self.template_kwargs['edns_new'])

class ResponseErrorWithEDNSFlag(ResponseErrorWithCondition):
    '''
    >>> e = ResponseErrorWithEDNSFlag(response_error=Timeout(tcp=False, attempts=3), flag='DO', query_specific=False)
    >>> e.description
    'No response was received from the server over UDP (tried 3 times) until the DO EDNS flag was cleared.'
    '''

    _abstract = False
    code = 'ERROR_WITH_EDNS_FLAG'
    references = ['RFC 6891, Sec. 6.1.4']
    required_params = ResponseErrorWithCondition.required_params + ['flag']

    def __init__(self, *args, **kwargs):
        self.precondition = 'the %(flag)s EDNS flag set'
        super(ResponseErrorWithEDNSFlag, self).__init__(**kwargs)
        self.template_kwargs['change'] = 'the %s EDNS flag was cleared' % (self.template_kwargs['flag'])

class ResponseErrorWithoutEDNSFlag(ResponseErrorWithCondition):
    '''
    >>> e = ResponseErrorWithoutEDNSFlag(response_error=Timeout(tcp=False, attempts=3), flag='DO', query_specific=False)
    >>> e.description
    'No response was received from the server over UDP (tried 3 times) until the DO EDNS flag was set.'
    '''

    _abstract = False
    code = 'ERROR_WITHOUT_EDNS_FLAG'
    references = ['RFC 6891, Sec. 6.1.4']
    required_params = ResponseErrorWithCondition.required_params + ['flag']

    def __init__(self, *args, **kwargs):
        self.precondition = 'the %(flag)s EDNS flag cleared'
        super(ResponseErrorWithoutEDNSFlag, self).__init__(**kwargs)
        self.template_kwargs['change'] = 'the %s EDNS flag was set' % (self.template_kwargs['flag'])

class ResponseErrorWithEDNSOption(ResponseErrorWithCondition):
    '''
    >>> e = ResponseErrorWithEDNSOption(response_error=Timeout(tcp=False, attempts=3), option='NSID', query_specific=False)
    >>> e.description
    'No response was received from the server over UDP (tried 3 times) until the NSID EDNS option was removed.'
    '''

    _abstract = False
    code = 'ERROR_WITH_EDNS_OPTION'
    references = ['RFC 6891, Sec. 6.1.2']
    required_params = ResponseErrorWithCondition.required_params + ['option']

    def __init__(self, *args, **kwargs):
        self.precondition = 'the %(option)s EDNS option present'
        super(ResponseErrorWithEDNSOption, self).__init__(**kwargs)
        self.template_kwargs['change'] = 'the %s EDNS option was removed' % (self.template_kwargs['option'])

class ResponseErrorWithoutEDNSOption(ResponseErrorWithCondition):
    '''
    >>> e = ResponseErrorWithoutEDNSOption(response_error=Timeout(tcp=False, attempts=3), option='NSID', query_specific=False)
    >>> e.description
    'No response was received from the server over UDP (tried 3 times) until the NSID EDNS option was added.'
    '''

    _abstract = False
    code = 'ERROR_WITHOUT_EDNS_OPTION'
    references = ['RFC 6891, Sec. 6.1.2']
    required_params = ResponseErrorWithCondition.required_params + ['option']

    def __init__(self, *args, **kwargs):
        self.precondition = 'without the %(option)s EDNS option'
        super(ResponseErrorWithoutEDNSOption, self).__init__(**kwargs)
        self.template_kwargs['change'] = 'the %s EDNS option was added' % (self.template_kwargs['option'])

class EDNSError(ResponseError):
    pass

class EDNSVersionMismatch(EDNSError):
    '''
    >>> e = EDNSVersionMismatch(request_version=1, response_version=0)
    >>> e.description
    'The server responded with EDNS version 0 when a request with EDNS version 1 was sent, instead of responding with RCODE BADVERS.'
    '''

    _abstract = False
    code = 'EDNS_VERSION_MISMATCH'
    description_template = "The server responded with EDNS version %(response_version)d when a request with EDNS version %(request_version)d was sent, instead of responding with RCODE BADVERS."
    references = ['RFC 6891, Sec. 6.1.3']
    required_params = ['request_version', 'response_version']

class EDNSIgnored(EDNSError):
    '''
    >>> e = EDNSIgnored()
    >>> e.description
    'The server responded with no OPT record, rather than with RCODE FORMERR.'
    '''

    _abstract = False
    code = 'EDNS_IGNORED'
    description_template = 'The server responded with no OPT record, rather than with RCODE FORMERR.'
    references = ['RFC 6891, Sec. 7']
    required_params = []

class EDNSSupportNoOpt(EDNSError):
    '''
    >>> e = EDNSSupportNoOpt()
    >>> e.description
    'The server appeared to understand EDNS by including RRSIG records, but its response included no OPT record.'
    '''

    _abstract = False
    code = 'EDNS_SUPPORT_NO_OPT'
    description_template = 'The server appeared to understand EDNS by including RRSIG records, but its response included no OPT record.'
    references = ['RFC 6891, Sec. 7']
    required_params = []

class GratuitousOPT(EDNSError):
    '''
    >>> e = GratuitousOPT()
    >>> e.description
    'The server responded with an OPT record, even though none was sent in the request.'
    '''

    _abstract = False
    code = 'GRATUITOUS_OPT'
    description_template = 'The server responded with an OPT record, even though none was sent in the request.'
    references = ['RFC 6891, Sec. 6.1.1']
    required_params = []

class ImplementedEDNSVersionNotProvided(EDNSError):
    '''
    >>> e = ImplementedEDNSVersionNotProvided(request_version=100, response_version=100)
    >>> e.description
    'The server responded with BADVERS to EDNS version 100 but responded with version 100 instead of providing the highest EDNS version it implements.'
    '''

    _abstract = False
    code = 'IMPLEMENTED_EDNS_VERSION_NOT_PROVIDED'
    description_template = "The server responded with BADVERS to EDNS version %(request_version)d but responded with version %(response_version)d instead of providing the highest EDNS version it implements."
    references = ['RFC 6891, Sec. 6.1.3']
    required_params = ['request_version', 'response_version']

class EDNSUndefinedFlagsSet(EDNSError):
    '''
    >>> e = EDNSUndefinedFlagsSet(flags=0x80)
    >>> e.description
    'The server set EDNS flags that are undefined: 0x80.'
    '''

    _abstract = False
    code = 'EDNS_UNDEFINED_FLAGS_SET'
    description_template = 'The server set EDNS flags that are undefined: %(flags_text)s.'
    references = ['RFC 6891, Sec. 6.1.4']
    required_params = ['flags']

    def __init__(self, **kwargs):
        super(EDNSUndefinedFlagsSet, self).__init__(**kwargs)
        self.template_kwargs['flags_text'] = '0x%x' % (self.template_kwargs['flags'])

class DNSSECDowngrade(EDNSError):
    description_template = "DNSSEC was effectively downgraded because %(response_error_description)s with %(precondition)s."
    required_params = ['response_error']
    precondition = None

    def __init__(self, *args, **kwargs):
        super(DNSSECDowngrade, self).__init__(**kwargs)
        self.template_kwargs['response_error_description'] = self.template_kwargs['response_error'].description[0].lower() + self.template_kwargs['response_error'].description[1:-1]
        self.template_kwargs['precondition'] = self.precondition

class DNSSECDowngradeDOBitCleared(DNSSECDowngrade):
    '''
    >>> e = DNSSECDowngradeDOBitCleared(response_error=Timeout(tcp=False, attempts=3))
    >>> e.description
    'DNSSEC was effectively downgraded because no response was received from the server over UDP (tried 3 times) with the DO bit set.'
    '''

    _abstract = False
    code = 'DNSSEC_DOWNGRADE_DO_CLEARED'
    precondition = 'the DO bit set'
    references = ['RFC 4035, Sec. 3.2.1']

class DNSSECDowngradeEDNSDisabled(DNSSECDowngrade):
    '''
    >>> e = DNSSECDowngradeEDNSDisabled(response_error=Timeout(tcp=False, attempts=3), query_specific=False)
    >>> e.description
    'DNSSEC was effectively downgraded because no response was received from the server over UDP (tried 3 times) with EDNS enabled.'
    '''

    _abstract = False
    code = 'DNSSEC_DOWNGRADE_EDNS_DISABLED'
    precondition = 'EDNS enabled'
    references = ['RFC 6891, Sec. 7', 'RFC 2671, Sec. 5.3']

class DNSCookieError(ResponseError):
    pass

class GratuitousCookie(DNSCookieError):
    '''
    >>> e = GratuitousCookie()
    >>> e.description
    'The server sent a COOKIE option when none was sent by the client.'
    '''

    _abstract = False
    code = 'GRATUITOUS_COOKIE'
    description_template = 'The server sent a COOKIE option when none was sent by the client.'
    references = ['RFC 7873, Sec. 5.2.1']

class MalformedCookieWithoutFORMERR(DNSCookieError):
    '''
    >>> e = MalformedCookieWithoutFORMERR()
    >>> e.description
    'The server appears to support DNS cookies but did not return a FORMERR status when issued a malformed COOKIE option.'
    '''

    _abstract = False
    code = 'MALFORMED_COOKIE_WITHOUT_FORMERR'
    description_template = 'The server appears to support DNS cookies but did not return a FORMERR status when issued a malformed COOKIE option.'
    references = ['RFC 7873, Sec. 5.2.2']

class NoCookieOption(DNSCookieError):
    '''
    >>> e = NoCookieOption()
    >>> e.description
    'The server appears to support DNS cookies but did not return a COOKIE option.'
    '''

    _abstract = False
    code = 'NO_COOKIE_OPTION'
    description_template = 'The server appears to support DNS cookies but did not return a COOKIE option.'
    references = ['RFC 7873, Sec. 5.2.3']

class NoServerCookieWithoutBADCOOKIE(DNSCookieError):
    '''
    >>> e = NoServerCookieWithoutBADCOOKIE()
    >>> e.description
    'The server appears to support DNS cookies but did not return a BADCOOKIE status when no server cookie was sent.'
    '''

    _abstract = False
    code = 'NO_SERVER_COOKIE_WITHOUT_BADCOOKIE'
    description_template = 'The server appears to support DNS cookies but did not return a BADCOOKIE status when no server cookie was sent.'
    references = ['RFC 7873, Sec. 5.2.3']

class InvalidServerCookieWithoutBADCOOKIE(DNSCookieError):
    '''
    >>> e = InvalidServerCookieWithoutBADCOOKIE()
    >>> e.description
    'The server appears to support DNS cookies but did not return a BADCOOKIE status when an invalid server cookie was sent.'
    '''

    _abstract = False
    code = 'INVALID_SERVER_COOKIE_WITHOUT_BADCOOKIE'
    description_template = 'The server appears to support DNS cookies but did not return a BADCOOKIE status when an invalid server cookie was sent.'
    references = ['RFC 7873, Sec. 5.2.4']

class NoServerCookie(DNSCookieError):
    '''
    >>> e = NoServerCookie()
    >>> e.description
    'The server appears to support DNS cookies but did not return a server cookie with its COOKIE option.'
    '''

    _abstract = False
    code = 'NO_SERVER_COOKIE'
    description_template = 'The server appears to support DNS cookies but did not return a server cookie with its COOKIE option.'
    references = ['RFC 7873, Sec. 5.2.3']

class ClientCookieMismatch(DNSCookieError):
    '''
    >>> e = ClientCookieMismatch()
    >>> e.description
    'The client cookie returned by the server did not match what was sent.'
    '''

    _abstract = False
    code = 'CLIENT_COOKIE_MISMATCH'
    description_template = 'The client cookie returned by the server did not match what was sent.'
    references = ['RFC 7873, Sec. 5.3']

class CookieInvalidLength(DNSCookieError):
    '''
    >>> e = CookieInvalidLength(length=61)
    >>> e.description
    'The cookie returned by the server had an invalid length of 61 bytes.'
    '''

    _abstract = False
    code = 'COOKIE_INVALID_LENGTH'
    description_template = 'The cookie returned by the server had an invalid length of %(length)d bytes.'
    references = ['RFC 7873, Sec. 5.3']
    required_params = ['length']

class UnableToRetrieveDNSSECRecords(ResponseError):
    '''
    >>> e = UnableToRetrieveDNSSECRecords()
    >>> e.description
    'The DNSSEC records necessary to validate the response could not be retrieved from the server.'
    '''

    _abstract = False
    code = 'UNABLE_TO_RETRIEVE_DNSSEC_RECORDS'
    description_template = 'The DNSSEC records necessary to validate the response could not be retrieved from the server.'
    references = ['RFC 4035, Sec. 3.1.1', 'RFC 4035, Sec. 3.1.3']
    required_params = []
    use_effective_query_tag = False

class MissingRRSIG(ResponseError):
    '''
    >>> e = MissingRRSIG()
    >>> e.description
    'No RRSIG covering the RRset was returned in the response.'
    '''

    _abstract = False
    code = 'MISSING_RRSIG'
    description_template = 'No RRSIG covering the RRset was returned in the response.'
    references = ['RFC 4035, Sec. 3.1.1']
    required_params = []

class MissingRRSIGForAlg(ResponseError):
    description_template = 'The %(source)s RRset for the zone included algorithm %(algorithm)d (%(algorithm_text)s), but no RRSIG with algorithm %(algorithm)d covering the RRset was returned in the response.'
    references = ['RFC 4035, Sec. 2.2', 'RFC 6840, Sec. 5.11']
    required_params = ['algorithm']
    source = None

    def __init__(self, **kwargs):
        super(MissingRRSIGForAlg, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = dns.dnssec.algorithm_to_text(self.template_kwargs['algorithm'])
        self.template_kwargs['source'] = self.source

class MissingRRSIGForAlgDNSKEY(MissingRRSIGForAlg):
    '''
    >>> e = MissingRRSIGForAlgDNSKEY(algorithm=5)
    >>> e.description
    'The DNSKEY RRset for the zone included algorithm 5 (RSASHA1), but no RRSIG with algorithm 5 covering the RRset was returned in the response.'
    '''

    _abstract = False
    code = 'MISSING_RRSIG_FOR_ALG_DNSKEY'
    source = 'DNSKEY'

class MissingRRSIGForAlgDS(MissingRRSIGForAlg):
    '''
    >>> e = MissingRRSIGForAlgDS(algorithm=5)
    >>> e.description
    'The DS RRset for the zone included algorithm 5 (RSASHA1), but no RRSIG with algorithm 5 covering the RRset was returned in the response.'
    '''

    _abstract = False
    code = 'MISSING_RRSIG_FOR_ALG_DS'
    source = 'DS'

class MissingRRSIGForAlgDLV(MissingRRSIGForAlg):
    '''
    >>> e = MissingRRSIGForAlgDLV(algorithm=5)
    >>> e.description
    'The DLV RRset for the zone included algorithm 5 (RSASHA1), but no RRSIG with algorithm 5 covering the RRset was returned in the response.'
    '''

    _abstract = False
    code = 'MISSING_RRSIG_FOR_ALG_DLV'
    source = 'DLV'

class MissingNSEC(ResponseError):
    description_template = 'No NSEC RR(s) were returned to validate the %(response)s response.'
    response = None

    def __init__(self, **kwargs):
        super(MissingNSEC, self).__init__(**kwargs)
        self.template_kwargs['response'] = self.response

class MissingNSECForNXDOMAIN(MissingNSEC):
    '''
    >>> e = MissingNSECForNXDOMAIN()
    >>> e.description
    'No NSEC RR(s) were returned to validate the NXDOMAIN response.'
    '''

    _abstract = False
    code = 'MISSING_NSEC_FOR_NXDOMAIN'
    references = ['RFC 4035, Sec. 3.1.3.2', 'RFC 5155, Sec. 7.2.2']
    response = 'NXDOMAIN'

class MissingNSECForNODATA(MissingNSEC):
    '''
    >>> e = MissingNSECForNODATA()
    >>> e.description
    'No NSEC RR(s) were returned to validate the NODATA response.'
    '''

    _abstract = False
    code = 'MISSING_NSEC_FOR_NODATA'
    references = ['RFC 4035, Sec. 3.1.3.1', 'RFC 5155, Sec. 7.2.3', 'RFC 5155, Sec. 7.2.4']
    response = 'NODATA'

class MissingNSECForWildcard(MissingNSEC):
    '''
    >>> e = MissingNSECForWildcard()
    >>> e.description
    'No NSEC RR(s) were returned to validate the wildcard response.'
    '''

    _abstract = False
    code = 'MISSING_NSEC_FOR_WILDCARD'
    references = ['RFC 4035, Sec. 3.1.3.3', 'RFC 4035, Sec. 3.1.3.4', 'RFC 5155, Sec. 7.2.5', 'RFC 5155, Sec. 7.2.6']
    response = 'wildcard'

class MissingSOA(ResponseError):
    description_template = 'No SOA RR was returned with the %(response)s response.'
    references = ['RFC 1034, Sec. 4.3.4']
    response = None

    def __init__(self, **kwargs):
        super(MissingSOA, self).__init__(**kwargs)
        self.template_kwargs['response'] = self.response

class MissingSOAForNXDOMAIN(MissingSOA):
    '''
    >>> e = MissingSOAForNXDOMAIN()
    >>> e.description
    'No SOA RR was returned with the NXDOMAIN response.'
    '''

    _abstract = False
    code = 'MISSING_SOA_FOR_NXDOMAIN'
    references = MissingSOA.references + ['RFC 2308, Sec. 2.1']
    response = 'NXDOMAIN'

class MissingSOAForNODATA(MissingSOA):
    '''
    >>> e = MissingSOAForNODATA()
    >>> e.description
    'No SOA RR was returned with the NODATA response.'
    '''

    _abstract = False
    code = 'MISSING_SOA_FOR_NODATA'
    references = MissingSOA.references + ['RFC 2308, Sec. 2.2']
    response = 'NODATA'

class UpwardReferral(ResponseError):
    _abstract = False
    code = 'UPWARD_REFERRAL'
    description_template = 'The response was an upward referral.'
    references = ['https://www.dns-oarc.net/oarc/articles/upward-referrals-considered-harmful']

class SOAOwnerNotZone(ResponseError):
    description_template = 'An SOA RR with owner name (%(soa_owner_name)s) not matching the zone name (%(zone_name)s) was returned with the %(response)s response.'
    references = ['RFC 1034, Sec. 4.3.4']
    required_params = ['soa_owner_name', 'zone_name']
    response = None

    def __init__(self, **kwargs):
        super(SOAOwnerNotZone, self).__init__(**kwargs)
        self.template_kwargs['response'] = self.response

class SOAOwnerNotZoneForNXDOMAIN(SOAOwnerNotZone):
    '''
    >>> e = SOAOwnerNotZoneForNXDOMAIN(soa_owner_name='foo.baz.', zone_name='bar.')
    >>> e.description
    'An SOA RR with owner name (foo.baz.) not matching the zone name (bar.) was returned with the NXDOMAIN response.'
    '''

    _abstract = False
    code = 'SOA_NOT_OWNER_FOR_NXDOMAIN'
    references = SOAOwnerNotZone.references + ['RFC 2308, Sec. 2.1']
    response = 'NXDOMAIN'

class SOAOwnerNotZoneForNODATA(SOAOwnerNotZone):
    '''
    >>> e = SOAOwnerNotZoneForNODATA(soa_owner_name='foo.baz.', zone_name='bar.')
    >>> e.description
    'An SOA RR with owner name (foo.baz.) not matching the zone name (bar.) was returned with the NODATA response.'
    '''

    _abstract = False
    code = 'SOA_NOT_OWNER_FOR_NODATA'
    references = SOAOwnerNotZone.references + ['RFC 2308, Sec. 2.2']
    response = 'NODATA'

class InconsistentNXDOMAIN(ResponseError):
    '''
    >>> e = InconsistentNXDOMAIN(qname='foo.baz.', rdtype_nxdomain='NS', rdtype_noerror='A')
    >>> e.description
    'The server returned a no error (NOERROR) response when queried for foo.baz. having record data of type A, but returned a name error (NXDOMAIN) when queried for foo.baz. having record data of type NS.'
    '''

    _abstract = False
    code = 'INCONSISTENT_NXDOMAIN'
    description_template = 'The server returned a no error (NOERROR) response when queried for %(qname)s having record data of type %(rdtype_noerror)s, but returned a name error (NXDOMAIN) when queried for %(qname)s having record data of type %(rdtype_nxdomain)s.'
    required_params = ['qname', 'rdtype_nxdomain', 'rdtype_noerror']
    references = ['RFC 1034, Sec. 4.3.2']

class InconsistentNXDOMAINAncestry(ResponseError):
    '''
    >>> e = InconsistentNXDOMAINAncestry(qname='foo.baz.', ancestor_qname='baz.')
    >>> e.description
    "A query for foo.baz. results in a NOERROR response, while a query for its ancestor, baz., returns a name error (NXDOMAIN), which indicates that subdomains of baz., including foo.baz., don't exist."
    '''

    _abstract = False
    code = 'INCONSISTENT_NXDOMAIN_ANCESTOR'
    description_template = "A query for %(qname)s results in a NOERROR response, while a query for its ancestor, %(ancestor_qname)s, returns a name error (NXDOMAIN), which indicates that subdomains of %(ancestor_qname)s, including %(qname)s, don't exist."
    required_params = ['qname', 'ancestor_qname']
    references = []

class PMTUExceeded(ResponseError):
    '''
    >>> e = PMTUExceeded(pmtu_lower_bound=None, pmtu_upper_bound=None)
    >>> e.description
    'No response was received until the UDP payload size was decreased, indicating that the server might be attempting to send a payload that exceeds the path maximum transmission unit (PMTU) size.'
    >>> e = PMTUExceeded(pmtu_lower_bound=511, pmtu_upper_bound=513)
    >>> e.description
    'No response was received until the UDP payload size was decreased, indicating that the server might be attempting to send a payload that exceeds the path maximum transmission unit (PMTU) size. The PMTU was bounded between 511 and 513 bytes.'
    '''

    _abstract = False
    code = 'PMTU_EXCEEDED'
    description_template = '%(description)s'
    required_params = ['pmtu_lower_bound', 'pmtu_upper_bound']
    references = ['RFC 6891, Sec. 6.2.6']
    use_effective_query_tag = False

    def __init__(self, **kwargs):
        super(PMTUExceeded, self).__init__(**kwargs)
        self.template_kwargs['description'] = 'No response was received until the UDP payload size was decreased, indicating that the server might be attempting to send a payload that exceeds the path maximum transmission unit (PMTU) size.'
        if self.template_kwargs['pmtu_lower_bound'] is not None and self.template_kwargs['pmtu_upper_bound'] is not None:
            self.template_kwargs['description'] += ' The PMTU was bounded between %(pmtu_lower_bound)d and %(pmtu_upper_bound)d bytes.' % self.template_kwargs

class ForeignClassData(ResponseError):
    section = None
    description_template = 'Data of class %(cls)s was found in the %(section)s section of the response.'
    references = ['RFC 1034', 'RFC 1035']
    required_params = ['cls']

    def __init__(self, **kwargs):
        super(ForeignClassData, self).__init__(**kwargs)
        self.template_kwargs['section'] = self.section

class ForeignClassDataAnswer(ForeignClassData):
    '''
    >>> e = ForeignClassDataAnswer(cls='CH')
    >>> e.description
    'Data of class CH was found in the Answer section of the response.'
    '''
    section = 'Answer'
    _abstract = False
    code = 'FOREIGN_CLASS_DATA_ANSWER'

class ForeignClassDataAuthority(ForeignClassData):
    '''
    >>> e = ForeignClassDataAuthority(cls='CH')
    >>> e.description
    'Data of class CH was found in the Authority section of the response.'
    '''
    section = 'Authority'
    _abstract = False
    code = 'FOREIGN_CLASS_DATA_AUTHORITY'

class ForeignClassDataAdditional(ForeignClassData):
    '''
    >>> e = ForeignClassDataAdditional(cls='CH')
    >>> e.description
    'Data of class CH was found in the Additional section of the response.'
    '''
    section = 'Additional'
    _abstract = False
    code = 'FOREIGN_CLASS_DATA_ADDITIONAL'

class CasePreservationError(ResponseError):
    '''
    >>> e = CasePreservationError(qname='ExAmPlE.CoM')
    >>> e.description
    'The case of the query name (ExAmPlE.CoM) was not preserved in the Question section of the response.'
    '''

    _abstract = False
    code = 'CASE_NOT_PRESERVED'
    description_template = '%(description)s'
    description_template = 'The case of the query name (%(qname)s) was not preserved in the Question section of the response.'
    required_params = ['qname']

class DelegationError(DomainNameAnalysisError):
    pass

class MissingSEPForAlg(DelegationError):
    '''
    >>> e = MissingSEPForAlg(algorithm=5, source='DS')
    >>> e.description
    "The DS RRset for the zone included algorithm 5 (RSASHA1), but no DS RR matched a DNSKEY with algorithm 5 that signs the zone's DNSKEY RRset."
    '''

    _abstract = False
    code = 'MISSING_SEP_FOR_ALG'
    description_template = "The %(source)s RRset for the zone included algorithm %(algorithm)d (%(algorithm_text)s), but no %(source)s RR matched a DNSKEY with algorithm %(algorithm)d that signs the zone's DNSKEY RRset."
    references = ['RFC 4035, Sec. 2.2', 'RFC 6840, Sec. 5.11']
    required_params = ['algorithm']

    def __init__(self, **kwargs):
        super(MissingSEPForAlg, self).__init__(**kwargs)
        self.template_kwargs['algorithm_text'] = dns.dnssec.algorithm_to_text(self.template_kwargs['algorithm'])
        try:
            self.template_kwargs['source'] = kwargs['source']
        except KeyError:
            raise TypeError('The "source" keyword argument is required for instantiation.')

class NoSEP(DelegationError):
    '''
    >>> e = NoSEP(source='DS')
    >>> e.description
    'No valid RRSIGs made by a key corresponding to a DS RR were found covering the DNSKEY RRset, resulting in no secure entry point (SEP) into the zone.'
    '''

    _abstract = False
    code = 'NO_SEP'
    description_template = "No valid RRSIGs made by a key corresponding to a DS RR were found covering the DNSKEY RRset, resulting in no secure entry point (SEP) into the zone."
    references = ['RFC 4035, Sec. 2.2', 'RFC 6840, Sec. 5.11']
    required_params = []

    def __init__(self, **kwargs):
        super(NoSEP, self).__init__(**kwargs)
        try:
            self.template_kwargs['source'] = kwargs['source']
        except KeyError:
            raise TypeError('The "source" keyword argument is required for instantiation.')

class NoNSInParent(DelegationError):
    '''
    >>> e = NoNSInParent(parent='baz.')
    >>> e.description
    'No delegation NS records were detected in the parent zone (baz.).  This results in an NXDOMAIN response to a DS query (for DNSSEC), even if the parent servers are authoritative for the child.'
    '''

    _abstract = False
    code = 'NO_NS_IN_PARENT'
    description_template = "No delegation NS records were detected in the parent zone (%(parent)s).  This results in an NXDOMAIN response to a DS query (for DNSSEC), even if the parent servers are authoritative for the child."
    references = ['RFC 1034, Sec. 4.2.2']
    required_params = ['parent']

class NoNSAddressesForIPVersion(DelegationError):
    version = None
    required_params = ['reference']

    def __init__(self, *args, **kwargs):
        super(NoNSAddressesForIPVersion, self).__init__(**kwargs)
        self.template_kwargs['version'] = self.version

class NoNSAddressesForIPv4(NoNSAddressesForIPVersion):
    '''
    >>> e = NoNSAddressesForIPv4(reference='parent')
    >>> e.description
    'No IPv4 addresses were found for NS records in the parent zone.'
    '''

    _abstract = False
    code = 'NO_NS_ADDRESSES_FOR_IPV4'
    description_template = "No IPv%(version)d addresses were found for NS records in the %(reference)s zone."
    references = []
    version = 4

class NoNSAddressesForIPv6(NoNSAddressesForIPVersion):
    '''
    >>> e = NoNSAddressesForIPv6(reference='parent')
    >>> e.description
    'No IPv6 addresses were found for NS records in the parent zone.'
    '''

    _abstract = False
    code = 'NO_NS_ADDRESSES_FOR_IPV6'
    description_template = "No IPv%(version)d addresses were found for NS records in the %(reference)s zone."
    references = []
    version = 6

class NSNameError(DelegationError):
    required_params = ['names']

    def __init__(self, **kwargs):
        super(NSNameError, self).__init__(**kwargs)
        self.template_kwargs['names_text'] = ', '.join(self.template_kwargs['names'])

class NSNameNotInChild(NSNameError):
    '''
    >>> e = NSNameNotInChild(names=('ns1.foo.baz.',), parent='baz.')
    >>> e.description
    'The following NS name(s) were found in the delegation NS RRset (i.e., in the baz. zone), but not in the authoritative NS RRset: ns1.foo.baz.'
    '''

    _abstract = False
    code = 'NS_NAME_NOT_IN_CHILD'
    description_template = "The following NS name(s) were found in the delegation NS RRset (i.e., in the %(parent)s zone), but not in the authoritative NS RRset: %(names_text)s"
    required_params = NSNameError.required_params + ['parent']

class NSNameNotInParent(NSNameError):
    '''
    >>> e = NSNameNotInParent(names=('ns1.foo.baz.',), parent='baz.')
    >>> e.description
    'The following NS name(s) were found in the authoritative NS RRset, but not in the delegation NS RRset (i.e., in the baz. zone): ns1.foo.baz.'
    '''

    _abstract = False
    code = 'NS_NAME_NOT_IN_PARENT'
    description_template = "The following NS name(s) were found in the authoritative NS RRset, but not in the delegation NS RRset (i.e., in the %(parent)s zone): %(names_text)s"
    required_params = NSNameError.required_params + ['parent']

class ErrorResolvingNSName(NSNameError):
    '''
    >>> e = ErrorResolvingNSName(names=('ns1.foo.baz.',))
    >>> e.description
    'There was an error resolving the following NS name(s) to address(es): ns1.foo.baz.'
    '''

    _abstract = False
    code = 'ERROR_RESOLVING_NS_NAME'
    description_template = 'There was an error resolving the following NS name(s) to address(es): %(names_text)s'

class MissingGlueForNSName(NSNameError):
    '''
    >>> e = MissingGlueForNSName(names=('ns1.foo.baz.',))
    >>> e.description
    'The following NS name(s) required glue, but no glue was returned in the referral: ns1.foo.baz.'
    '''

    _abstract = False
    code = 'MISSING_GLUE_FOR_NS_NAME'
    description_template = "The following NS name(s) required glue, but no glue was returned in the referral: %(names_text)s"

class NoAddressForNSName(NSNameError):
    '''
    >>> e = NoAddressForNSName(names=('ns1.foo.baz.',))
    >>> e.description
    'The following NS name(s) did not resolve to address(es): ns1.foo.baz.'
    '''

    _abstract = False
    code = 'NO_ADDRESS_FOR_NS_NAME'
    description_template = "The following NS name(s) did not resolve to address(es): %(names_text)s"

class PrivateAddressNS(NSNameError):
    pass

class NSNameResolvesToPrivateIP(PrivateAddressNS):
    '''
    >>> e = NSNameResolvesToPrivateIP(names=('ns1.foo.baz.',))
    >>> e.description
    'The following NS name(s) resolved to IP address(es) in private IP address space: ns1.foo.baz.'
    '''

    _abstract = False
    code = 'NS_NAME_PRIVATE_IP'
    description_template = "The following NS name(s) resolved to IP address(es) in private IP address space: %(names_text)s"

class GlueReferencesPrivateIP(PrivateAddressNS):
    '''
    >>> e = GlueReferencesPrivateIP(names=('ns1.foo.baz.',))
    >>> e.description
    'Glue for the following NS name(s) referenced IP address(es) in private IP address space: ns1.foo.baz.'
    '''

    _abstract = False
    code = 'GLUE_PRIVATE_IP'
    description_template = "Glue for the following NS name(s) referenced IP address(es) in private IP address space: %(names_text)s"

class GlueMismatchError(DelegationError):
    '''
    >>> e = GlueMismatchError(name='ns1.foo.baz.', glue_addresses=('192.0.2.1',), auth_addresses=('192.0.2.2',))
    >>> e.description
    'The glue address(es) for ns1.foo.baz. (192.0.2.1) differed from its authoritative address(es) (192.0.2.2).'
    '''

    _abstract = False
    code = 'GLUE_MISMATCH'
    description_template = 'The glue address(es) for %(name)s (%(glue_addresses_text)s) differed from its authoritative address(es) (%(auth_addresses_text)s).'
    required_params = ['name', 'glue_addresses', 'auth_addresses']

    def __init__(self, **kwargs):
        super(GlueMismatchError, self).__init__(**kwargs)
        self.template_kwargs['glue_addresses_text'] = ', '.join(self.template_kwargs['glue_addresses'])
        self.template_kwargs['auth_addresses_text'] = ', '.join(self.template_kwargs['auth_addresses'])

class MissingGlueIPv4(DelegationError):
    '''
    >>> e = MissingGlueIPv4(name='ns1.foo.baz.')
    >>> e.description
    'Authoritative A records exist for ns1.foo.baz., but there are no corresponding A glue records.'
    '''

    _abstract = False
    code = 'MISSING_GLUE_IPV4'
    description_template = "Authoritative A records exist for %(name)s, but there are no corresponding A glue records."
    required_params = ['name']

class MissingGlueIPv6(DelegationError):
    '''
    >>> e = MissingGlueIPv6(name='ns1.foo.baz.')
    >>> e.description
    'Authoritative AAAA records exist for ns1.foo.baz., but there are no corresponding AAAA glue records.'
    '''

    _abstract = False
    code = 'MISSING_GLUE_IPV6'
    description_template = "Authoritative AAAA records exist for %(name)s, but there are no corresponding AAAA glue records."
    required_params = ['name']

class ExtraGlueIPv4(DelegationError):
    '''
    >>> e = ExtraGlueIPv4(name='ns1.foo.baz.')
    >>> e.description
    'A glue records exist for ns1.foo.baz., but there are no corresponding authoritative A records.'
    '''

    _abstract = False
    code = 'EXTRA_GLUE_IPV4'
    description_template = "A glue records exist for %(name)s, but there are no corresponding authoritative A records."
    required_params = ['name']

class ExtraGlueIPv6(DelegationError):
    '''
    >>> e = ExtraGlueIPv6(name='ns1.foo.baz.')
    >>> e.description
    'AAAA glue records exist for ns1.foo.baz., but there are no corresponding authoritative AAAA records.'
    '''

    _abstract = False
    code = 'EXTRA_GLUE_IPV6'
    description_template = "AAAA glue records exist for %(name)s, but there are no corresponding authoritative AAAA records."
    required_params = ['name']

class ServerUnresponsive(DelegationError):
    description_template = "The server(s) were not responsive to queries over %(proto)s."
    proto = None

    def __init__(self, **kwargs):
        super(ServerUnresponsive, self).__init__(**kwargs)
        self.template_kwargs['proto'] = self.proto

class ServerUnresponsiveUDP(ServerUnresponsive):
    '''
    >>> e = ServerUnresponsiveUDP()
    >>> e.description
    'The server(s) were not responsive to queries over UDP.'
    '''

    _abstract = False
    code = 'SERVER_UNRESPONSIVE_UDP'
    proto = 'UDP'

class ServerUnresponsiveTCP(ServerUnresponsive):
    '''
    >>> e = ServerUnresponsiveTCP()
    >>> e.description
    'The server(s) were not responsive to queries over TCP.'
    '''

    _abstract = False
    code = 'SERVER_UNRESPONSIVE_TCP'
    proto = 'TCP'

class ServerInvalidResponseUDP(DelegationError):
    '''
    >>> e = ServerInvalidResponseUDP()
    >>> e.description
    'The server(s) responded over UDP with a malformed response or with an invalid RCODE.'
    '''

    _abstract = False
    code = 'SERVER_INVALID_RESPONSE_UDP'
    description_template = 'The server(s) responded over UDP with a malformed response or with an invalid RCODE.'

class ServerInvalidResponseTCP(DelegationError):
    '''
    >>> e = ServerInvalidResponseTCP()
    >>> e.description
    'The server(s) responded over TCP with a malformed response or with an invalid RCODE.'
    '''

    _abstract = False
    code = 'SERVER_INVALID_RESPONSE_TCP'
    description_template = 'The server(s) responded over TCP with a malformed response or with an invalid RCODE.'

class ServerNotAuthoritative(DelegationError):
    '''
    >>> e = ServerNotAuthoritative()
    >>> e.description
    'The server(s) did not respond authoritatively for the namespace.'
    '''

    _abstract = False
    code = 'SERVER_NOT_AUTHORITATIVE'
    description_template = "The server(s) did not respond authoritatively for the namespace."

class DNAMEError(DomainNameAnalysisError):
    pass

class DNAMENoCNAME(DNAMEError):
    '''
    >>> e = DNAMENoCNAME()
    >>> e.description
    'No synthesized CNAME RR was found accompanying the DNAME record.'
    '''
    _abstract = False
    description_template = "No synthesized CNAME RR was found accompanying the DNAME record."
    code = 'DNAME_NO_CNAME'

class DNAMETargetMismatch(DNAMEError):
    '''
    >>> e = DNAMETargetMismatch(included_target='foo.baz.', synthesized_target='bar.baz.')
    >>> e.description
    'The included CNAME RR is not a valid synthesis of the DNAME record (foo.baz. != bar.baz.).'
    '''
    _abstract = False
    description_template = "The included CNAME RR is not a valid synthesis of the DNAME record (%(included_target)s != %(synthesized_target)s)."
    code = 'DNAME_TARGET_MISMATCH'
    required_params = ['included_target', 'synthesized_target']

class DNAMETTLZero(DNAMEError):
    '''
    >>> e = DNAMETTLZero()
    >>> e.description
    'The TTL of the synthesized CNAME RR is 0.'
    '''
    _abstract = False
    description_template = "The TTL of the synthesized CNAME RR is 0."
    code = 'DNAME_TTL_ZERO'

class DNAMETTLMismatch(DNAMEError):
    '''
    >>> e = DNAMETTLMismatch(cname_ttl=50, dname_ttl=60)
    >>> e.description
    'The TTL of the synthesized CNAME RR (50) does not match the TTL of the DNAME record (60).'
    '''
    _abstract = False
    description_template = "The TTL of the synthesized CNAME RR (%(cname_ttl)d) does not match the TTL of the DNAME record (%(dname_ttl)d)."
    code = 'DNAME_TTL_MISMATCH'
    required_params = ['cname_ttl', 'dname_ttl']

class DNSKEYError(DomainNameAnalysisError):
    pass

class DNSKEYMissingFromServers(DNSKEYError):
    '''
    >>> e = DNSKEYMissingFromServers()
    >>> e.description
    'The DNSKEY RR was not found in the DNSKEY RRset returned by one or more servers.'
    '''
    _abstract = False
    description_template = "The DNSKEY RR was not found in the DNSKEY RRset returned by one or more servers."
    code = 'DNSKEY_MISSING_FROM_SERVERS'

class DNSKEYNotAtZoneApex(DNSKEYError):
    '''
    >>> e = DNSKEYNotAtZoneApex(zone='foo.baz.', name='bar.foo.baz.')
    >>> e.description
    'The owner name of the DNSKEY RRset (bar.foo.baz.) does not match the zone apex (foo.baz.).'
    '''
    _abstract = False
    description_template = "The owner name of the DNSKEY RRset (%(name)s) does not match the zone apex (%(zone)s)."
    code = 'DNSKEY_NOT_AT_ZONE_APEX'
    required_params = ['zone', 'name']

class DNSKEYBadLength(DNSKEYError):
    pass

class DNSKEYZeroLength(DNSKEYBadLength):
    '''
    >>> e = DNSKEYZeroLength()
    >>> e.description
    'The length of the key is 0 bits.'
    '''
    _abstract = False
    description_template = 'The length of the key is 0 bits.'
    code = 'DNSKEY_ZERO_LENGTH'
    references = []
    required_params = []

class DNSKEYBadLengthGOST(DNSKEYBadLength):
    '''
    >>> e = DNSKEYBadLengthGOST(length=500)
    >>> e.description
    'The length of the key is 500 bits, but a GOST public key (DNSSEC algorithm 12) must be 512 bits long.'
    '''
    _abstract = False
    description_template = 'The length of the key is %(length)d bits, but a GOST public key (DNSSEC algorithm 12) must be 512 bits long.'
    code = 'DNSKEY_BAD_LENGTH_GOST'
    references = ['RFC 5933, Sec. 5.1']
    required_params = ['length']

class DNSKEYBadLengthECDSA(DNSKEYBadLength):
    curve = None
    algorithm = None
    correct_length = None
    description_template = 'The length of the key is %(length)d bits, but an ECDSA public key using Curve %(curve)s (DNSSEC algorithm %(algorithm)d) must be %(correct_length)d bits long.'
    references = ['RFC 6605, Sec. 4']
    required_params = ['length']

    def __init__(self, **kwargs):
        super(DNSKEYBadLengthECDSA, self).__init__(**kwargs)
        self.template_kwargs['curve'] = self.curve
        self.template_kwargs['algorithm'] = self.algorithm
        self.template_kwargs['correct_length'] = self.correct_length

class DNSKEYBadLengthECDSA256(DNSKEYBadLengthECDSA):
    '''
    >>> e = DNSKEYBadLengthECDSA256(length=500)
    >>> e.description
    'The length of the key is 500 bits, but an ECDSA public key using Curve P-256 (DNSSEC algorithm 13) must be 512 bits long.'
    '''
    curve = 'P-256'
    algorithm = 13
    correct_length = 512
    _abstract = False
    code = 'DNSKEY_BAD_LENGTH_ECDSA256'

class DNSKEYBadLengthECDSA384(DNSKEYBadLengthECDSA):
    '''
    >>> e = DNSKEYBadLengthECDSA384(length=500)
    >>> e.description
    'The length of the key is 500 bits, but an ECDSA public key using Curve P-384 (DNSSEC algorithm 14) must be 768 bits long.'
    '''
    curve = 'P-384'
    algorithm = 14
    correct_length = 768
    _abstract = False
    code = 'DNSKEY_BAD_LENGTH_ECDSA384'

class DNSKEYBadLengthEdDSA(DNSKEYBadLength):
    curve = None
    algorithm = None
    correct_length = None
    description_template = 'The length of the key is %(length)d bits, but an %(curve)s public key (DNSSEC algorithm %(algorithm)d) must be %(correct_length)d bits long.'
    references = ['RFC 8080, Sec. 3']
    required_params = ['length']

    def __init__(self, **kwargs):
        super(DNSKEYBadLengthEdDSA, self).__init__(**kwargs)
        self.template_kwargs['curve'] = self.curve
        self.template_kwargs['algorithm'] = self.algorithm
        self.template_kwargs['correct_length'] = self.correct_length

class DNSKEYBadLengthEd25519(DNSKEYBadLengthEdDSA):
    '''
    >>> e = DNSKEYBadLengthEd25519(length=500)
    >>> e.description
    'The length of the key is 500 bits, but an Ed25519 public key (DNSSEC algorithm 15) must be 256 bits long.'
    '''
    curve = 'Ed25519'
    algorithm = 15
    correct_length = 256
    _abstract = False
    code = 'DNSKEY_BAD_LENGTH_ED25519'

class DNSKEYBadLengthEd448(DNSKEYBadLengthEdDSA):
    '''
    >>> e = DNSKEYBadLengthEd448(length=500)
    >>> e.description
    'The length of the key is 500 bits, but an Ed448 public key (DNSSEC algorithm 16) must be 456 bits long.'
    '''
    curve = 'Ed448'
    algorithm = 16
    correct_length = 456
    _abstract = False
    code = 'DNSKEY_BAD_LENGTH_ED448'

class TrustAnchorError(DomainNameAnalysisError):
    pass

class NoTrustAnchorSigning(TrustAnchorError):
    '''
    >>> e = NoTrustAnchorSigning(zone='foo.baz.')
    >>> e.description
    'One or more keys were designated as trust anchors for foo.baz., but none were found signing the DNSKEY RRset.'
    '''
    _abstract = False
    description_template = "One or more keys were designated as trust anchors for %(zone)s, but none were found signing the DNSKEY RRset."
    code = 'NO_TRUST_ANCHOR_SIGNING'
    required_params = ['zone']

class RevokedNotSigning(DNSKEYError):
    '''
    >>> e = RevokedNotSigning()
    >>> e.description
    'The key was revoked but was not found signing the RRset.'
    '''
    _abstract = False
    description_template = "The key was revoked but was not found signing the RRset."
    code = 'REVOKED_NOT_SIGNING'

class ZoneDataError(DomainNameAnalysisError):
    pass

class CNAMEWithOtherData(ZoneDataError):
    '''
    >>> e = CNAMEWithOtherData(name='foo.')
    >>> e.description
    'The server returned CNAME for foo., but records of other types exist at that name.'
    '''
    _abstract = False
    description_template = "The server returned CNAME for %(name)s, but records of other types exist at that name."
    code = 'CNAME_WITH_OTHER_DATA'
    required_params = ['name']
    references = ['RFC 2181, Sec. 10.1']

class CNAMELoop(ZoneDataError):
    '''
    >>> e = CNAMELoop()
    >>> e.description
    'This record results in a CNAME loop.'
    '''
    _abstract = False
    description_template = "This record results in a CNAME loop."
    code = 'CNAME_LOOP'
    references = ['RFC 1034, Sec. 3.6.2']
