#
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

import base64
import StringIO
import struct

import dns.rdatatype, dns.name

from format import DNSKEY_FLAGS

from M2Crypto import DSA, EC, Engine, EVP, m2, RSA
from M2Crypto.m2 import hex_to_bn, bn_to_mpi

GOST_PREFIX = '\x30\x63\x30\x1c\x06\x06\x2a\x85\x03\x02\x02\x13\x30\x12\x06\x07\x2a\x85\x03\x02\x02\x23\x01\x06\x07\x2a\x85\x03\x02\x02\x1e\x01\x03\x43\x00\x04\x40'

class GostMessageDigest(EVP.MessageDigest):
    def __init__(self, md):
        self.md=md
        self.ctx=m2.md_ctx_new()
        m2.digest_init(self.ctx, self.md)

def _gost_init():
    gost = Engine.load_dynamic_engine('gost', '/usr/lib/x86_64-linux-gnu/openssl-1.0.0/engines/libgost.so')
    gost.init()
    gost.set_default()

def _gost_cleanup():
    gost = Engine.Engine('gost')
    gost.finish()
    Engine.cleanup()

def key_tag(dnskey, clear_revoke=False):
    '''Return the key_tag for the given key, flags, protocol, algorithm,
    as specified in RFC 4034.  If clear_revoke is True, then clear the
    revoke flag of the DNSKEY RR first.'''

    if dnskey.algorithm == 1:
        key_tag, = struct.unpack('!H', dnskey.key[-3:-1])
        return key_tag

    if clear_revoke:
        flags = dnskey.flags & (~DNSKEY_FLAGS['revoke'])
    else:
        flags = dnskey.flags

    key_str = struct.pack('!HBB', flags, dnskey.protocol, dnskey.algorithm) + dnskey.key

    ac = 0
    for i in range(len(key_str)):
        b, = struct.unpack('B',key_str[i])
        if i & 1:
            ac += b
        else:
            ac += (b << 8)

    ac += (ac >> 16) & 0xffff
    return ac & 0xffff

def key_len(dnskey):
    key_str = dnskey.key
    # RSA keys
    if dnskey.algorithm in (1,5,7,8,10):
        try:
            # get the exponent length
            e_len, = struct.unpack('B',key_str[0])
        except IndexError:
            return 0

        offset = 1
        if e_len == 0:
            e_len, = struct.unpack('!H',key_str[1:3])
            offset = 3

        # get the exponent 
        offset += e_len

        # get the modulus
        return (len(key_str) - offset) << 3

    # DSA keys
    elif dnskey.algorithm in (3,6):
        t, = struct.unpack('B',key_str[0])
        return (64 + t*8)<<3

    # GOST keys
    elif dnskey.algorithm in (12,):
        return len(key_str)<<3

    # EC keys
    elif dnskey.algorithm in (13,14):
        return len(key_str)<<3

    return None

def _canonicalize_rrset(rrset):
    '''Downcase rdata in each RR.'''
    #XXX see if this can be done in dnspython

    rrset.name = rrset.name.canonicalize()
    for rr in rrset:
        if rrset.rdtype == dns.rdatatype.SOA:
            rr.mname = rr.mname.canonicalize()
            rr.rname = rr.rname.canonicalize()
        elif rrset.rdtype in (dns.rdatatype.CNAME, dns.rdatatype.DNAME, dns.rdatatype.NS, dns.rdatatype.PTR):
            rr.target = rr.target.canonicalize()
        elif rrset.rdtype == dns.rdatatype.MX:
            rr.exchange = rr.exchange.canonicalize()

def _rr_cmp(a, b):
    '''Compare the wire value of rdata a and rdata b.'''
    #XXX see if this can be done in dnspython

    a_val = a.to_digestable()
    b_val = b.to_digestable()

    if a_val < b_val:
        return -1
    elif a_val > b_val:
        return 1
    else:
        return 0

def _message_for_rrsig(rrset, rrsig):
    msg_io = StringIO.StringIO()

    # write RRSIG in wire format
    rrsig_rdata = struct.pack('!HBBIIIH', rrsig.type_covered,
                         rrsig.algorithm, rrsig.labels,
                         rrsig.original_ttl, rrsig.expiration,
                         rrsig.inception, rrsig.key_tag)
    msg_io.write(rrsig_rdata)
    rrsig.signer.canonicalize().to_wire(msg_io)

    _canonicalize_rrset(rrset)
    rrs_canonical = list(rrset)
    rrs_canonical.sort(cmp=_rr_cmp)

    rrset_name = reduce_wildcard(rrset, [rrsig]) or rrset.name

    for rr in rrs_canonical:
        rrset_name.to_wire(msg_io)
        #XXX check that TTL of rrset isn't greater than original TTL
        stuff = struct.pack("!HHIH", rrset.rdtype, rrset.rdclass,
                            rrsig.original_ttl, 0)
        msg_io.write(stuff)

        rdata_start = msg_io.tell()
        rr.to_wire(msg_io)
        rdata_end = msg_io.tell()

        # now go back and write the rd_len value
        msg_io.seek(rdata_start - 2, 0)
        msg_io.write(struct.pack("!H", rdata_end - rdata_start))
        # and now seek back to the end of the file
        msg_io.seek(0, 2)
    return msg_io.getvalue()

def _message_for_ds(name, dnskey):
    msg_io = StringIO.StringIO()

    name.canonicalize().to_wire(msg_io)

    # write DNSKEY rdata in wire format
    dnskey_rdata = struct.pack('!HBB', dnskey.flags,
                         dnskey.protocol, dnskey.algorithm)
    msg_io.write(dnskey_rdata)
    msg_io.write(dnskey.key)

    return msg_io.getvalue()

def validate_ds_digest(ds, name, dnskey):
    msg = _message_for_ds(name, dnskey)

    if ds.digest_type == 1:
        md = EVP.MessageDigest('sha1')
        md.update(msg)
        valid = md.final() == ds.digest
    elif ds.digest_type == 2:
        md = EVP.MessageDigest('sha256')
        md.update(msg)
        valid = md.final() == ds.digest
    elif ds.digest_type == 3:
        _gost_init()
        mdgost = m2.get_digestbyname('GOST R 34.11-94')
        md = GostMessageDigest(mdgost)
        md.update(msg)
        valid = md.final() == ds.digest
        _gost_cleanup()
    elif ds.digest_type == 4:
        md = EVP.MessageDigest('sha384')
        md.update(msg)
        valid = md.final() == ds.digest
    else:
        valid = None
    return valid

def _dnskey_to_dsa(dnskey):
    # get T
    t, = struct.unpack('B',dnskey.key[0])
    offset = 1

    # get Q
    new_offset = offset+20
    q = ''
    for c in dnskey.key[offset:new_offset]:
        q += '%02x' % struct.unpack('B',c)[0]
    q = bn_to_mpi(hex_to_bn(q))
    offset = new_offset

    # get P
    new_offset = offset+64+(t<<3)
    p = ''
    for c in dnskey.key[offset:new_offset]:
        p += '%02x' % struct.unpack('B',c)[0]
    p = bn_to_mpi(hex_to_bn(p))
    offset = new_offset

    # get G
    new_offset = offset+64+(t<<3)
    g = ''
    for c in dnskey.key[offset:new_offset]:
        g += '%02x' % struct.unpack('B',c)[0]
    g = bn_to_mpi(hex_to_bn(g))
    offset = new_offset

    # get Y
    new_offset = offset+64+(t<<3)
    y = ''
    for c in dnskey.key[offset:new_offset]:
        y += '%02x' % struct.unpack('B',c)[0]
    y = bn_to_mpi(hex_to_bn(y))
    offset = new_offset

    # create the DSA public key
    try:
        dsa = DSA.pub_key_from_params(p,q,g,y)
    except AttributeError:
        sys.stderr.write('warning: using unpatched version of m2crypto\n')
        return None
    return dsa

def _dnskey_to_rsa(dnskey):
    try:
        # get the exponent length
        e_len, = struct.unpack('B',dnskey.key[0])
    except IndexError:
        return None

    offset = 1
    if e_len == 0:
        e_len, = struct.unpack('!H',dnskey.key[1:3])
        offset = 3

    # get the exponent 
    e = ''
    for c in dnskey.key[offset:offset+e_len]:
        e += '%02x' % struct.unpack('B',c)[0]
    e = bn_to_mpi(hex_to_bn(e))
    offset += e_len

    # get the modulus
    n = ''
    for c in dnskey.key[offset:]:
        n += '%02x' % struct.unpack('B',c)[0]
    n = bn_to_mpi(hex_to_bn(n))

    # create the RSA public key
    rsa = RSA.new_pub_key((e,n))
    pubkey = EVP.PKey()
    pubkey.assign_rsa(rsa)

    return pubkey

def _dnskey_to_gost(dnskey):
    der = GOST_PREFIX + dnskey.key
    pem = '-----BEGIN PUBLIC KEY-----\n'+base64.encodestring(der)+'-----END PUBLIC KEY-----'

    return EVP.load_key_string_pubkey(pem)

def _dnskey_to_ec(dnskey):
    if dnskey.algorithm == 13:
        curve = EC.NID_X9_62_prime256v1
    elif dnskey.algorithm == 14:
        curve = EC.NID_secp384r1
    else:
        raise ValueError('Algorithm not supported')

    return EC.pub_key_from_params(curve, dnskey.key)

def _validate_rrsig_rsa(rrsig, rrset, dnskey):
    pubkey = _dnskey_to_rsa(dnskey)
    if pubkey is None:
        return False

    msg = _message_for_rrsig(rrset, rrsig)

    if rrsig.algorithm in (1,):
        md='md5'
    elif rrsig.algorithm in (5,7):
        md='sha1'
    elif rrsig.algorithm in (8,):
        md='sha256'
    elif rrsig.algorithm in (10,):
        md='sha512'
    else:
        raise ValueError('hash unknown!')

    # reset context for appropriate hash
    pubkey.reset_context(md=md)
    pubkey.verify_init()
    pubkey.verify_update(msg)

    valid = pubkey.verify_final(rrsig.signature) == 1
    return valid

def _validate_rrsig_dsa(rrsig, rrset, dnskey):
    pubkey = _dnskey_to_dsa(dnskey)
    msg = _message_for_rrsig(rrset, rrsig)

    sig = rrsig.signature

    # get T
    t, = struct.unpack('B',sig[0])
    offset = 1

    # get R
    new_offset = offset+20
    r = ''
    for c in sig[offset:new_offset]:
        r += '%02x' % struct.unpack('B',c)[0]
    r = bn_to_mpi(hex_to_bn(r))
    offset = new_offset

    # get S
    new_offset = offset+20
    s = ''
    for c in sig[offset:new_offset]:
        s += '%02x' % struct.unpack('B',c)[0]
    s = bn_to_mpi(hex_to_bn(s))
    offset = new_offset

    md = EVP.MessageDigest('sha1')
    md.update(msg)
    digest = md.final()

    valid = pubkey.verify(digest, r, s) == 1

    return valid

def _validate_rrsig_gost(rrsig, rrset, dnskey):
    _gost_init()

    pubkey = _dnskey_to_gost(dnskey)
    msg = _message_for_rrsig(rrset, rrsig)

    pubkey.md = m2.get_digestbyname('GOST R 34.11-94')
    pubkey.verify_init()
    pubkey.verify_update(msg)

    valid = pubkey.verify_final(rrsig.signature) == 1

    _gost_cleanup()

    return valid

def _validate_rrsig_ec(rrsig, rrset, dnskey):
    pubkey = _dnskey_to_ec(dnskey)
    msg = _message_for_rrsig(rrset, rrsig)

    if rrsig.algorithm in (13,):
        alg='sha256'
        sigsize = 64
    elif rrsig.algorithm in (14,):
        alg='sha384'
        sigsize = 96
    else:
        raise ValueError('EC hash algorithm unknown!')

    if sigsize != len(rrsig.signature):
        return False

    sig = rrsig.signature
    offset = 0

    # get R
    new_offset = offset+sigsize/2
    r = ''
    for c in sig[offset:new_offset]:
        r += '%02x' % struct.unpack('B',c)[0]
    r = bn_to_mpi(hex_to_bn(r))
    offset = new_offset

    # get S
    new_offset = offset+sigsize/2
    s = ''
    for c in sig[offset:new_offset]:
        s += '%02x' % struct.unpack('B',c)[0]
    s = bn_to_mpi(hex_to_bn(s))
    offset = new_offset

    md = EVP.MessageDigest(alg)
    md.update(msg)
    digest = md.final()

    valid = pubkey.verify_dsa(digest, r, s) == 1

    return valid

def validate_rrsig(rrsig, rrset, dnskey):
    assert rrsig.algorithm == dnskey.algorithm

    # create an RSA key object for RSA keys
    if dnskey.algorithm in (1,5,7,8,10):
        valid = _validate_rrsig_rsa(rrsig, rrset, dnskey)
    elif dnskey.algorithm in (3,6):
        valid = _validate_rrsig_dsa(rrsig, rrset, dnskey)
    elif dnskey.algorithm in (12,):
        valid = _validate_rrsig_gost(rrsig, rrset, dnskey)
    elif dnskey.algorithm in (13,14):
        valid = _validate_rrsig_ec(rrsig, rrset, dnskey)
    else:
        valid = None

    return valid

def dnskeys_for_ds(name, ds, dnskey_rrsets_rrsigs, supported_ds_algorithms=None):
    dnskeys_good_hash = set()
    dnskeys_bad_hash = set()
    dnskeys_unknown_hash = set()

    completed_dnskeys = set()
    for dnskey_rrset, servers, rrsigs in dnskey_rrsets_rrsigs:
        if dnskey_rrset.rdtype != dns.rdatatype.DNSKEY:
            continue
        good_from_rrset = set()
        bad_from_rrset = set()
        unknown_from_rrset = set()
        for dnskey in dnskey_rrset:
            if dnskey in completed_dnskeys:
                continue
            completed_dnskeys.add(dnskey)
            my_key_tag = key_tag(dnskey)
            my_key_tag_no_revoke = key_tag(dnskey, True)
            if not (ds.key_tag in (my_key_tag, my_key_tag_no_revoke) and \
                    ds.algorithm == dnskey.algorithm):
                continue
            if supported_ds_algorithms is not None and \
                    ds.digest_type not in supported_ds_algorithms:
                valid = None
            else:
                valid = validate_ds_digest(ds, name, dnskey)

            if valid is None:
                unknown_from_rrset.add(dnskey)
            elif valid:
                good_from_rrset.add(dnskey)
            else:
                bad_from_rrset.add(dnskey)

        if good_from_rrset:
            dnskeys_good_hash.update(good_from_rrset)
        elif bad_from_rrset:
            dnskeys_bad_hash.update(bad_from_rrset)
        dnskeys_unknown_hash.update(unknown_from_rrset)

    l = [(k, True) for k in dnskeys_good_hash] + [(k, False) for k in dnskeys_bad_hash] + [(k, None) for k in dnskeys_unknown_hash]
    if not l:
        l = [(None, None)]
    return l

def ds_by_dnskey(name, ds_rrset, dnskey_rrsets_rrsigs, supported_ds_algorithms=None):
    grouped_ds = {}
    for ds in ds_rrset:
        for dnskey, valid in dnskeys_for_ds(name, ds, dnskey_rrsets_rrsigs, supported_ds_algorithms):
            if (ds.algorithm, ds.key_tag, dnskey) not in grouped_ds:
                grouped_ds[(ds.algorithm, ds.key_tag, dnskey)] = set()
            grouped_ds[(ds.algorithm, ds.key_tag, dnskey)].add((ds, valid))
    return grouped_ds

def dnskeys_for_rrsig(rrsig, rrset, dnskey_rrsets_rrsigs, dnssec_algorithms=None):
    dnskeys_good_sig = set()
    dnskeys_bad_sig = set()
    dnskeys_unknown_sig = set()

    self_sig = rrset.rdtype == dns.rdatatype.DNSKEY and rrsig.signer == rrset.name

    completed_dnskeys = set()
    for dnskey_rrset, servers, rrsigs in dnskey_rrsets_rrsigs:
        good_from_rrset = set()
        bad_from_rrset = set()
        unknown_from_rrset = set()
        for dnskey in dnskey_rrset:
            if dnskey in completed_dnskeys:
                continue
            if self_sig and dnskey not in rrset:
                continue
            completed_dnskeys.add(dnskey)
            my_key_tag = key_tag(dnskey)
            my_key_tag_no_revoke = key_tag(dnskey, True)
            if not (dnskey.protocol == 3 and \
                    rrsig.key_tag in (my_key_tag, my_key_tag_no_revoke) and \
                    rrsig.algorithm == dnskey.algorithm):
                continue
            if dnssec_algorithms is not None and \
                    rrsig.algorithm not in dnssec_algorithms:
                valid = None
            else:
                valid = validate_rrsig(rrsig, rrset, dnskey)
            if valid is None:
                unknown_from_rrset.add(dnskey)
            elif valid:
                good_from_rrset.add(dnskey)
            else:
                bad_from_rrset.add(dnskey)

        if good_from_rrset:
            dnskeys_good_sig.update(good_from_rrset)
        elif bad_from_rrset:
            dnskeys_bad_sig.update(bad_from_rrset)
        dnskeys_unknown_sig.update(unknown_from_rrset)

    l = [(k, True) for k in dnskeys_good_sig] + [(k, False) for k in dnskeys_bad_sig] + [(k, None) for k in dnskeys_unknown_sig]
    if not l:
        l = [(None, None)]
    return l

def reduce_wildcard(rrset, rrsigs):
    if not rrsigs:
        return None

    #XXX what if rrsigs have different labels values?
    for rrsig in rrsigs:
        if len(rrset.name) - 1 > rrsig.labels:
            return dns.name.Name(('*',)+rrset.name.labels[-(rrsig.labels+1):])

    return None

def dlv_name(name, dlv_domain):
    try:
        return dns.name.Name(name.labels[:-1] + dlv_domain.labels)
    except dns.name.NameTooLong:
        return None
