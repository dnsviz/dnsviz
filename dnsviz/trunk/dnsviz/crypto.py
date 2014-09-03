#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Author: Casey Deccio (casey@deccio.net)
#
# Copyright 2012-2014 Sandia Corporation. Under the terms of Contract
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
import struct
import hashlib

from M2Crypto import DSA, EC, Engine, EVP, m2, RSA
from M2Crypto.m2 import hex_to_bn, bn_to_mpi

GOST_PREFIX = '\x30\x63\x30\x1c\x06\x06\x2a\x85\x03\x02\x02\x13\x30\x12\x06\x07\x2a\x85\x03\x02\x02\x23\x01\x06\x07\x2a\x85\x03\x02\x02\x1e\x01\x03\x43\x00\x04\x40'
GOST_DIGEST_NAME = 'GOST R 34.11-94'

_supported_algs = set([1,5,7,8,10])
_supported_digest_algs = set([1,2,4])
_supported_nsec3_algs = set([1])
def _check_dsa_support():
    try:
        DSA.pub_key_from_params
        _supported_algs.update((3,6)) 
    except AttributeError:
        pass

def _check_gost_support():
    try:
        _gost_init()
        try:
            m2.get_digestbyname(GOST_DIGEST_NAME)
            _supported_algs.add(12) 
            _supported_digest_algs.add(3) 
        except AttributeError:
            pass
        _gost_cleanup()
    except Engine.EngineError:
        pass

def _check_ec_support():
    try:
        EC.pub_key_from_params
        _supported_algs.update((13,14)) 
    except AttributeError:
        pass

def alg_is_supported(alg):
    return alg in _supported_algs

def digest_alg_is_supported(alg):
    return alg in _supported_digest_algs

def nsec3_alg_is_supported(alg):
    return alg in _supported_nsec3_algs

def _gost_init():
    gost = Engine.load_dynamic_engine('gost', '/usr/lib/x86_64-linux-gnu/openssl-1.0.0/engines/libgost.so')
    gost.init()
    gost.set_default()

def _gost_cleanup():
    from M2Crypto import Engine
    gost = Engine.Engine('gost')
    gost.finish()
    Engine.cleanup()

_check_dsa_support()
_check_gost_support()
_check_ec_support()

class GostMessageDigest(EVP.MessageDigest):
    def __init__(self, md):
        self.md=md
        self.ctx=m2.md_ctx_new()
        m2.digest_init(self.ctx, self.md)

def validate_ds_digest(digest_alg, digest, dnskey_msg):
    if not digest_alg_is_supported(digest_alg):
        return None

    if digest_alg == 1:
        md = EVP.MessageDigest('sha1')
        md.update(dnskey_msg)
        return md.final() == digest
    elif digest_alg == 2:
        md = EVP.MessageDigest('sha256')
        md.update(dnskey_msg)
        return md.final() == digest
    elif digest_alg == 3:
        _gost_init()
        try:
            mdgost = m2.get_digestbyname(GOST_DIGEST_NAME)
            md = GostMessageDigest(mdgost)
            md.update(dnskey_msg)
            return md.final() == digest
        finally:
            _gost_cleanup()
    elif digest_alg == 4:
        md = EVP.MessageDigest('sha384')
        md.update(dnskey_msg)
        return md.final() == digest

def _dnskey_to_dsa(key):
    # get T
    t, = struct.unpack('B',key[0])
    offset = 1

    # get Q
    new_offset = offset+20
    q = ''
    for c in key[offset:new_offset]:
        q += '%02x' % struct.unpack('B',c)[0]
    q = bn_to_mpi(hex_to_bn(q))
    offset = new_offset

    # get P
    new_offset = offset+64+(t<<3)
    p = ''
    for c in key[offset:new_offset]:
        p += '%02x' % struct.unpack('B',c)[0]
    p = bn_to_mpi(hex_to_bn(p))
    offset = new_offset

    # get G
    new_offset = offset+64+(t<<3)
    g = ''
    for c in key[offset:new_offset]:
        g += '%02x' % struct.unpack('B',c)[0]
    g = bn_to_mpi(hex_to_bn(g))
    offset = new_offset

    # get Y
    new_offset = offset+64+(t<<3)
    y = ''
    for c in key[offset:new_offset]:
        y += '%02x' % struct.unpack('B',c)[0]
    y = bn_to_mpi(hex_to_bn(y))
    offset = new_offset

    # create the DSA public key
    return DSA.pub_key_from_params(p,q,g,y)

def _dnskey_to_rsa(key):
    try:
        # get the exponent length
        e_len, = struct.unpack('B',key[0])
    except IndexError:
        return None

    offset = 1
    if e_len == 0:
        e_len, = struct.unpack('!H',key[1:3])
        offset = 3

    # get the exponent 
    e = ''
    for c in key[offset:offset+e_len]:
        e += '%02x' % struct.unpack('B',c)[0]
    e = bn_to_mpi(hex_to_bn(e))
    offset += e_len

    # get the modulus
    n = ''
    for c in key[offset:]:
        n += '%02x' % struct.unpack('B',c)[0]
    n = bn_to_mpi(hex_to_bn(n))

    # create the RSA public key
    rsa = RSA.new_pub_key((e,n))
    pubkey = EVP.PKey()
    pubkey.assign_rsa(rsa)

    return pubkey

def _dnskey_to_gost(key):
    der = GOST_PREFIX + key
    pem = '-----BEGIN PUBLIC KEY-----\n'+base64.encodestring(der)+'-----END PUBLIC KEY-----'

    return EVP.load_key_string_pubkey(pem)

def _dnskey_to_ec(alg, key):
    if alg == 13:
        curve = EC.NID_X9_62_prime256v1
    elif alg == 14:
        curve = EC.NID_secp384r1
    else:
        raise ValueError('Algorithm not supported')

    return EC.pub_key_from_params(curve, key)

def _validate_rrsig_rsa(alg, sig, msg, key):
    pubkey = _dnskey_to_rsa(key)

    if alg in (1,):
        md='md5'
    elif alg in (5,7):
        md='sha1'
    elif alg in (8,):
        md='sha256'
    elif alg in (10,):
        md='sha512'
    else:
        raise ValueError('RSA Algorithm unknown.')

    # reset context for appropriate hash
    pubkey.reset_context(md=md)
    pubkey.verify_init()
    pubkey.verify_update(msg)

    return pubkey.verify_final(sig) == 1

def _validate_rrsig_dsa(alg, sig, msg, key):
    pubkey = _dnskey_to_dsa(key)

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

    return pubkey.verify(digest, r, s) == 1

def _validate_rrsig_gost(alg, sig, msg, key):
    _gost_init()

    try:
        pubkey = _dnskey_to_gost(key)

        pubkey.md = m2.get_digestbyname(GOST_DIGEST_NAME)
        pubkey.verify_init()
        pubkey.verify_update(msg)

        return pubkey.verify_final(sig) == 1

    finally:
        _gost_cleanup()

def _validate_rrsig_ec(alg, sig, msg, key):
    pubkey = _dnskey_to_ec(alg, key)

    if alg in (13,):
        alg='sha256'
        sigsize = 64
    elif alg in (14,):
        alg='sha384'
        sigsize = 96
    else:
        raise ValueError('EC hash algorithm unknown!')

    if sigsize != len(sig):
        return False

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

    return pubkey.verify_dsa(digest, r, s) == 1

def validate_rrsig(alg, sig, msg, key):
    if not alg_is_supported(alg):
        return None

    # create an RSA key object for RSA keys
    if alg in (1,5,7,8,10):
        return _validate_rrsig_rsa(alg, sig, msg, key)
    elif alg in (3,6):
        return _validate_rrsig_dsa(alg, sig, msg, key)
    elif alg in (12,):
        return _validate_rrsig_gost(alg, sig, msg, key)
    elif alg in (13,14):
        return _validate_rrsig_ec(alg, sig, msg, key)

def get_digest_for_nsec3(val, salt, alg, iterations):
    if not nsec3_alg_is_supported(alg):
        raise ValueError('NSEC3 digest algorithm not supported')

    if alg == 1:
        hash_func = hashlib.sha1

    for i in range(iterations + 1):
        val = hash_func(val + salt).digest()
    return val
