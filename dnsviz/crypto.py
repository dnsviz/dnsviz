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

import atexit
import base64
import binascii
import logging
import struct
import hashlib
import os
import re

from . import format as fmt
lb2s = fmt.latin1_binary_to_string

logger = logging.getLogger(__name__)

ALG_TYPE_DNSSEC = 0
ALG_TYPE_DIGEST = 1
ALG_TYPE_NSEC3 = 2

ALG_TYPE_DNSSEC_TEXT = [
        'algorithm',
        'digest algorithm',
        'NSEC3 algorithm',
]

_crypto_sources = {
        'M2Crypto >= 0.21.1': (set([1,5,7,8,10]), set([1,2,4]), set([1])),
        'M2Crypto >= 0.24.0': (set([3,6,13,14]), set(), set()),
        'M2Crypto >= 0.24.0 and either openssl < 1.1.0 or openssl >= 1.1.0 plus the OpenSSL GOST Engine': (set([12]), set([3]), set()),
        'M2Crypto >= 0.37.0 and openssl >= 1.1.1': (set([15,16]), set(), set()),
}
_logged_modules = set()

_supported_algs = set()
_supported_digest_algs = set()
_supported_nsec3_algs = set([1])
try:
    from M2Crypto import EVP, RSA
    from M2Crypto.m2 import hex_to_bn, bn_to_mpi
except:
    pass
else:
    _supported_algs.update(set([1,5,7,8,10]))
    _supported_digest_algs.update(set([1,2,4]))

GOST_PREFIX = b'\x30\x63\x30\x1c\x06\x06\x2a\x85\x03\x02\x02\x13\x30\x12\x06\x07\x2a\x85\x03\x02\x02\x23\x01\x06\x07\x2a\x85\x03\x02\x02\x1e\x01\x03\x43\x00\x04\x40'
GOST_ENGINE_NAME = b'gost'
GOST_DIGEST_NAME = b'GOST R 34.11-94'

ED25519_PREFIX = b'\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'
ED448_PREFIX = b'\x30\x43\x30\x05\x06\x03\x2b\x65\x71\x03\x3a\x00'

# python3/python2 dual compatibility
if not isinstance(GOST_ENGINE_NAME, str):
    GOST_ENGINE_NAME = lb2s(GOST_ENGINE_NAME)
    GOST_DIGEST_NAME = lb2s(GOST_DIGEST_NAME)

try:
    # available from python 3.1
    base64encodebytes = base64.encodebytes
except AttributeError:
    # available until python 3.8
    base64encodebytes = base64.encodestring

EC_NOCOMPRESSION = b'\x04'


def _init_dynamic():
    try:
        Engine.load_dynamic()
    except Engine.EngineError:
        pass
    else:
        atexit.register(Engine.cleanup)

def _check_dsa_support():
    try:
        DSA.pub_key_from_params
        _supported_algs.update((3,6))
    except AttributeError:
        pass

def _check_gost_support():
    _gost_init()
    try:
        md = EVP.MessageDigest(GOST_DIGEST_NAME)
    except ValueError:
        pass
    else:
        _supported_algs.add(12)
        _supported_digest_algs.add(3)
    finally:
        _gost_cleanup()

def _check_ec_support():
    try:
        EC.pub_key_from_params
        _supported_algs.update((13,14))
    except AttributeError:
        pass

def _check_ed_support():
    if m2.OPENSSL_VERSION_NUMBER >= 0x10101000:
        _supported_algs.update((15,16))

def alg_is_supported(alg):
    return alg in _supported_algs

def digest_alg_is_supported(alg):
    return alg in _supported_digest_algs

def nsec3_alg_is_supported(alg):
    return alg in _supported_nsec3_algs

def _log_unsupported_alg(alg, alg_type):
    for mod in _crypto_sources:
        if alg in _crypto_sources[mod][alg_type]:
            if mod not in _logged_modules:
                _logged_modules.add(mod)
                logger.warning('Warning: Without the installation of %s, cryptographic validation of DNSSEC %s %d (and possibly others) is not supported.' % (mod, ALG_TYPE_DNSSEC_TEXT[alg_type], alg))
            return

def _gost_init():
    try:
        gost = Engine.Engine(GOST_ENGINE_NAME)
        gost.init()
        gost.set_default()
    except ValueError:
        pass

def _gost_cleanup():
    from M2Crypto import Engine
    try:
        gost = Engine.Engine(GOST_ENGINE_NAME)
    except ValueError:
        pass
    else:
        gost.finish()

try:
    from M2Crypto import DSA
except:
    pass
else:
    _check_dsa_support()

try:
    from M2Crypto import Engine, m2
    _init_dynamic()
except:
    pass
else:
    _check_gost_support()

try:
    from M2Crypto import EC
except:
    pass
else:
    _check_ec_support()

try:
    from M2Crypto.m2 import digest_verify_init
except:
    pass
else:
    _check_ed_support()

def validate_ds_digest(digest_alg, digest, dnskey_msg):
    if not digest_alg_is_supported(digest_alg):
        _log_unsupported_alg(digest_alg, ALG_TYPE_DIGEST)
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
            md = EVP.MessageDigest(GOST_DIGEST_NAME)
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
    t = key[0]
    # python3/python2 dual compatibility
    if not isinstance(t, int):
        t = ord(t)
    offset = 1

    # get Q
    new_offset = offset+20
    q = bn_to_mpi(hex_to_bn(binascii.hexlify(key[offset:new_offset])))
    offset = new_offset

    # get P
    new_offset = offset+64+(t<<3)
    p = bn_to_mpi(hex_to_bn(binascii.hexlify(key[offset:new_offset])))
    offset = new_offset

    # get G
    new_offset = offset+64+(t<<3)
    g = bn_to_mpi(hex_to_bn(binascii.hexlify(key[offset:new_offset])))
    offset = new_offset

    # get Y
    new_offset = offset+64+(t<<3)
    y = bn_to_mpi(hex_to_bn(binascii.hexlify(key[offset:new_offset])))
    offset = new_offset

    # create the DSA public key
    return DSA.pub_key_from_params(p,q,g,y)

def _dnskey_to_rsa(key):
    try:
        # get the exponent length
        e_len = key[0]
    except IndexError:
        return None
    # python3/python2 dual compatibility
    if not isinstance(e_len, int):
        e_len = ord(e_len)

    offset = 1
    if e_len == 0:
        e_len, = struct.unpack(b'!H',key[1:3])
        offset = 3

    # get the exponent
    e = bn_to_mpi(hex_to_bn(binascii.hexlify(key[offset:offset+e_len])))
    offset += e_len

    # get the modulus
    n = bn_to_mpi(hex_to_bn(binascii.hexlify(key[offset:])))

    # create the RSA public key
    rsa = RSA.new_pub_key((e,n))
    pubkey = EVP.PKey()
    pubkey.assign_rsa(rsa)

    return pubkey

def _dnskey_to_gost(key):
    der = GOST_PREFIX + key
    pem = b'-----BEGIN PUBLIC KEY-----\n'+base64encodebytes(der)+b'-----END PUBLIC KEY-----'

    return EVP.load_key_string_pubkey(pem)

def _dnskey_to_ed(alg, key):
    if alg == 15:
        der = ED25519_PREFIX + key
    elif alg == 16:
        der = ED448_PREFIX + key
    else:
        raise ValueError('Algorithm not supported')

    pem = b'-----BEGIN PUBLIC KEY-----\n'+base64encodebytes(der)+b'-----END PUBLIC KEY-----'
    return EVP.load_key_string_pubkey(pem)

def _dnskey_to_ec(alg, key):
    if alg == 13:
        curve = EC.NID_X9_62_prime256v1
    elif alg == 14:
        curve = EC.NID_secp384r1
    else:
        raise ValueError('Algorithm not supported')

    try:
        return EC.pub_key_from_params(curve, EC_NOCOMPRESSION + key)
    except ValueError:
        return None

def _validate_rrsig_rsa(alg, sig, msg, key):
    pubkey = _dnskey_to_rsa(key)

    # if the key is invalid, then the signature is also invalid
    if pubkey is None:
        return False

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

    # if the key is invalid, then the signature is also invalid
    if pubkey is None:
        return False

    # get T
    t = sig[0]
    # python3/python2 dual compatibility
    if not isinstance(t, int):
        t = ord(t)
    offset = 1

    # get R
    new_offset = offset+20
    r = bn_to_mpi(hex_to_bn(binascii.hexlify(sig[offset:new_offset])))
    offset = new_offset

    # get S
    new_offset = offset+20
    s = bn_to_mpi(hex_to_bn(binascii.hexlify(sig[offset:new_offset])))
    offset = new_offset

    md = EVP.MessageDigest('sha1')
    md.update(msg)
    digest = md.final()

    return pubkey.verify(digest, r, s) == 1

def _validate_rrsig_gost(alg, sig, msg, key):
    _gost_init()

    try:
        pubkey = _dnskey_to_gost(key)

        # if the key is invalid, then the signature is also invalid
        if pubkey is None:
            return False

        pubkey.md = m2.get_digestbyname(GOST_DIGEST_NAME)
        pubkey.verify_init()
        pubkey.verify_update(msg)

        return pubkey.verify_final(sig) == 1

    finally:
        _gost_cleanup()

def _validate_rrsig_ec(alg, sig, msg, key):
    pubkey = _dnskey_to_ec(alg, key)

    # if the key is invalid, then the signature is also invalid
    if pubkey is None:
        return False

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
    new_offset = offset+sigsize//2
    r = bn_to_mpi(hex_to_bn(binascii.hexlify(sig[offset:new_offset])))
    offset = new_offset

    # get S
    new_offset = offset+sigsize//2
    s = bn_to_mpi(hex_to_bn(binascii.hexlify(sig[offset:new_offset])))
    offset = new_offset

    md = EVP.MessageDigest(alg)
    md.update(msg)
    digest = md.final()

    return pubkey.verify_dsa(digest, r, s) == 1

def _validate_rrsig_ed(alg, sig, msg, key):
    pubkey = _dnskey_to_ed(alg, key)

    # if the key is invalid, then the signature is also invalid
    if pubkey is None:
        return False

    pubkey.reset_context(None)
    pubkey.digest_verify_init()
    return pubkey.digest_verify(sig, msg) == 1

def validate_rrsig(alg, sig, msg, key):
    if not alg_is_supported(alg):
        _log_unsupported_alg(alg, ALG_TYPE_DNSSEC)
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
    elif alg in (15,16):
        return _validate_rrsig_ed(alg, sig, msg, key)

def get_digest_for_nsec3(val, salt, alg, iterations):
    if not nsec3_alg_is_supported(alg):
        _log_unsupported_alg(alg, ALG_TYPE_NSEC3)
        return None

    if alg == 1:
        hash_func = hashlib.sha1

    for i in range(iterations + 1):
        val = hash_func(val + salt).digest()
    return val
