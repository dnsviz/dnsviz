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
# Copyright 2016-2024 Casey Deccio
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

from cryptography.hazmat.backends import openssl as OpenSSL
from cryptography.hazmat.primitives.asymmetric import dsa as DSA
from cryptography.hazmat.primitives.asymmetric import ec as EC
from cryptography.hazmat.primitives.asymmetric import ed25519 as ED25519
from cryptography.hazmat.primitives.asymmetric import ed448 as ED448
from cryptography.hazmat.primitives.asymmetric import rsa as RSA
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

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
        'M2Crypto >= 0.24.0 and openssl >= 1.1.0 plus the OpenSSL GOST Engine': (set([12]), set([3]), set()),
}
_logged_modules = (set(), set(), set())

_supported_algs = set([1,3,5,6,7,8,10,13,14,15,16])
_supported_digest_algs = set([1,2,4])
_supported_nsec3_algs = set([1])

GOST_PREFIX = b'\x30\x63\x30\x1c\x06\x06\x2a\x85\x03\x02\x02\x13\x30\x12\x06\x07\x2a\x85\x03\x02\x02\x23\x01\x06\x07\x2a\x85\x03\x02\x02\x1e\x01\x03\x43\x00\x04\x40'
GOST_ENGINE_NAME = b'gost'
GOST_DIGEST_NAME = b'GOST R 34.11-94'

# For backwards compatibility with cryptography < 36.0.
# See https://cryptography.io/en/latest/faq/#faq-missing-backend
backend = OpenSSL.backend

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

def alg_is_supported(alg):
    return alg in _supported_algs

def digest_alg_is_supported(alg):
    return alg in _supported_digest_algs

def nsec3_alg_is_supported(alg):
    return alg in _supported_nsec3_algs

def _log_unsupported_alg(alg, alg_type):
    for mod in _crypto_sources:
        if alg in _crypto_sources[mod][alg_type]:
            if mod not in _logged_modules[alg_type]:
                _logged_modules[alg_type].add(mod)
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
    from M2Crypto import Engine, EVP, m2
    _init_dynamic()
    _check_gost_support()
except:
    pass

def validate_ds_digest(digest_alg, digest, dnskey_msg):
    mydigest = get_ds_digest(digest_alg, dnskey_msg)
    if mydigest is None:
        return None
    else:
        return mydigest == digest

def get_ds_digest(digest_alg, dnskey_msg):
    if not digest_alg_is_supported(digest_alg):
        _log_unsupported_alg(digest_alg, ALG_TYPE_DIGEST)
        return None

    if digest_alg == 1:
        md = hashes.Hash(hashes.SHA1(), backend)
        md.update(dnskey_msg)
        return md.finalize()
    elif digest_alg == 2:
        md = hashes.Hash(hashes.SHA256(), backend)
        md.update(dnskey_msg)
        return md.finalize()
    elif digest_alg == 3:
        _gost_init()
        try:
            md = EVP.MessageDigest(GOST_DIGEST_NAME)
            md.update(dnskey_msg)
            return md.final()
        finally:
            _gost_cleanup()
    elif digest_alg == 4:
        md = hashes.Hash(hashes.SHA384(), backend)
        md.update(dnskey_msg)
        return md.finalize()

def _dnskey_to_dsa(key):
    # get T
    t = key[0]
    # python3/python2 dual compatibility
    if not isinstance(t, int):
        t = ord(t)
    offset = 1

    # get Q
    new_offset = offset+20
    # python3/python2 dual compatibility
    if hasattr(int, 'from_bytes'):
        q = int.from_bytes(key[offset:new_offset], 'big')
    else:
        q = int(key[offset:new_offset].encode('hex'), 16)
    offset = new_offset

    # get P
    new_offset = offset+64+(t<<3)
    # python3/python2 dual compatibility
    if hasattr(int, 'from_bytes'):
        p = int.from_bytes(key[offset:new_offset], 'big')
    else:
        p = int(key[offset:new_offset].encode('hex'), 16)
    offset = new_offset

    # get G
    new_offset = offset+64+(t<<3)
    # python3/python2 dual compatibility
    if hasattr(int, 'from_bytes'):
        g = int.from_bytes(key[offset:new_offset], 'big')
    else:
        g = int(key[offset:new_offset].encode('hex'), 16)
    offset = new_offset

    # get Y
    new_offset = offset+64+(t<<3)
    # python3/python2 dual compatibility
    if hasattr(int, 'from_bytes'):
        y = int.from_bytes(key[offset:new_offset], 'big')
    else:
        y = int(key[offset:new_offset].encode('hex'), 16)
    offset = new_offset

    # create the DSA public key
    param_nums = DSA.DSAParameterNumbers(p, q, g)
    dsa = DSA.DSAPublicNumbers(y, param_nums)

    try:
        return dsa.public_key(backend)
    except ValueError:
        return None

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

    if len(key) < offset + e_len:
        return None

    # get the exponent
    # python3/python2 dual compatibility
    if hasattr(int, 'from_bytes'):
        e = int.from_bytes(key[offset:offset+e_len], 'big')
    else:
        e = int(key[offset:offset+e_len].encode('hex'), 16)
    offset += e_len

    if len(key) <= offset:
        return None

    # get the modulus
    # python3/python2 dual compatibility
    if hasattr(int, 'from_bytes'):
        n = int.from_bytes(key[offset:], 'big')
    else:
        n = int(key[offset:].encode('hex'), 16)

    # create the RSA public key
    rsa = RSA.RSAPublicNumbers(e, n)
    try:
        return rsa.public_key(backend)
    except ValueError:
        return None

def _dnskey_to_gost(key):
    der = GOST_PREFIX + key
    pem = b'-----BEGIN PUBLIC KEY-----\n'+base64encodebytes(der)+b'-----END PUBLIC KEY-----'

    return EVP.load_key_string_pubkey(pem)

def _dnskey_to_ed(alg, key):
    if alg == 15:
        try:
            return ED25519.Ed25519PublicKey.from_public_bytes(key)
        except ValueError:
            return None
    elif alg == 16:
        try:
            return ED448.Ed448PublicKey.from_public_bytes(key)
        except ValueError:
            return None
    else:
        raise ValueError('Algorithm not supported')

def _dnskey_to_ec(alg, key):
    if alg == 13:
        curve = EC.SECP256R1()
    elif alg == 14:
        curve = EC.SECP384R1()
    else:
        raise ValueError('Algorithm not supported')

    try:
        return EC.EllipticCurvePublicKey.from_encoded_point(curve, EC_NOCOMPRESSION + key)
    except ValueError:
        return None

def _validate_rrsig_rsa(alg, sig, msg, key):
    pubkey = _dnskey_to_rsa(key)

    # if the key is invalid, then the signature is also invalid
    if pubkey is None:
        return False

    if alg in (1,):
        hsh = hashes.MD5()
    elif alg in (5,7):
        hsh = hashes.SHA1()
    elif alg in (8,):
        hsh = hashes.SHA256()
    elif alg in (10,):
        hsh = hashes.SHA512()
    else:
        raise ValueError('RSA Algorithm unknown.')

    try:
        pubkey.verify(sig, msg, padding.PKCS1v15(), hsh)
    except InvalidSignature:
        return False
    else:
        return True

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
    # python3/python2 dual compatibility
    if hasattr(int, 'from_bytes'):
        r = int.from_bytes(sig[offset:new_offset], 'big')
    else:
        r = int(sig[offset:new_offset].encode('hex'), 16)
    offset = new_offset

    # get S
    new_offset = offset+20
    # python3/python2 dual compatibility
    if hasattr(int, 'from_bytes'):
        s = int.from_bytes(sig[offset:new_offset], 'big')
    else:
        s = int(sig[offset:new_offset].encode('hex'), 16)
    offset = new_offset

    sig = utils.encode_dss_signature(r, s)

    try:
        pubkey.verify(sig, msg, hashes.SHA1())
    except InvalidSignature:
        return False
    else:
        return True

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
        alg = EC.ECDSA(hashes.SHA256())
        sigsize = 64
    elif alg in (14,):
        alg = EC.ECDSA(hashes.SHA384())
        sigsize = 96
    else:
        raise ValueError('EC hash algorithm unknown!')

    if sigsize != len(sig):
        return False

    offset = 0

    # get R
    new_offset = offset+sigsize//2
    # python3/python2 dual compatibility
    if hasattr(int, 'from_bytes'):
        r = int.from_bytes(sig[offset:new_offset], 'big')
    else:
        r = int(sig[offset:new_offset].encode('hex'), 16)
    offset = new_offset

    # get S
    new_offset = offset+sigsize//2
    # python3/python2 dual compatibility
    if hasattr(int, 'from_bytes'):
        s = int.from_bytes(sig[offset:new_offset], 'big')
    else:
        s = int(sig[offset:new_offset].encode('hex'), 16)
    offset = new_offset

    sig = utils.encode_dss_signature(r, s)
    try:
        pubkey.verify(sig, msg, alg)
    except InvalidSignature:
        return False
    else:
        return True

def _validate_rrsig_ed(alg, sig, msg, key):
    pubkey = _dnskey_to_ed(alg, key)

    # if the key is invalid, then the signature is also invalid
    if pubkey is None:
        return False

    try:
        pubkey.verify(sig, msg)
    except InvalidSignature:
        return False
    else:
        return True

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
