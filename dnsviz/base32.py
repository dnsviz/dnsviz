#
# Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
# 2011, 2012, 2013, 2014, 2015 Python Software Foundation; All Rights Reserved
#
# PSF license: https://docs.python.org/2/license.html
#
# PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2
# --------------------------------------------
#
# 1. This LICENSE AGREEMENT is between the Python Software Foundation
# ("PSF"), and the Individual or Organization ("Licensee") accessing and
# otherwise using this software ("Python") in source or binary form and
# its associated documentation.
#
# 2. Subject to the terms and conditions of this License Agreement, PSF hereby
# grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
# analyze, test, perform and/or display publicly, prepare derivative works,
# distribute, and otherwise use Python alone or in any derivative version,
# provided, however, that PSF's License Agreement and PSF's notice of copyright,
# i.e., "Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
# 2011, 2012, 2013, 2014, 2015 Python Software Foundation; All Rights Reserved"
# are retained in Python alone or in any derivative version prepared by Licensee.
#
# 3. In the event Licensee prepares a derivative work that is based on
# or incorporates Python or any part thereof, and wants to make
# the derivative work available to others as provided herein, then
# Licensee hereby agrees to include in any such work a brief summary of
# the changes made to Python.
#
# 4. PSF is making Python available to Licensee on an "AS IS"
# basis.  PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
# IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND
# DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
# FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON WILL NOT
# INFRINGE ANY THIRD PARTY RIGHTS.
#
# 5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
# FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
# A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON,
# OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.
#
# 6. This License Agreement will automatically terminate upon a material
# breach of its terms and conditions.
#
# 7. Nothing in this License Agreement shall be deemed to create any
# relationship of agency, partnership, or joint venture between PSF and
# Licensee.  This License Agreement does not grant permission to use PSF
# trademarks or trade name in a trademark sense to endorse or promote
# products or services of Licensee, or any third party.
#
# 8. By copying, installing or otherwise using Python, Licensee
# agrees to be bound by the terms and conditions of this License
# Agreement.
#

#
# The contents of this module are derived the base64 module of python 2.7, with
# the value of _b32tab modified to use the Base 32 Encoding with Extended Hex
# Alphabet, as specified in RFC 4648.
#

import struct

_b32tab = { 0: '0', 1: '1', 2: '2', 3: '3', 4: '4', 5: '5', 6: '6', 7: '7', 8: '8', 9: '9',
        10: 'A', 11: 'B', 12: 'C', 13: 'D', 14: 'E', 15: 'F', 16: 'G', 17: 'H', 18: 'I', 19: 'J',
        20: 'K', 21: 'L', 22: 'M', 23: 'N', 24: 'O', 25: 'P', 26: 'Q', 27: 'R', 28: 'S', 29: 'T',
        30: 'U', 31: 'V' }
EMPTYSTRING = ''

b32alphabet = set(_b32tab.values())

def b32encode(s):
    """Encode a string using Base32.

    s is the string to encode.  The encoded string is returned.
    """
    parts = []
    quanta, leftover = divmod(len(s), 5)
    # Pad the last quantum with zero bits if necessary
    if leftover:
        s += ('\0' * (5 - leftover))
        quanta += 1
    for i in range(quanta):
        # c1 and c2 are 16 bits wide, c3 is 8 bits wide.  The intent of this
        # code is to process the 40 bits in units of 5 bits.  So we take the 1
        # leftover bit of c1 and tack it onto c2.  Then we take the 2 leftover
        # bits of c2 and tack them onto c3.  The shifts and masks are intended
        # to give us values of exactly 5 bits in width.
        c1, c2, c3 = struct.unpack('!HHB', s[i*5:(i+1)*5])
        c2 += (c1 & 1) << 16 # 17 bits wide
        c3 += (c2 & 3) << 8  # 10 bits wide
        parts.extend([_b32tab[c1 >> 11],         # bits 1 - 5
                      _b32tab[(c1 >> 6) & 0x1f], # bits 6 - 10
                      _b32tab[(c1 >> 1) & 0x1f], # bits 11 - 15
                      _b32tab[c2 >> 12],         # bits 16 - 20 (1 - 5)
                      _b32tab[(c2 >> 7) & 0x1f], # bits 21 - 25 (6 - 10)
                      _b32tab[(c2 >> 2) & 0x1f], # bits 26 - 30 (11 - 15)
                      _b32tab[c3 >> 5],          # bits 31 - 35 (1 - 5)
                      _b32tab[c3 & 0x1f],        # bits 36 - 40 (1 - 5)
                      ])
    encoded = EMPTYSTRING.join(parts)
    # Adjust for any leftover partial quanta
    if leftover == 1:
        return encoded[:-6] + '======'
    elif leftover == 2:
        return encoded[:-4] + '===='
    elif leftover == 3:
        return encoded[:-3] + '==='
    elif leftover == 4:
        return encoded[:-1] + '='
    return encoded
