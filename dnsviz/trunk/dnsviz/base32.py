import struct

_b32tab = { 0: '0', 1: '1', 2: '2', 3: '3', 4: '4', 5: '5', 6: '6', 7: '7', 8: '8', 9: '9',
        10: 'A', 11: 'B', 12: 'C', 13: 'D', 14: 'E', 15: 'F', 16: 'G', 17: 'H', 18: 'I', 19: 'J',
        20: 'K', 21: 'L', 22: 'M', 23: 'N', 24: 'O', 25: 'P', 26: 'Q', 27: 'R', 28: 'S', 29: 'T',
        30: 'U', 31: 'V' }
EMPTYSTRING = ''

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
