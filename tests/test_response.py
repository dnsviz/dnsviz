# -*- coding: utf-8 -*-

import binascii
import dns.message
import unittest

from dnsviz.response import DNSResponse

class DNSResponseTestCase(unittest.TestCase):
    def test_nsid_val(self):
        tests = [
            # DNS message in wire format, expected NSID value
            ("26898105000100000000000106646e7376697a036e657400001c000100002904d00000000000120003000e68756d616e2d7265616461626c65", "human-readable"),
            ("43468105000100000000000106646e7376697a036e657400001c000100002904d000000000000800030004c01dcafe", "0xc01dcafe"),
        ]
        for wire, nsid_val in tests:
            msg = dns.message.from_wire(binascii.unhexlify(wire))
            resp = DNSResponse(msg, 0, None, None, None, None, None, None, None, False)
            self.assertEqual(resp.nsid_val(), nsid_val)
