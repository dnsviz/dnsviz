import argparse
import binascii
import datetime
import gzip
import importlib
import io
import logging
import os
import subprocess
import tempfile
import unittest

import dns.name, dns.rdatatype, dns.rrset, dns.zone

from dnsviz.format import utc
from dnsviz.util import get_default_trusted_keys

mod = importlib.import_module('dnsviz.commands.graph')
GraphArgHelper = getattr(mod, 'GraphArgHelper')
AnalysisInputError = getattr(mod, 'AnalysisInputError')

DATA_DIR = os.path.dirname(__file__)
EXAMPLE_AUTHORITATIVE = os.path.join(DATA_DIR, 'data', 'example-authoritative.json.gz')


class DNSVizGraphOptionsTestCase(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger()
        for handler in self.logger.handlers:
            self.logger.removeHandler(handler)
        self.logger.addHandler(logging.NullHandler())

    def test_rrtype_list(self):
        arg1 = 'A,AAAA,MX,CNAME'
        arg1_with_spaces = ' A , AAAA , MX , CNAME '
        arg2 = 'A'
        arg3 = 'A,BLAH'
        arg4_empty = ''
        arg4_empty_spaces = ' '

        type_list1 = [dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.MX, dns.rdatatype.CNAME]
        type_list2 = [dns.rdatatype.A]
        empty_list = []

        self.assertEqual(GraphArgHelper.comma_separated_dns_types(arg1), type_list1)
        self.assertEqual(GraphArgHelper.comma_separated_dns_types(arg1_with_spaces), type_list1)
        self.assertEqual(GraphArgHelper.comma_separated_dns_types(arg2), type_list2)
        self.assertEqual(GraphArgHelper.comma_separated_dns_types(arg4_empty), empty_list)
        self.assertEqual(GraphArgHelper.comma_separated_dns_types(arg4_empty_spaces), empty_list)

        # invalid schema
        with self.assertRaises(argparse.ArgumentTypeError):
            GraphArgHelper.comma_separated_dns_types(arg3)

    def test_integer_list(self):
        arg1 = '1,2,3,4,5'
        arg1_with_spaces = ' 1 , 2 , 3 , 4 , 5 '
        arg2 = '1'
        arg3 = '1,A'
        arg4_empty = ''
        arg4_empty_spaces = ' '

        int_list1 = [1,2,3,4,5]
        int_list2 = [1]
        empty_list = []

        int_set1 = set([1,2,3,4,5])
        int_set2 = set([1])
        empty_set = set([])

        self.assertEqual(GraphArgHelper.comma_separated_ints(arg1), int_list1)
        self.assertEqual(GraphArgHelper.comma_separated_ints(arg1_with_spaces), int_list1)
        self.assertEqual(GraphArgHelper.comma_separated_ints(arg2), int_list2)
        self.assertEqual(GraphArgHelper.comma_separated_ints(arg4_empty), empty_list)
        self.assertEqual(GraphArgHelper.comma_separated_ints(arg4_empty_spaces), empty_list)

        self.assertEqual(GraphArgHelper.comma_separated_ints_set(arg1), int_set1)
        self.assertEqual(GraphArgHelper.comma_separated_ints_set(arg1_with_spaces), int_set1)
        self.assertEqual(GraphArgHelper.comma_separated_ints_set(arg2), int_set2)
        self.assertEqual(GraphArgHelper.comma_separated_ints_set(arg4_empty), empty_set)
        self.assertEqual(GraphArgHelper.comma_separated_ints_set(arg4_empty_spaces), empty_set)

        # invalid schema
        with self.assertRaises(argparse.ArgumentTypeError):
            GraphArgHelper.comma_separated_ints(arg3)

    def test_valid_domain_name(self):
        arg1 = '.'
        arg2 = 'www.example.com'
        arg3 = 'www..example.com'

        self.assertEqual(GraphArgHelper.valid_domain_name(arg1), dns.name.from_text(arg1))
        self.assertEqual(GraphArgHelper.valid_domain_name(arg2), dns.name.from_text(arg2))

        # invalid domain name
        with self.assertRaises(argparse.ArgumentTypeError):
            GraphArgHelper.valid_domain_name(arg3)

    def test_ingest_input(self):
        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_bad_json:
            example_bad_json.write(b'{')

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_no_version:
            example_no_version.write(b'{}')

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_invalid_version_1:
            example_invalid_version_1.write(b'{ "_meta._dnsviz.": { "version": 1.11 } }')

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_invalid_version_2:
            example_invalid_version_2.write(b'{ "_meta._dnsviz.": { "version": 5.0 } }')

        with gzip.open(EXAMPLE_AUTHORITATIVE, 'rb') as example_auth_in:
            with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_auth_out:
                example_auth_out.write(example_auth_in.read())

        try:
            args = ['-r', example_auth_out.name]
            arghelper = GraphArgHelper(self.logger)
            arghelper.build_parser('graph')
            arghelper.parse_args(args)
            arghelper.ingest_input()

            # Bad json
            args = ['-r', example_bad_json.name]
            arghelper = GraphArgHelper(self.logger)
            arghelper.build_parser('graph')
            arghelper.parse_args(args)
            with self.assertRaises(AnalysisInputError):
                arghelper.ingest_input()

            # No version
            args = ['-r', example_no_version.name]
            arghelper = GraphArgHelper(self.logger)
            arghelper.build_parser('graph')
            arghelper.parse_args(args)
            with self.assertRaises(AnalysisInputError):
                arghelper.ingest_input()

            # Invalid version
            args = ['-r', example_invalid_version_1.name]
            arghelper = GraphArgHelper(self.logger)
            arghelper.build_parser('graph')
            arghelper.parse_args(args)
            with self.assertRaises(AnalysisInputError):
                arghelper.ingest_input()

            # Invalid version
            args = ['-r', example_invalid_version_2.name]
            arghelper = GraphArgHelper(self.logger)
            arghelper.build_parser('graph')
            arghelper.parse_args(args)
            with self.assertRaises(AnalysisInputError):
                arghelper.ingest_input()

        finally:
            for tmpfile in (example_auth_out, example_bad_json, example_no_version, \
                    example_invalid_version_1, example_invalid_version_2):
                os.remove(tmpfile.name)

    def test_ingest_names(self):
        args = ['example.com', 'example.net']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        arghelper.ingest_names()
        self.assertEqual(list(arghelper.names), [dns.name.from_text('example.com'), dns.name.from_text('example.net')])

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as names_file:
            names_file.write(b'example.com\nexample.net\n')

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_names_only:
            example_names_only.write(b'{ "_meta._dnsviz.": { "version": 1.2, "names": [ "example.com.", "example.net.", "example.org." ] } }') 

        try:
            args = ['-f', names_file.name]
            arghelper = GraphArgHelper(self.logger)
            arghelper.build_parser('graph')
            arghelper.parse_args(args)
            arghelper.ingest_names()
            self.assertEqual(list(arghelper.names), [dns.name.from_text('example.com'), dns.name.from_text('example.net')])

            args = ['-r', example_names_only.name]
            arghelper = GraphArgHelper(self.logger)
            arghelper.build_parser('graph')
            arghelper.parse_args(args)
            arghelper.ingest_input()
            arghelper.ingest_names()
            self.assertEqual(list(arghelper.names), [dns.name.from_text('example.com'), dns.name.from_text('example.net'), dns.name.from_text('example.org')])

            args = ['-r', example_names_only.name, 'example.com']
            arghelper = GraphArgHelper(self.logger)
            arghelper.build_parser('graph')
            arghelper.parse_args(args)
            arghelper.ingest_input()
            arghelper.ingest_names()
            self.assertEqual(list(arghelper.names), [dns.name.from_text('example.com')])
        finally:
            for tmpfile in (names_file, example_names_only):
                os.remove(tmpfile.name)

    def test_trusted_keys_file(self):
        tk1 = 'example.com. IN DNSKEY 256 3 7 AwEAAZ2YEuBl4X58v1CezDfZjT1viYn5kY3MF3lSDjvHjMZ6gJlYt4Qq oIdpChifmeJldEX9/wPc04Tg7MlEfV3m0x2j80dMyObM0FZTxzMgbTFk Zs0AWrDXELieGkFZv1FB9YoxSX2XqvpFxwvPyyszUtCy/c5hrb6vfKRB Jh+qIO+NsNrl6O8NiYjWWNjdiFw+c2BxzpArQoaA+rcoyDYwH4xGpvTw YLnE9HmkwTSQuwASkgWgX3KgTmsDEw4I0P5Tk+wvmNnaqDhmFMHJK5Oh 92wUX+ppxxSgUx4UIJmftzi7sCg0qekIYUf99Dkn7OlC8X0rjj+xO4cD hbTjGkxmsD0='
        tk2 = 'example.com. IN DNSKEY 256 3 7 AwEAAaerI6CXvvG6U3UxkB0PXj+ORyGFtABYJ6JG3NL6w1KKlZl+73AS aPEEa7SXeuWmAWE1N3rsbnrMBvepBXkCbP609eoo2mJ8bsozT/NNwSSc FP1Ddw4wxpZAC/+/K736rF1HbI3ROS/rBTr7RW6rWzcyPbYFuUMVzrAM ZSJNJsTDcmyGc5Is3cFzNcrd3/Gmcjt8TKMmGq51HXWzFvxro7EH6aOl K6G4O4+mzaUKp91mg7DAVhX8yXnadXUZQ4yDfLzSleYQ2TroQqeSgI3X m/gUoACm3ELUOr84TmIKZ67X/zBTx8tHC5iBWY2tbIKqiJY7I4/aW4S4 NraCSRbDpbM='
        tk1_rdata = ' '.join(tk1.split()[3:])
        tk2_rdata = ' '.join(tk2.split()[3:])
        tk_explicit = [(dns.name.from_text('example.com'), dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, tk1_rdata)),
                (dns.name.from_text('example.com'), dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, tk2_rdata))]

        now = datetime.datetime.now(utc)
        tk_default = get_default_trusted_keys(now)

        args = ['example.com']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        arghelper.aggregate_trusted_key_info()
        self.assertEqual(arghelper.trusted_keys, None)
        arghelper.update_trusted_key_info(now)
        self.assertEqual(arghelper.trusted_keys, tk_default)

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as tk1_file:
            tk1_file.write(tk1.encode('utf-8'))

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as tk2_file:
            tk2_file.write(tk2.encode('utf-8'))

        try:
            args = ['-t', tk1_file.name, '-t', tk2_file.name, 'example.com']
            arghelper = GraphArgHelper(self.logger)
            arghelper.build_parser('graph')
            arghelper.parse_args(args)
            arghelper.aggregate_trusted_key_info()
            arghelper.update_trusted_key_info(now)
            self.assertEqual(arghelper.trusted_keys, tk_explicit)

            args = ['-t', '/dev/null', 'example.com']
            arghelper = GraphArgHelper(self.logger)
            arghelper.build_parser('graph')
            arghelper.parse_args(args)
            arghelper.aggregate_trusted_key_info()
            arghelper.update_trusted_key_info(now)
            self.assertEqual(arghelper.trusted_keys, [])

        finally:
            for tmpfile in (tk1_file, tk2_file):
                os.remove(tmpfile.name)

    def test_option_combination_errors(self):

        # Names file and command-line domain names are mutually exclusive
        args = ['-f', '/dev/null', 'example.com']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        with self.assertRaises(argparse.ArgumentTypeError):
            arghelper.check_args()

        # Names file and command-line domain names are mutually exclusive
        args = ['-O', '-o', '/dev/null']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        with self.assertRaises(argparse.ArgumentTypeError):
            arghelper.check_args()

        # But this is allowed
        args = ['-o', '/dev/null']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        arghelper.check_args()

        # So is this
        args = ['-O']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        arghelper.check_args()

    def test_output_format(self):

        args = ['-T', 'png', '-o', 'foo.dot']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.output_format, 'png')

        args = ['-o', 'foo.dot']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.output_format, 'dot')

        args = ['-o', 'foo.png']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.output_format, 'png')

        args = ['-o', 'foo.html']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.output_format, 'html')

        args = ['-o', 'foo.svg']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.output_format, 'svg')

        args = ['-o', 'foo.xyz']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        with self.assertRaises(argparse.ArgumentTypeError):
            arghelper.set_kwargs()

        args = ['-o', 'png']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        with self.assertRaises(argparse.ArgumentTypeError):
            arghelper.set_kwargs()

        args = ['-o', '-']
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.output_format, 'dot')

        args = []
        arghelper = GraphArgHelper(self.logger)
        arghelper.build_parser('graph')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.output_format, 'dot')

if __name__ == '__main__':
    unittest.main()
